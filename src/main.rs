use clap::Parser;
use crossbeam_channel::{unbounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};
use ssh2::{Channel, Session};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long, value_name = "CONFIG")]
    config: PathBuf,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SSHInfo {
    host: String,
    user: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct FilePair {
    src: String,
    dest: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Config {
    hosts: Vec<SSHInfo>,
    files: Vec<FilePair>,
    ssh_key: String,
    check_interval: u64,
}

#[derive(Debug)]
struct Job {
    host: SSHInfo,
    files: Vec<FilePair>,
}

fn retry<T, E, F>(mut f: F) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Debug,
{
    let mut attempts = 0;
    loop {
        match f() {
            Ok(val) => return Ok(val),
            Err(e) => {
                attempts += 1;
                if attempts >= 5 {
                    return Err(e);
                }
                eprintln!("Attempt {} failed: {:?}. Retrying...", attempts, e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn create_ssh_session(host: &SSHInfo, key_path: &str) -> Result<Session, Box<dyn std::error::Error>> {
    retry(|| {
        let tcp = TcpStream::connect(format!("{}:22", host.host))?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        sess.userauth_pubkey_file(&host.user, None, Path::new(key_path), None)?;
        Ok(sess)
    })
}

fn check_first_deploy(sess: &Session) -> bool {
    let result = retry(|| {
        let mut channel = sess.channel_session()?;
        channel.exec("cat /tmp/first_deploy_complete")?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        Ok(s == "true".to_string())
    });
    result.unwrap_or(false)
}

fn write_first_deploy(sess: &Session) -> Result<(), Box<dyn std::error::Error>> {
    retry(|| {
        let mut channel = sess.channel_session()?;
        channel.exec("echo -ne 'true' > /tmp/first_deploy_complete")?;
        Ok(())
    })
}

fn deploy_files(sess: &Session, files: &[FilePair]) -> Result<(), Box<dyn std::error::Error>> {
    for pair in files {
        retry(|| {
            let content = fs::read(&pair.src).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            let mut remote_file = sess.scp_send(Path::new(&pair.dest), 0o644, content.len() as u64, None)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            remote_file.write_all(&content).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            remote_file.send_eof().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            remote_file.wait_eof().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            remote_file.close().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            Ok(())
        })?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_str = fs::read_to_string(&args.config)?;
    let config: Config = serde_yaml::from_str(&config_str)?;

    let (tx, rx): (Sender<Job>, Receiver<Job>) = unbounded();

    // Worker Thread
    let worker_conf = config.clone();
    thread::spawn(move || {
        while let Ok(job) = rx.recv() {
            if let Ok(sess) = create_ssh_session(&job.host, &worker_conf.ssh_key) {
                if deploy_files(&sess, &job.files).is_ok() {
                    if !check_first_deploy(&sess) {
                        let _ = write_first_deploy(&sess);
                    }
                }
            }
        }
    });

    // Initial Check Thread
    let init_tx = tx.clone();
    let init_conf = config.clone();
    thread::spawn(move || {
        for host in &init_conf.hosts {
            if let Ok(sess) = create_ssh_session(host, &init_conf.ssh_key) {
                if !check_first_deploy(&sess) {
                    let _ = init_tx.send(Job {
                        host: host.clone(),
                        files: init_conf.files.clone(),
                    });
                }
            }
        }
    });

    // Changes Monitor Thread
    let monitor_tx = tx.clone();
    let monitor_conf = config.clone();
    thread::spawn(move || {
        let mut last_mtimes: HashMap<String, SystemTime> = HashMap::new();

        loop {
            let mut changed_files = Vec::new();
            for pair in &monitor_conf.files {
                if let Ok(meta) = fs::metadata(&pair.src) {
                    let mtime = meta.modified().unwrap_or(SystemTime::now());
                    if last_mtimes.get(&pair.src).map_or(true, |&t| t < mtime) {
                        last_mtimes.insert(pair.src.clone(), mtime);
                        changed_files.push(pair.clone());
                    }
                }
            }

            if !changed_files.is_empty() {
                for host in &monitor_conf.hosts {
                    let _ = monitor_tx.send(Job {
                        host: host.clone(),
                        files: changed_files.clone(),
                    });
                }
            }
            thread::sleep(Duration::from_secs(monitor_conf.check_interval));
        }
    });

    // Keep main thread alive
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
