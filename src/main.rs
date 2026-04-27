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

fn create_ssh_session(host: &SSHInfo, key_path: &str) -> Result<Session, Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(format!("{}:22", host.host))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_pubkey_file(&host.user, None, Path::new(key_path), None)?;
    Ok(sess)
}

fn check_first_deploy(sess: &Session) -> bool {
    for _ in 0..5 {
        let mut channel: Channel;

        match sess.channel_session() {
            Ok(val) => {
                channel = val
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                continue;
            }
        }

        match channel.exec("cat /tmp/first_deploy_complete") {
            Ok(_) => {
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                continue;
            }
        }

        let mut s = String::new();

        match channel.read_to_string(&mut s) {
            Ok(_) => {
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                continue;
            }
        }

        return s == "true".to_string()
    }
    return false
}

fn write_first_deploy(sess: &Session) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..5 {
        let mut channel = sess.channel_session()?;
        match channel.exec("echo -ne 'true' > /tmp/first_deploy_complete") {
            Ok(_) => {
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                continue;
            }
        }
        return Ok(())
    }

    return Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        "failed after retries",
    )))
}

fn deploy_files(sess: &Session, files: &[FilePair]) -> Result<(), Box<dyn std::error::Error>> {
    for pair in files {
        let content = fs::read(&pair.src)?;
        let mut remote_file = sess.scp_send(Path::new(&pair.dest), 0o644, content.len() as u64, None)?;
        remote_file.write_all(&content)?;
        remote_file.send_eof()?;
        remote_file.wait_eof()?;
        remote_file.close()?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_str = fs::read_to_string(&args.config)?;
    let config: Config = serde_yaml::from_str(&config_str)?;

    let (tx, rx): (Sender<Job>, Receiver<Job>) = unbounded();

    // Worker Thread
    let worker_tx = tx.clone();
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
