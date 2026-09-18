use std::{
    fs::File,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use ssh2::{Session, Sftp};
use russh::{
    client,
    keys::{load_secret_key, PrivateKeyWithHashAlg},
    ChannelId,
};

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

fn main() -> Result<()> {
    let args = Args::parse();

    let configs = load_config(&args.config)?;

    println!("Loaded {} config(s)", configs.len());

    for (config_index, config) in configs.iter().enumerate() {
        println!(
            "\n=== Config {} / {} ===",
            config_index + 1,
            configs.len()
        );

        run_config(config)?;
    }

    Ok(())
}

fn load_config(path: &Path) -> Result<Vec<Config>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open config: {}", path.display()))?;

    let configs: Vec<Config> = serde_yaml::from_reader(file)
        .with_context(|| format!("failed to parse YAML: {}", path.display()))?;

    if configs.is_empty() {
        bail!("configuration contains no configs");
    }

    for (index, config) in configs.iter().enumerate() {
        if config.hosts.is_empty() {
            bail!("config {} contains no hosts", index + 1);
        }

        if config.files.is_empty() {
            bail!("config {} contains no files", index + 1);
        }

        if config.ssh_key.is_empty() {
            bail!("config {} has an empty ssh_key", index + 1);
        }
    }

    Ok(configs)
}

fn run_config(config: &Config) -> Result<()> {
    /*
     * Construct jobs in the same order as the YAML.
     */
    let jobs: Vec<Job> = config
        .hosts
        .iter()
        .cloned()
        .map(|host| Job {
            host,
            files: config.files.clone(),
        })
        .collect();

    loop {
        for job in &jobs {
            if let Err(error) = run_job(job, &config.ssh_key) {
                eprintln!(
                    "[{}@{}] ERROR: {error:#}",
                    job.host.user, job.host.host
                );
            }
        }

        thread::sleep(Duration::from_secs(config.check_interval));
    }
}

fn run_job(job: &Job, ssh_key: &str) -> Result<()> {
    println!(
        "\n--- {}@{} ---",
        job.host.user, job.host.host
    );

    let session = connect_ssh(&job.host, ssh_key)?;

    /*
     * Files are intentionally processed sequentially in the order
     * specified by the YAML.
     */
    for file in &job.files {
        sync_file(&session, file)?;
    }

    Ok(())
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        /*
         * Do not blindly return true in a production program.
         *
         * This is equivalent to accepting any host key, which is
         * convenient while getting the synchronization program working.
         */
        Ok(true)
    }
}

async fn connect_ssh(
    host: &SSHInfo,
    ssh_key: &str,
) -> Result<russh::client::Handle<ClientHandler>> {
    let key = load_secret_key(Path::new(ssh_key), None)
        .with_context(|| {
            format!("failed to load SSH private key: {ssh_key}")
        })?;

    let config = russh::client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    };

    let mut session = client::connect(
        Arc::new(config),
        (host.host.as_str(), 22),
        ClientHandler,
    )
    .await
    .with_context(|| {
        format!("failed to connect to {}:22", host.host)
    })?;

    let key = PrivateKeyWithHashAlg::new(
        Arc::new(key),
        session.best_supported_rsa_hash().await?.flatten(),
    );

    let auth = session
        .authenticate_publickey(&host.user, key)
        .await
        .with_context(|| {
            format!(
                "public-key authentication failed for {}@{}",
                host.user, host.host
            )
        })?;

    if !auth.success() {
        bail!(
            "SSH server rejected public-key authentication for {}@{}",
            host.user,
            host.host
        );
    }

    println!(
        "authenticated {}@{}",
        host.user, host.host
    );

    Ok(session)
}

fn sync_file(session: &Session, file: &FilePair) -> Result<()> {
    let src = Path::new(&file.src);

    println!("checking {} -> {}", src.display(), file.dest);

    let local_hash = sha256_file(src)
        .with_context(|| format!("failed to hash {}", src.display()))?;

    let remote_hash = remote_sha256(session, &file.dest)?;

    match remote_hash {
        Some(hash) if hash == local_hash => {
            println!("  unchanged");
        }

        Some(_) => {
            println!("  changed; uploading");
            upload_file(session, src, &file.dest)?;
        }

        None => {
            println!("  destination does not exist; uploading");
            upload_file(session, src, &file.dest)?;
        }
    }

    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;

    let mut hasher = Sha3_256::new();
    let mut buffer = [0u8; 1024 * 64];

    loop {
        let count = file.read(&mut buffer)?;

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn remote_sha256(session: &Session, path: &str) -> Result<Option<String>> {
    /*
     * Use SFTP rather than a remote shell command. This avoids
     * shell quoting issues with filenames.
     */
    let sftp = session.sftp()?;

    match sftp.open(Path::new(path)) {
        Ok(mut file) => {
            let mut hasher = Sha3_256::new();
            let mut buffer = [0u8; 1024 * 64];

            loop {
                let count = file.read(&mut buffer)?;

                if count == 0 {
                    break;
                }

                hasher.update(&buffer[..count]);
            }

            Ok(Some(hex::encode(hasher.finalize())))
        }

        Err(error) => {
            /*
             * SFTP doesn't provide a particularly convenient
             * cross-platform "not found" API, so check whether
             * the path exists separately.
             */
            if !remote_exists(&sftp, path) {
                Ok(None)
            } else {
                Err(error.into())
            }
        }
    }
}

fn remote_exists(sftp: &Sftp, path: &str) -> bool {
    sftp.stat(Path::new(path)).is_ok()
}

fn upload_file(
    session: &Session,
    src: &Path,
    dest: &str,
) -> Result<()> {
    let sftp = session
        .sftp()
        .context("failed to initialize SFTP")?;

    let metadata = std::fs::metadata(src)
        .with_context(|| format!("failed to stat {}", src.display()))?;

    /*
     * Ensure the destination's parent directory exists.
     *
     * SFTP mkdir is intentionally not recursive, so create each
     * component separately.
     */
    if let Some(parent) = Path::new(dest).parent() {
        create_remote_directories(&sftp, parent)?;
    }

    /*
     * Upload to a temporary file first. This prevents the remote
     * destination from being left partially written if the transfer
     * fails.
     */
    let temporary = format!("{}.tmp", dest);

    {
        let mut remote = sftp
            .create(Path::new(&temporary))
            .with_context(|| {
                format!("failed to create remote file {temporary}")
            })?;

        let mut local = File::open(src)
            .with_context(|| format!("failed to open {}", src.display()))?;

        std::io::copy(&mut local, &mut remote)
            .with_context(|| {
                format!(
                    "failed uploading {} -> {}",
                    src.display(),
                    temporary
                )
            })?;

        remote.flush()?;
    }

    /*
     * Preserve the local file's Unix permissions where possible.
     */
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode() & 0o7777;

        let mut stat = ssh2::FileStat::default();
        stat.perm = Some(mode);

        let _ = sftp.setstat(Path::new(&temporary), stat);
    }

    /*
     * Rename is atomic on the same filesystem, so the destination
     * never becomes a partially uploaded file.
     */
    sftp.rename(
        Path::new(&temporary),
        Path::new(dest),
        None,
    )
    .with_context(|| {
        format!(
            "failed to replace remote destination {}",
            dest
        )
    })?;

    println!("  uploaded");

    Ok(())
}

fn create_remote_directories(
    sftp: &Sftp,
    path: &Path,
) -> Result<()> {
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component);

        match sftp.stat(&current) {
            Ok(stat) => {
                /*
                 * It exists. Continue.
                 */
                if stat.perm.is_none() {
                    continue;
                }
            }

            Err(_) => {
                /*
                 * Directory doesn't exist.
                 */
                sftp.mkdir(&current, 0o755)
                    .with_context(|| {
                        format!(
                            "failed to create remote directory {}",
                            current.display()
                        )
                    })?;
            }
        }
    }

    Ok(())
}
