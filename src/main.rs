use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use russh::{
    client,
    keys::{load_secret_key, PrivateKeyWithHashAlg},
};
use russh_sftp::{
    client::SftpSession,
    protocol::OpenFlags,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tokio::{
    fs::File as TokioFile,
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
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

/*
 * SSH client handler.
 *
 * IMPORTANT:
 * check_server_key() currently accepts any server key.
 *
 * That is convenient while getting the program working, but it
 * should eventually verify ~/.ssh/known_hosts.
 */
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        println!("server key: {server_public_key:?}");

        /*
         * TODO: verify against known_hosts.
         */
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let configs = load_config(&args.config)?;

    println!("Loaded {} config(s)", configs.len());

    /*
     * Each YAML config gets its own independent async task.
     *
     * This is important because every Config can have a different
     * check_interval.
     */
    let mut tasks = Vec::with_capacity(configs.len());

    for (config_index, config) in configs.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            println!(
                "\n=== Config {} ===",
                config_index + 1
            );

            if let Err(error) = run_config(config).await {
                eprintln!(
                    "[config {}] ERROR: {error:#}",
                    config_index + 1
                );
            }
        }));
    }

    /*
     * Config loops are intended to run forever.
     *
     * Waiting on all tasks keeps main alive while still allowing
     * the configs to operate independently.
     */
    for task in tasks {
        task.await
            .context("configuration task panicked")?;
    }

    Ok(())
}

fn load_config(path: &Path) -> Result<Vec<Config>> {
    let file = File::open(path)
        .with_context(|| {
            format!(
                "failed to open config: {}",
                path.display()
            )
        })?;

    let configs: Vec<Config> = serde_yaml::from_reader(file)
        .with_context(|| {
            format!(
                "failed to parse YAML: {}",
                path.display()
            )
        })?;

    if configs.is_empty() {
        bail!("configuration contains no configs");
    }

    for (index, config) in configs.iter().enumerate() {
        if config.hosts.is_empty() {
            bail!(
                "config {} contains no hosts",
                index + 1
            );
        }

        if config.files.is_empty() {
            bail!(
                "config {} contains no files",
                index + 1
            );
        }

        if config.ssh_key.trim().is_empty() {
            bail!(
                "config {} has an empty ssh_key",
                index + 1
            );
        }

        if config.check_interval == 0 {
            bail!(
                "config {} has check_interval = 0",
                index + 1
            );
        }

        /*
         * Validate every source file up front so a bad path doesn't
         * repeatedly fail every poll cycle.
         */
        for (file_index, file) in config.files.iter().enumerate() {
            let src = Path::new(&file.src);

            if !src.is_file() {
                bail!(
                    "config {} file {} source does not exist or is not a regular file: {}",
                    index + 1,
                    file_index + 1,
                    src.display()
                );
            }

            if file.dest.trim().is_empty() {
                bail!(
                    "config {} file {} has an empty destination",
                    index + 1,
                    file_index + 1
                );
            }
        }
    }

    Ok(configs)
}

async fn run_config(config: Config) -> Result<()> {
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
            if let Err(error) = run_job(
                job,
                &config.ssh_key,
            )
            .await
            {
                eprintln!(
                    "[{}@{}] ERROR: {error:#}",
                    job.host.user,
                    job.host.host
                );
            }
        }

        println!(
            "\nnext check in {} second(s)",
            config.check_interval
        );

        sleep(Duration::from_secs(
            config.check_interval,
        ))
        .await;
    }
}

async fn run_job(
    job: &Job,
    ssh_key: &str,
) -> Result<()> {
    println!(
        "\n--- {}@{} ---",
        job.host.user,
        job.host.host
    );

    let session = connect_ssh(
        &job.host,
        ssh_key,
    )
    .await?;

    /*
     * Open the SFTP subsystem.
     */
    let channel = session
        .channel_open_session()
        .await
        .context("failed to open SSH session channel")?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .context("failed to request SFTP subsystem")?;

    let sftp = SftpSession::new(
        channel.into_stream()
    )
    .await
    .context("failed to initialize SFTP")?;

    sftp.set_timeout(30);

    /*
     * Process files strictly in YAML order.
     */
    for file in &job.files {
        sync_file(
            &sftp,
            file,
        )
        .await
        .with_context(|| {
            format!(
                "failed syncing {} -> {}",
                file.src,
                file.dest
            )
        })?;
    }

    /*
     * Explicitly close the SFTP subsystem.
     */
    sftp.close()
        .await
        .context("failed to close SFTP session")?;

    Ok(())
}

async fn connect_ssh(
    host: &SSHInfo,
    ssh_key: &str,
) -> Result<russh::client::Handle<ClientHandler>> {
    println!(
        "connecting to {}@{}",
        host.user,
        host.host
    );

    let private_key = load_secret_key(
        Path::new(ssh_key),
        None,
    )
    .with_context(|| {
        format!(
            "failed to load SSH private key: {}",
            ssh_key
        )
    })?;

    let config = russh::client::Config {
        inactivity_timeout: Some(
            Duration::from_secs(30)
        ),

        /*
         * Avoid Nagle's algorithm for SFTP traffic.
         */
        nodelay: true,

        ..Default::default()
    };

    let mut session = client::connect(
        Arc::new(config),
        (host.host.as_str(), 22),
        ClientHandler,
    )
    .await
    .with_context(|| {
        format!(
            "failed to connect to {}:22",
            host.host
        )
    })?;

    /*
     * Russh needs to know which RSA hash algorithm the server
     * supports when an RSA key is used.
     */
    let rsa_hash = session
        .best_supported_rsa_hash()
        .await
        .context(
            "failed to determine supported RSA hash algorithm"
        )?
        .flatten();

    let key = PrivateKeyWithHashAlg::new(
        Arc::new(private_key),
        rsa_hash,
    );

    let auth = session
        .authenticate_publickey(
            &host.user,
            key,
        )
        .await
        .with_context(|| {
            format!(
                "public-key authentication failed for {}@{}",
                host.user,
                host.host
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
        host.user,
        host.host
    );

    Ok(session)
}

async fn sync_file(
    sftp: &SftpSession,
    file: &FilePair,
) -> Result<()> {
    let src = Path::new(&file.src);

    println!(
        "checking {} -> {}",
        src.display(),
        file.dest
    );

    /*
     * Calculate the source hash.
     *
     * This deliberately uses SHA3-256 to match your current
     * implementation.
     */
    let local_hash = sha3_file(src)
        .with_context(|| {
            format!(
                "failed to hash {}",
                src.display()
            )
        })?;

    let remote_hash =
        remote_sha3_256(
            sftp,
            &file.dest,
        )
        .await?;

    match remote_hash {
        Some(hash) if hash == local_hash => {
            println!("  unchanged");
        }

        Some(_) => {
            println!(
                "  changed; uploading"
            );

            upload_file(
                sftp,
                src,
                &file.dest,
            )
            .await?;
        }

        None => {
            println!(
                "  destination does not exist; uploading"
            );

            upload_file(
                sftp,
                src,
                &file.dest,
            )
            .await?;
        }
    }

    Ok(())
}

fn sha3_file(
    path: &Path,
) -> Result<String> {
    let mut file = File::open(path)?;

    let mut hasher = Sha3_256::new();

    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = file.read(
            &mut buffer
        )?;

        if count == 0 {
            break;
        }

        hasher.update(
            &buffer[..count]
        );
    }

    Ok(hex::encode(
        hasher.finalize()
    ))
}

async fn remote_sha3_256(
    sftp: &SftpSession,
    path: &str,
) -> Result<Option<String>> {
    if !sftp
        .try_exists(path)
        .await
        .with_context(|| {
            format!(
                "failed to check remote path {}",
                path
            )
        })?
    {
        return Ok(None);
    }

    let mut file = sftp
        .open(path)
        .await
        .with_context(|| {
            format!(
                "failed to open remote file {}",
                path
            )
        })?;

    let mut hasher = Sha3_256::new();

    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = file
            .read(&mut buffer)
            .await
            .with_context(|| {
                format!(
                    "failed reading remote file {}",
                    path
                )
            })?;

        if count == 0 {
            break;
        }

        hasher.update(
            &buffer[..count]
        );
    }

    file.close()
        .await
        .with_context(|| {
            format!(
                "failed closing remote file {}",
                path
            )
        })?;

    Ok(Some(
        hex::encode(hasher.finalize())
    ))
}

async fn upload_file(
    sftp: &SftpSession,
    src: &Path,
    dest: &str,
) -> Result<()> {
    /*
     * Make sure the remote parent exists.
     */
    if let Some(parent) = remote_parent(dest) {
        create_remote_directories(
            sftp,
            parent,
        )
        .await?;
    }

    /*
     * Upload to a temporary file first.
     *
     * If the transfer fails, the destination isn't modified.
     */
    let temporary = format!(
        "{}.tmp",
        dest
    );

    /*
     * Clean up an old temporary file from a previous failed run.
     */
    if sftp
        .try_exists(&temporary)
        .await
        .with_context(|| {
            format!(
                "failed checking temporary file {}",
                temporary
            )
        })?
    {
        sftp.remove_file(&temporary)
            .await
            .with_context(|| {
                format!(
                    "failed removing stale temporary file {}",
                    temporary
                )
            })?;
    }

    let mut local = TokioFile::open(src)
        .await
        .with_context(|| {
            format!(
                "failed to open local file {}",
                src.display()
            )
        })?;

    let mut remote = sftp
        .open_with_flags(
            &temporary,
            OpenFlags::CREATE
                | OpenFlags::TRUNCATE
                | OpenFlags::WRITE,
        )
        .await
        .with_context(|| {
            format!(
                "failed creating remote temporary file {}",
                temporary
            )
        })?;

    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = local
            .read(&mut buffer)
            .await
            .with_context(|| {
                format!(
                    "failed reading local file {}",
                    src.display()
                )
            })?;

        if count == 0 {
            break;
        }

        remote
            .write_all(&buffer[..count])
            .await
            .with_context(|| {
                format!(
                    "failed writing remote temporary file {}",
                    temporary
                )
            })?;
    }

    remote
        .flush()
        .await
        .with_context(|| {
            format!(
                "failed flushing remote temporary file {}",
                temporary
            )
        })?;

    /*
     * close() waits for pending writes to complete and reports
     * the remote close result.
     */
    remote
        .close()
        .await
        .with_context(|| {
            format!(
                "failed closing remote temporary file {}",
                temporary
            )
        })?;

    /*
     * SFTP v3 rename does not necessarily overwrite an existing
     * destination. Remove the old destination only after the new
     * file has been completely uploaded.
     */
    if sftp
        .try_exists(dest)
        .await
        .with_context(|| {
            format!(
                "failed checking existing destination {}",
                dest
            )
        })?
    {
        sftp.remove_file(dest)
            .await
            .with_context(|| {
                format!(
                    "failed removing existing destination {}",
                    dest
                )
            })?;
    }

    sftp.rename(
        &temporary,
        dest,
    )
    .await
    .with_context(|| {
        format!(
            "failed renaming {} -> {}",
            temporary,
            dest
        )
    })?;

    println!("  uploaded");

    Ok(())
}

fn remote_parent(
    path: &str,
) -> Option<&str> {
    match path.rsplit_once('/') {
        Some((parent, _filename)) => {
            if parent.is_empty() {
                Some("/")
            } else {
                Some(parent)
            }
        }

        None => None,
    }
}

async fn create_remote_directories(
    sftp: &SftpSession,
    path: &str,
) -> Result<()> {
    if path.is_empty() || path == "/" {
        return Ok(());
    }

    let absolute = path.starts_with('/');

    let mut current = if absolute {
        String::from("/")
    } else {
        String::new()
    };

    for component in path.split('/') {
        if component.is_empty()
            || component == "."
        {
            continue;
        }

        if !current.is_empty()
            && !current.ends_with('/')
        {
            current.push('/');
        }

        current.push_str(component);

        if !sftp
            .try_exists(&current)
            .await
            .with_context(|| {
                format!(
                    "failed checking remote directory {}",
                    current
                )
            })?
        {
            sftp.create_dir(&current)
                .await
                .with_context(|| {
                    format!(
                        "failed creating remote directory {}",
                        current
                    )
                })?;
        }
    }

    Ok(())
}
