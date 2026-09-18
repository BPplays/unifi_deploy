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
    ChannelMsg,
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

const SFTP_REQUEST_TIMEOUT_SECS: u64 = 30;
const SSH_INACTIVITY_TIMEOUT_SECS: u64 = 120;
const IO_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long, value_name = "CONFIG")]
    config: PathBuf,
}

/// `sftp` means "try SFTP first, then fall back to SSH".
/// `ssh` means "skip SFTP and use plain SSH".
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
enum TransferMethod {
    #[default]
    Sftp,
    Ssh,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SSHInfo {
    host: String,
    user: String,

    #[serde(default)]
    transfer_method: TransferMethod,
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

#[derive(Debug, Clone)]
struct Job {
    host: SSHInfo,
    files: Vec<FilePair>,
}

enum Transport {
    Sftp(SftpSession),
    Ssh,
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        /*
         * TODO: replace this with known_hosts verification.
         *
         * For now, print the key so it is visible while testing.
         */
        println!("server key: {server_public_key:?}");

        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let configs = load_config(&args.config)?;

    println!("Loaded {} config(s)", configs.len());

    /*
     * Each config gets its own polling loop so configs with different
     * check intervals can operate independently.
     */
    let mut tasks = Vec::with_capacity(configs.len());

    for (config_index, config) in configs.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            if let Err(error) =
                run_config(config_index + 1, config).await
            {
                eprintln!(
                    "[config {}] ERROR: {error:#}",
                    config_index + 1
                );
            }
        }));
    }

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

    let configs: Vec<Config> =
        serde_yaml::from_reader(file)
            .with_context(|| {
                format!(
                    "failed to parse YAML: {}",
                    path.display()
                )
            })?;

    if configs.is_empty() {
        bail!("configuration contains no configs");
    }

    for (config_index, config) in configs.iter().enumerate() {
        if config.hosts.is_empty() {
            bail!(
                "config {} contains no hosts",
                config_index + 1
            );
        }

        if config.files.is_empty() {
            bail!(
                "config {} contains no files",
                config_index + 1
            );
        }

        if config.ssh_key.trim().is_empty() {
            bail!(
                "config {} has an empty ssh_key",
                config_index + 1
            );
        }

        if config.check_interval == 0 {
            bail!(
                "config {} has check_interval = 0",
                config_index + 1
            );
        }

        for (file_index, file) in config.files.iter().enumerate() {
            if file.src.trim().is_empty() {
                bail!(
                    "config {} file {} has an empty src",
                    config_index + 1,
                    file_index + 1
                );
            }

            if file.dest.trim().is_empty() {
                bail!(
                    "config {} file {} has an empty dest",
                    config_index + 1,
                    file_index + 1
                );
            }

            let src = Path::new(&file.src);

            if !src.is_file() {
                bail!(
                    "config {} file {} source does not exist or is not a regular file: {}",
                    config_index + 1,
                    file_index + 1,
                    src.display()
                );
            }
        }
    }

    Ok(configs)
}

async fn run_config(
    config_index: usize,
    config: Config,
) -> Result<()> {
    println!();
    println!("=== Config {} ===", config_index);

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
        /*
         * Start every host at the same time.
         *
         * Each host gets its own task, so connecting to one host
         * does not block the other hosts.
         */
        let mut tasks = Vec::with_capacity(jobs.len());

        for job in jobs.iter().cloned() {
            let ssh_key = config.ssh_key.clone();

            tasks.push(tokio::spawn(async move {
                let host_name =
                    format!("{}@{}", job.host.user, job.host.host);

                if let Err(error) =
                    run_job(&job, &ssh_key).await
                {
                    eprintln!(
                        "[{}] ERROR: {error:#}",
                        host_name
                    );
                }
            }));
        }

        /*
         * Wait for all hosts to finish before starting the
         * next polling interval.
         */
        for task in tasks {
            task.await
                .context("host task panicked")?;
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

    let transport = match job.host.transfer_method {
        TransferMethod::Ssh => {
            println!("transfer method: SSH");
            Transport::Ssh
        }

        TransferMethod::Sftp => {
            println!(
                "transfer method: SFTP first, SSH fallback"
            );

            match try_open_sftp(&session).await {
                Ok(sftp) => {
                    println!("SFTP available");
                    Transport::Sftp(sftp)
                }

                Err(error) => {
                    println!(
                        "SFTP unavailable: {error:#}"
                    );
                    println!(
                        "falling back to SSH"
                    );

                    Transport::Ssh
                }
            }
        }
    };

    /*
     * Files are processed strictly in YAML order.
     */
    for file in &job.files {
        match &transport {
            Transport::Sftp(sftp) => {
                sync_file_sftp(
                    sftp,
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

            Transport::Ssh => {
                sync_file_ssh(
                    &session,
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
        }
    }

    if let Transport::Sftp(sftp) = &transport {
        sftp.close()
            .await
            .context("failed to close SFTP session")?;
    }

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
            Duration::from_secs(
                SSH_INACTIVITY_TIMEOUT_SECS,
            ),
        ),
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

    let rsa_hash = session
        .best_supported_rsa_hash()
        .await
        .context(
            "failed to determine supported RSA hash",
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

async fn try_open_sftp(
    session: &russh::client::Handle<ClientHandler>,
) -> Result<SftpSession> {
    let channel = session
        .channel_open_session()
        .await
        .context(
            "failed to open SFTP session channel"
        )?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .context(
            "SFTP subsystem request failed"
        )?;

    /*
     * The timeout must be configured before SftpSession::new()
     * because new_with_config() performs the initial SFTP
     * protocol initialization.
     */
    let sftp = SftpSession::new_with_config(
        channel.into_stream(),
        russh_sftp::client::Config {
            request_timeout_secs:
                SFTP_REQUEST_TIMEOUT_SECS,
            ..Default::default()
        },
    )
    .await
    .context("SFTP initialization failed")?;

    Ok(sftp)
}

async fn sync_file_sftp(
    sftp: &SftpSession,
    file: &FilePair,
) -> Result<()> {
    let src = Path::new(&file.src);

    println!(
        "checking {} -> {}",
        src.display(),
        file.dest
    );

    let local_hash =
        local_sha3_file(src).await?;

    let remote_hash =
        remote_sha3_sftp(
            sftp,
            &file.dest,
        )
        .await?;

    match remote_hash {
        Some(hash) if hash == local_hash => {
            println!("  unchanged");
        }

        Some(_) => {
            println!("  changed; uploading");

            upload_file_sftp(
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

            upload_file_sftp(
                sftp,
                src,
                &file.dest,
            )
            .await?;
        }
    }

    Ok(())
}

async fn sync_file_ssh(
    session: &russh::client::Handle<ClientHandler>,
    file: &FilePair,
) -> Result<()> {
    let src = Path::new(&file.src);

    println!(
        "checking {} -> {}",
        src.display(),
        file.dest
    );

    let local_hash =
        local_sha3_file(src).await?;

    /*
     * The entire remote file is streamed over SSH to the
     * computer running this program, and hashed locally.
     */
    let remote_hash =
        remote_sha3_ssh(
            session,
            &file.dest,
        )
        .await?;

    match remote_hash {
        Some(hash) if hash == local_hash => {
            println!("  unchanged");
        }

        Some(_) => {
            println!("  changed; uploading");

            upload_file_ssh(
                session,
                src,
                &file.dest,
            )
            .await?;
        }

        None => {
            println!(
                "  destination does not exist; uploading"
            );

            upload_file_ssh(
                session,
                src,
                &file.dest,
            )
            .await?;
        }
    }

    Ok(())
}

async fn local_sha3_file(
    path: &Path,
) -> Result<String> {
    let mut file =
        TokioFile::open(path)
            .await
            .with_context(|| {
                format!(
                    "failed to open {}",
                    path.display()
                )
            })?;

    let mut hasher = Sha3_256::new();
    let mut buffer = [0u8; IO_BUFFER_SIZE];

    loop {
        let count =
            file.read(&mut buffer).await?;

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(
        hasher.finalize()
    ))
}

async fn remote_sha3_sftp(
    sftp: &SftpSession,
    path: &str,
) -> Result<Option<String>> {
    if !sftp
        .try_exists(path)
        .await
        .with_context(|| {
            format!(
                "failed checking remote path {}",
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
    let mut buffer = [0u8; IO_BUFFER_SIZE];

    loop {
        let count =
            file.read(&mut buffer).await?;

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
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

async fn remote_sha3_ssh(
    session: &russh::client::Handle<ClientHandler>,
    path: &str,
) -> Result<Option<String>> {
    let mut channel = session
        .channel_open_session()
        .await
        .context(
            "failed to open SSH channel for remote read"
        )?;

    let quoted_path = shell_quote(path);

    /*
     * Exit 66 means the file does not exist.
     *
     * Using shell redirection rather than:
     *
     *   cat -- <path>
     *
     * avoids relying on the remote cat implementation supporting
     * the `--` option.
     */
    let command = format!(
        "if [ -f {path} ]; then cat < {path}; else exit 66; fi",
        path = quoted_path
    );

    channel
        .exec(true, command)
        .await
        .context(
            "failed to execute remote file read"
        )?;

    let mut hasher = Sha3_256::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                hasher.update(&data);
            }

            ChannelMsg::ExtendedData {
                data,
                ext,
            } => {
                /*
                 * SSH extended data type 1 is stderr.
                 */
                if ext == 1 {
                    let remaining =
                        4096usize.saturating_sub(stderr.len());

                    let amount =
                        remaining.min(data.len());

                    stderr.extend_from_slice(
                        &data[..amount],
                    );
                }
            }

            ChannelMsg::ExitStatus {
                exit_status: status,
            } => {
                exit_status = Some(status);
            }

            ChannelMsg::Close => {
                break;
            }

            _ => {}
        }
    }

    match exit_status {
        Some(0) => {
            Ok(Some(
                hex::encode(hasher.finalize())
            ))
        }

        Some(66) => {
            Ok(None)
        }

        Some(status) => {
            let stderr = String::from_utf8_lossy(&stderr);

            if stderr.is_empty() {
                bail!(
                    "remote read of {} exited with status {}",
                    path,
                    status
                );
            } else {
                bail!(
                    "remote read of {} exited with status {}: {}",
                    path,
                    status,
                    stderr.trim()
                );
            }
        }

        None => {
            bail!(
                "remote read of {} closed without an exit status",
                path
            );
        }
    }
}

async fn upload_file_sftp(
    sftp: &SftpSession,
    src: &Path,
    dest: &str,
) -> Result<()> {
    if let Some(parent) = remote_parent(dest) {
        create_remote_directories(
            sftp,
            parent,
        )
        .await?;
    }

    let temporary =
        format!("{}.tmp", dest);

    /*
     * Remove a stale temp file left over from an interrupted
     * previous transfer.
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

    let mut local =
        TokioFile::open(src)
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

    tokio::io::copy(
        &mut local,
        &mut remote,
    )
    .await
    .with_context(|| {
        format!(
            "failed uploading {} -> {}",
            src.display(),
            temporary
        )
    })?;

    remote
        .flush()
        .await
        .with_context(|| {
            format!(
                "failed flushing {}",
                temporary
            )
        })?;

    remote
        .close()
        .await
        .with_context(|| {
            format!(
                "failed closing {}",
                temporary
            )
        })?;

    /*
     * Replace the destination only after the complete upload.
     */
    if sftp
        .try_exists(dest)
        .await
        .with_context(|| {
            format!(
                "failed checking destination {}",
                dest
            )
        })?
    {
        sftp.remove_file(dest)
            .await
            .with_context(|| {
                format!(
                    "failed removing destination {}",
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

async fn upload_file_ssh(
    session: &russh::client::Handle<ClientHandler>,
    src: &Path,
    dest: &str,
) -> Result<()> {
    let temporary =
        format!("{}.tmp", dest);

    /*
     * mkdir -p and cat are part of one shell command, so the file
     * is never created if the parent directory cannot be created.
     */
    let parent_command = match remote_parent(dest) {
        Some(parent) => {
            let quoted_parent =
                shell_quote(parent);

            format!(
                "mkdir -p {parent}",
                parent = quoted_parent
            )
        }

        None => String::from(":"),
    };

    let quoted_temporary =
        shell_quote(&temporary);

    let command = format!(
        "{mkdir} && cat > {temporary}",
        mkdir = parent_command,
        temporary = quoted_temporary,
    );

    let mut channel = session
        .channel_open_session()
        .await
        .context(
            "failed to open SSH channel for upload"
        )?;

    channel
        .exec(true, command)
        .await
        .context(
            "failed to start remote upload"
        )?;

    let local =
        TokioFile::open(src)
            .await
            .with_context(|| {
                format!(
                    "failed to open local file {}",
                    src.display()
                )
            })?;

    /*
     * Stream the local file into the remote command's stdin.
     */
    channel
        .data(local)
        .await
        .with_context(|| {
            format!(
                "failed streaming {} to remote host",
                src.display()
            )
        })?;

    /*
     * Tell remote cat that the input file is complete.
     */
    channel
        .eof()
        .await
        .context(
            "failed sending upload EOF"
        )?;

    let mut stderr = Vec::new();
    let mut exit_status = None;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::ExtendedData {
                data,
                ext,
            } => {
                if ext == 1 {
                    let remaining =
                        4096usize.saturating_sub(stderr.len());

                    let amount =
                        remaining.min(data.len());

                    stderr.extend_from_slice(
                        &data[..amount],
                    );
                }
            }

            ChannelMsg::ExitStatus {
                exit_status: status,
            } => {
                exit_status = Some(status);
            }

            ChannelMsg::Close => {
                break;
            }

            _ => {}
        }
    }

    match exit_status {
        Some(0) => {}

        Some(status) => {
            let stderr =
                String::from_utf8_lossy(&stderr);

            if stderr.is_empty() {
                bail!(
                    "remote upload command exited with status {}",
                    status
                );
            } else {
                bail!(
                    "remote upload command exited with status {}: {}",
                    status,
                    stderr.trim()
                );
            }
        }

        None => {
            bail!(
                "remote upload command closed without an exit status"
            );
        }
    }

    /*
     * The upload succeeded. Now atomically-ish replace the
     * destination using the remote `mv` operation.
     */
    let move_command = format!(
        "mv -f {temporary} {destination}",
        temporary = shell_quote(&temporary),
        destination = shell_quote(dest),
    );

    exec_checked(
        session,
        &move_command,
    )
    .await
    .with_context(|| {
        format!(
            "failed replacing destination {}",
            dest
        )
    })?;

    println!("  uploaded");

    Ok(())
}

async fn exec_checked(
    session: &russh::client::Handle<ClientHandler>,
    command: &str,
) -> Result<()> {
    let mut channel = session
        .channel_open_session()
        .await
        .context(
            "failed to open SSH command channel"
        )?;

    channel
        .exec(true, command)
        .await
        .with_context(|| {
            format!(
                "failed to execute remote command: {}",
                command
            )
        })?;

    let mut stderr = Vec::new();
    let mut exit_status = None;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::ExtendedData {
                data,
                ext,
            } => {
                if ext == 1 {
                    let remaining =
                        4096usize.saturating_sub(stderr.len());

                    let amount =
                        remaining.min(data.len());

                    stderr.extend_from_slice(
                        &data[..amount],
                    );
                }
            }

            ChannelMsg::ExitStatus {
                exit_status: status,
            } => {
                exit_status = Some(status);
            }

            ChannelMsg::Close => {
                break;
            }

            _ => {}
        }
    }

    match exit_status {
        Some(0) => Ok(()),

        Some(status) => {
            let stderr =
                String::from_utf8_lossy(&stderr);

            if stderr.is_empty() {
                bail!(
                    "remote command exited with status {}",
                    status
                );
            } else {
                bail!(
                    "remote command exited with status {}: {}",
                    status,
                    stderr.trim()
                );
            }
        }

        None => {
            bail!(
                "remote command closed without an exit status"
            );
        }
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

fn remote_parent(path: &str) -> Option<&str> {
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

/*
 * Quote a string for a POSIX shell using single quotes.
 *
 * Example:
 *
 *   abc'def
 *
 * becomes:
 *
 *   'abc'"'"'def'
 */
fn shell_quote(value: &str) -> String {
    format!(
        "'{}'",
        value.replace(
            '\'',
            "'\"'\"'"
        )
    )
}
