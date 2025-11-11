//! SMB2/3 Client CLI

use clap::{Parser, Subcommand};
use rust_smb::client::{ClientConfig, SmbClient};
use rust_smb::protocol::smb2_constants::{CreateDisposition, DesiredAccess};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "smb-client")]
#[command(about = "Rust SMB2/3 Client", long_about = None)]
struct Args {
    /// SMB server address or hostname
    #[arg(short = 'H', long)]
    host: String,

    /// Port to connect to
    #[arg(short = 'p', long, default_value = "445")]
    port: u16,

    /// Username for authentication
    #[arg(short = 'u', long, default_value = "guest")]
    username: String,

    /// Password for authentication
    #[arg(short = 'P', long, default_value = "")]
    password: String,

    /// Domain/workgroup
    #[arg(short = 'd', long, default_value = "WORKGROUP")]
    domain: String,

    /// Share name to connect to
    #[arg(short = 's', long)]
    share: String,

    /// Log level
    #[arg(short = 'l', long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List files in a directory
    Ls {
        /// Directory path to list
        #[arg(default_value = "/")]
        path: String,
    },

    /// Download a file from the server
    Get {
        /// Remote file path
        remote: String,
        /// Local file path (optional, uses remote filename if not specified)
        local: Option<PathBuf>,
    },

    /// Upload a file to the server
    Put {
        /// Local file path
        local: PathBuf,
        /// Remote file path (optional, uses local filename if not specified)
        remote: Option<String>,
    },

    /// Display file information
    Info {
        /// File path
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

    tracing::info!("Connecting to {}:{}", args.host, args.port);

    // Create client config
    let mut config = ClientConfig::default();
    config.username = args.username.clone();
    config.password = args.password.clone();
    config.domain = args.domain.clone();

    // Create client
    let mut client = SmbClient::with_config(config);

    // Connect to server
    client.connect(&args.host, args.port).await?;

    // Authenticate
    if args.username == "guest" && args.password.is_empty() {
        tracing::info!("Using guest authentication");
        // Guest auth is handled in session_setup
    } else {
        tracing::info!("Authenticating as {}\\{}", args.domain, args.username);
    }

    // Session setup
    client.session_setup().await?;

    // Connect to share
    tracing::info!("Connecting to share: {}", args.share);
    let tree_id = client.tree_connect(&args.share).await?;

    // Execute command
    match args.command {
        Commands::Ls { path } => {
            tracing::info!("Listing directory: {}", path);
            // For now, just open the directory
            let handle = client
                .open_file(
                    tree_id,
                    &path,
                    DesiredAccess::FILE_READ_DATA | DesiredAccess::FILE_READ_ATTRIBUTES,
                    CreateDisposition::OPEN,
                )
                .await?;

            // TODO: Implement directory listing using Query Directory
            tracing::info!("Directory opened successfully: {}", path);

            client.close_file(&handle).await?;
        }

        Commands::Get { remote, local } => {
            let local_path = local
                .unwrap_or_else(|| PathBuf::from(remote.split('/').last().unwrap_or("download")));

            tracing::info!("Downloading {} -> {}", remote, local_path.display());

            // Open file for reading
            let handle = client
                .open_file(
                    tree_id,
                    &remote,
                    DesiredAccess::FILE_READ_DATA | DesiredAccess::FILE_READ_ATTRIBUTES,
                    CreateDisposition::OPEN,
                )
                .await?;

            // Read file in chunks
            let mut data = Vec::new();
            let mut offset = 0u64;
            let chunk_size = 65536u32;

            loop {
                let chunk = client.read_file(&handle, offset, chunk_size).await?;
                if chunk.is_empty() {
                    break;
                }
                data.extend_from_slice(&chunk);
                offset += chunk.len() as u64;
            }

            // Write to local file
            std::fs::write(&local_path, data)?;
            tracing::info!("Downloaded {} bytes", offset);

            // Close file
            client.close_file(&handle).await?;
        }

        Commands::Put { local, remote } => {
            let remote_path = remote.unwrap_or_else(|| {
                local
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("upload")
                    .to_string()
            });

            tracing::info!("Uploading {} -> {}", local.display(), remote_path);

            // Read local file
            let data = std::fs::read(&local)?;

            // Open/create remote file
            let handle = client
                .open_file(
                    tree_id,
                    &remote_path,
                    DesiredAccess::FILE_WRITE_DATA | DesiredAccess::FILE_WRITE_ATTRIBUTES,
                    CreateDisposition::OverwriteIf,
                )
                .await?;

            // Write file in chunks
            let mut offset = 0u64;
            let chunk_size = 65536;

            for chunk in data.chunks(chunk_size) {
                let written = client.write_file(&handle, offset, chunk).await?;
                offset += written as u64;
            }

            tracing::info!("Uploaded {} bytes", offset);

            // Close file
            client.close_file(&handle).await?;
        }

        Commands::Info { path } => {
            tracing::info!("Getting info for: {}", path);

            // Open file/directory
            let handle = client
                .open_file(
                    tree_id,
                    &path,
                    DesiredAccess::FILE_READ_ATTRIBUTES,
                    CreateDisposition::OPEN,
                )
                .await?;

            tracing::info!("File/Directory: {}", path);
            tracing::info!("Handle: {:?}", handle);
            // TODO: Query and display file information

            // Close handle
            client.close_file(&handle).await?;
        }
    }

    // Disconnect
    client.disconnect().await?;
    tracing::info!("Disconnected");

    Ok(())
}
