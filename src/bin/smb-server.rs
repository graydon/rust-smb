//! SMB2/3 Server implementation

use clap::Parser;
use rust_smb::server::{ServerConfig, SmbServer};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "smb-server")]
#[command(about = "Rust SMB2/3 Server", long_about = None)]
struct Args {
    /// Server name
    #[arg(short = 'n', long, default_value = "RUST-SMB")]
    server_name: String,

    /// Workgroup/domain name
    #[arg(short = 'w', long, default_value = "WORKGROUP")]
    workgroup: String,

    /// Port to listen on
    #[arg(short = 'p', long, default_value = "445")]
    port: u16,

    /// Bind address
    #[arg(short = 'b', long, default_value = "0.0.0.0")]
    bind: String,

    /// Allow guest access
    #[arg(long, default_value = "true")]
    allow_guest: bool,

    /// Require signing
    #[arg(long, default_value = "false")]
    require_signing: bool,

    /// Maximum connections
    #[arg(long, default_value = "100")]
    max_connections: usize,

    /// Share definitions (can be specified multiple times)
    /// Format: name:path:description
    #[arg(short = 's', long, value_parser = parse_share)]
    shares: Vec<ShareDef>,

    /// Root directory for serving files
    #[arg(short = 'r', long, required = true)]
    root_dir: PathBuf,

    /// Log level
    #[arg(short = 'l', long, default_value = "info")]
    log_level: String,
}

#[derive(Debug, Clone)]
struct ShareDef {
    name: String,
    path: PathBuf,
    description: String,
}

fn parse_share(s: &str) -> Result<ShareDef, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 {
        return Err("Share format: name:path[:description]".to_string());
    }

    Ok(ShareDef {
        name: parts[0].to_string(),
        path: PathBuf::from(parts[1]),
        description: parts.get(2).unwrap_or(&"").to_string(),
    })
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

    tracing::info!("Starting SMB2/3 server");
    tracing::info!("Server name: {}", args.server_name);
    tracing::info!("Workgroup: {}", args.workgroup);

    // Create server configuration
    let config = ServerConfig {
        server_name: args.server_name,
        server_description: "Rust SMB2/3 Server".to_string(),
        workgroup: args.workgroup,
        allow_guest: args.allow_guest,
        require_signing: args.require_signing,
        max_connections: args.max_connections,
    };

    // Create server with filesystem backend
    tracing::info!(
        "Using filesystem backend with root: {}",
        args.root_dir.display()
    );
    let server = SmbServer::with_config(config).with_real_filesystem(args.root_dir.clone());

    // Add shares from command line
    if args.shares.is_empty() {
        // Add default share if none specified
        tracing::info!(
            "No shares specified, adding default share 'public' -> {}",
            args.root_dir.display()
        );
        server
            .add_share(
                "public",
                "Public share",
                args.root_dir.to_str().unwrap_or("/tmp"),
            )
            .await;
    } else {
        for share in &args.shares {
            tracing::info!("Adding share '{}' -> {}", share.name, share.path.display());
            server
                .add_share(
                    &share.name,
                    &share.description,
                    share.path.to_str().unwrap_or("/tmp"),
                )
                .await;
        }
    }

    // Bind to address
    let addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;

    tracing::info!("Server listening on {}", addr);
    tracing::info!("Press Ctrl+C to stop");
    tracing::info!("");
    tracing::info!("Test with:");
    tracing::info!("  smbclient -L //localhost -p {} -N", args.port);
    tracing::info!("  smbclient //localhost/public -p {} -N", args.port);
    tracing::info!("");

    // Handle shutdown signal
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutdown signal received, stopping server...");
        std::process::exit(0);
    });

    // Run the server
    server.run(addr).await?;

    Ok(())
}
