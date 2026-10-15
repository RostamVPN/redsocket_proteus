//! Doomed Proxy Example.
//!
//! A simple TCP proxy designed for testing, which optionally terminates
//! connections abruptly after a configurable timeout.

use std::error::Error;

use clap::Parser;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "A simple TCP proxy that optionally produces an error after a timeout"
)]
struct Args {
    /// Target forwarding address (e.g., 127.0.0.1:8080)
    #[arg(short, long, value_name = "ADDR:PORT", required = true)]
    connect: String,

    /// Address to listen on
    #[arg(
        short,
        long,
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:1080"
    )]
    listen: String,

    /// Timeout in seconds (e.g., 30)
    #[arg(short, long, value_name = "SECONDS", value_parser = parse_duration)]
    timeout: Option<Duration>,
}

/// Helper to convert seconds from CLI into a Duration
fn parse_duration(arg: &str) -> Result<Duration, String> {
    arg.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("'{}' is not a valid number of seconds", arg))
}

/// A simple TCP proxy that optionally terminates connections after a timeout.
///
/// This function sets up a `TcpListener` that proxies incoming connections to a specified
/// target address. If a timeout is provided via command-line arguments, each connection
/// will be terminated after the specified duration.
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Returns an error if the listener fails to bind.
///   Otherwise, it continuously loops over accepted connections and proxies them to
///   the target.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let listener = TcpListener::bind(&args.listen).await?;
    println!(
        "Proxying {} -> {} (timeout: {:?})",
        args.listen, args.connect, args.timeout
    );

    while let Ok((mut inbound, _)) = listener.accept().await {
        let target = args.connect.clone();
        let timeout_dur = args.timeout.unwrap_or(Duration::MAX);

        tokio::spawn(async move {
            let result = timeout(timeout_dur, async move {
                let mut outbound = TcpStream::connect(target).await?;
                copy_bidirectional(&mut inbound, &mut outbound).await
            })
            .await;

            // Try to emit a TCP reset instead of EOF on timeout.
            //   Requires `nightly` build with the `tcp_linger` feature.
            //   https://github.com/rust-lang/rust/issues/88494
            // if let Ok(std_stream) = inbound.into_std() {
            //     let _ = std_stream.set_linger(Some(Duration::from_secs(0)));
            // }

            match result {
                Ok(Ok((sent, received))) => {
                    println!("Closed: {} bytes sent, {} received", sent, received);
                }
                Ok(Err(e)) => eprintln!("Transfer error: {}", e),
                Err(_) => eprintln!("Connection timed out"),
            }
        });
    }
    Ok(())
}
