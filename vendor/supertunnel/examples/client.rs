//! SuperTunnel Client Example.
//!
//! This module provides a SOCKS5 proxy client that establishes a multiplexed,
//! reliable, and resumable tunnel to a SuperTunnel server.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use clap::Parser;
use fast_socks5::server::{Socks5ServerProtocol, SocksServerError};
use fast_socks5::{ReplyError, Socks5Command};
use supertunnel::io::{CopyError, TransferError, copy_spawn_try_join};
use supertunnel::net::NetworkTarget;
use supertunnel::proto::*;
use supertunnel::util::{DecodedSinkWriter, EncodedStreamReader};
use supertunnel::{FrameSize, Protocol};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "A client-side proxy forwarding socks5 connections to a supertunnel server"
)]
struct Args {
    /// Address of the supertunnel server (e.g., 127.0.0.1:8080)
    #[arg(short, long, value_name = "ADDR:PORT", required = true)]
    connect: String,

    /// Address to listen for socks5 connections
    #[arg(
        short,
        long,
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:1080"
    )]
    listen: String,
}

/// Initializes the client, parses arguments, and starts the SOCKS5 proxy.
///
/// This function sets up the entire client-side application. It performs the following steps:
/// 1. Initializes the logger.
/// 2. Parses command-line arguments for the server and listening addresses.
/// 3. Establishes a TCP connection to the SuperTunnel server.
/// 4. Sets up the protocol stack (Framing, Resumption, Reliability, Routing).
/// 5. Spawns a background task (`transfer`) to handle the persistent connection to the server, including reconnection logic.
/// 6. Binds a TCP listener to the specified SOCKS5 address.
/// 7. Enters a loop to accept and handle incoming SOCKS5 connections concurrently.
///
/// # Returns
///
/// * `io::Result<()>` - Returns `Ok(())` on successful listener setup. Errors can occur
///   if the server connection or listener binding/accepting fails.
#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let args = Args::parse();

    // We are the client, we need a connection to the supertunnel server.
    let outbound = TcpStream::connect(args.connect.clone()).await?;

    // We use a single tunnel for all incoming streams.
    let router = RoutingClient::<TcpPayload>::new();
    let router_handle = router.handle().clone();
    let resume = ResumptionClient::new(Reliability::new(router));
    let resume_handle = resume.handle().clone();
    let stack = Framing::new(resume);

    // We want to copy all data between our stack and the server.
    // Do this in the background while we process incoming socks5 connections below.
    tokio::spawn(transfer(
        stack,
        outbound,
        resume_handle,
        args.connect.clone(),
    ));

    // Compute the max payload chunk size for our stack.
    let stack_mss = PayloadCodec::mss(RoutingCodec::mss(ReliabilityCodec::mss(
        ResumptionCodec::mss(FramingCodec::mss(FramingCodec::mtu())),
    )));

    // Start listener for incoming socks5 connections.
    let listener = TcpListener::bind(&args.listen).await?;
    log::info!("Proxying {} -> {}", args.listen, args.connect);

    loop {
        // Handle each new socks request in the background.
        // We'll add new sessions into our existing shared router.
        let (inbound, _) = listener.accept().await?; // Exit on error.
        let router_handle = router_handle.clone();
        // handle_connection(inbound, router_handle, stack_mss).await;
        tokio::spawn(handle_connection(inbound, router_handle, stack_mss));
    }
}

#[derive(Debug)]
enum ClientError {
    #[expect(dead_code)]
    Socks(SocksServerError),
    #[expect(dead_code)]
    Tunnel(RoutingError),
    SocksCommandNotSupported,
}

impl From<SocksServerError> for ClientError {
    fn from(value: SocksServerError) -> Self {
        ClientError::Socks(value)
    }
}

impl From<RoutingError> for ClientError {
    fn from(value: RoutingError) -> Self {
        ClientError::Tunnel(value)
    }
}

/// Asynchronously handles a new incoming TCP connection by processing the SOCKS5 handshake
/// and tunneling the connection.
///
/// This function orchestrates the SOCKS5 negotiation and, upon success, integrates the
/// new session into the shared routing layer. It logs the outcome of the operation.
///
/// # Inputs
///
/// * `inbound: TcpStream` - The incoming TCP stream from a client trying to connect via SOCKS5.
/// * `handle: RoutingHandle<TcpPayload>` - A handle to the shared routing client, used to manage sessions.
/// * `mss: usize` - The Maximum Segment Size for the payload, ensuring data is chunked correctly.
async fn handle_connection(inbound: TcpStream, handle: RoutingHandle<TcpPayload>, mss: usize) {
    match socks_then_tunnel(inbound, handle, mss).await {
        Ok(target) => log::info!("New session added: {target}"),
        Err(e) => log::debug!("Session connection error: {e:?}"),
    };
}

/// Performs the SOCKS5 handshake and, if successful, establishes a new session.
///
/// This function first performs the SOCKS5 authentication and command processing. It only
/// supports the `TCPConnect` command. If the command is supported, it requests a new
/// session from the SuperTunnel server via the `RoutingHandle`. On success, it replies to the
/// SOCKS5 client and adds the new session to the router.
///
/// # Inputs
///
/// * `inbound: TcpStream` - The raw TCP stream from the SOCKS5 client.
/// * `handle: RoutingHandle<TcpPayload>` - A mutable handle to the routing client for session management.
/// * `mss: usize` - The Maximum Segment Size for the payload.
///
/// # Returns
///
/// * `Result<NetworkTarget, ClientError>` - On success, returns `Ok(NetworkTarget)` with details
///   of the destination. On failure, returns a `ClientError` variant, such as:
///   - `ClientError::SocksCommandNotSupported` if the client requests a command other than `TCPConnect`.
///   - `ClientError::Tunnel(...)` if the SuperTunnel server rejects or times out the session request.
///
/// # Errors
///
/// * Can error during SOCKS5 negotiation (e.g., I/O errors, invalid protocol usage).
/// * Can error if the session connection to the SuperTunnel server fails.
async fn socks_then_tunnel(
    inbound: TcpStream,
    mut handle: RoutingHandle<TcpPayload>,
    mss: usize,
) -> Result<NetworkTarget, ClientError> {
    let socks = Socks5ServerProtocol::accept_no_auth(inbound).await?;
    let (socks, cmd, target) = socks.read_command().await?;

    if cmd != Socks5Command::TCPConnect {
        socks.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ClientError::SocksCommandNotSupported);
    };

    let target = NetworkTarget::from(target.into_string_and_port());
    let timeout = Duration::from_secs(5);

    match handle.connect_session(target.clone(), Some(timeout)).await {
        Ok(session_id) => {
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
            let inbound = socks.reply_success(bind_addr).await?;

            let (src, dst) = inbound.into_split();
            let client_io = TcpPayload::new(session_id, src, dst, mss);

            handle.add_session(session_id, client_io).await?;
            Ok(target)
        }
        Err(e) => {
            socks.reply_error(&ReplyError::ConnectionTimeout).await?;
            Err(e.into())
        }
    }
}

/// Manages the data transfer between the local protocol stack and the remote SuperTunnel server.
///
/// This function creates a bidirectional data transfer loop. It is designed to be resilient
/// to network interruptions. If the connection to the server is lost (`TransferError::Network`),
/// it attempts to reconnect and resume the session using the `ResumptionHandle`.
///
/// # Inputs
///
/// * `stack: T` - The protocol stack (`Framing`, `Resumption`, etc.) to communicate with.
/// * `outbound: TcpStream` - The initial TCP stream connected to the SuperTunnel server.
/// * `resume_handle: ResumptionHandle` - A handle to manage session resumption on reconnect.
/// * `reconnect: String` - The server address to use for reconnection attempts.
///
/// # Returns
///
/// * `Result<(u64, u64), TransferError>` - On success, returns a tuple of bytes transferred.
///   On a non-recoverable error, returns the underlying `TransferError`.  The function is
///   designed to loop indefinitely on network errors.
///
/// # Errors
///
/// * Returns a `TransferError` if a non-network error occurs (e.g., a protocol violation)
///   or if reconnection fails after a network error.
async fn transfer<T>(
    stack: T,
    outbound: TcpStream,
    resume_handle: ResumptionHandle,
    reconnect: String,
) -> Result<(usize, usize), TransferError<CopyError>>
where
    T: Protocol + Send + 'static,
    <T as Protocol>::Codec: Send,
    <T as Protocol>::Message: Send,
    <T as Protocol>::StreamHalf: Unpin + Send,
    <T as Protocol>::SinkHalf: Unpin + Send,
{
    let (stream, sink) = stack.into_split();
    let mut stack_reader = EncodedStreamReader::<T>::new(stream, T::codec());
    let mut stack_writer = DecodedSinkWriter::<T>::new(sink, T::codec());

    let (mut net_reader, mut net_writer) = outbound.into_split();

    loop {
        log::debug!("Starting transfer try_join().");

        // Copy data between the protocol stack and the network.
        // Keep track of error source so we can resume if possible.
        let (io_objects, result) = copy_spawn_try_join(
            stack_reader,
            stack_writer,
            net_reader,
            net_writer,
            None,
            Some(io::ErrorKind::UnexpectedEof.into()),
        )
        .await;

        log::debug!("Transfer try_join returned: {result:?}");

        // Treat non-network errors as legitimate.
        if !matches!(result, Err(TransferError::Network(_))) {
            return result;
        }

        // OK, we had a read or write error on the network, so drop those
        // objects but keep the stack objects so we can resume.
        (stack_reader, stack_writer, _, _) = io_objects;

        // Obtain new net objects by reconnecting and trying to resume.
        log::debug!("Reconnecting to server.");
        let Ok(reconnected_stream) = TcpStream::connect(reconnect.clone()).await else {
            return result;
        };
        (net_reader, net_writer) = reconnected_stream.into_split();

        // Guard against partial data that may have been left when the connection broke.
        stack_reader.clear();
        stack_writer.clear();

        // Clone the handle for this resume request-response cycle.
        let mut resuming = resume_handle.clone();

        // Queue a request that the server resume from the previous state.
        log::info!("Initiating request to resume stack on new connection...");
        if let Err(e) = resuming.resume_request(Some(Duration::from_secs(1))).await {
            log::info!("Failed to request a resume: {e}");
            return result;
        };

        // Wait for the server response. Use a background task, we need to get
        // back to the copy loop to actually transfer the message.
        tokio::spawn(async move {
            // The background task just logs the result. If it fails, the main
            // copy loop will also fail again.
            match resuming
                .resume_response(Some(Duration::from_secs(30)))
                .await
            {
                Ok(_new_id) => log::info!("Successfully resumed tunnel!"),
                Err(e) => log::info!("Failed to resume: {e}"),
            }
        });
    }
}
