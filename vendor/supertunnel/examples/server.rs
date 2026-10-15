//! SuperTunnel Server Example.
//!
//! This module provides the server-side implementation, accepting incoming
//! SuperTunnel connections and demultiplexing them to their intended network targets.

use std::io;

use clap::Parser;
use supertunnel::io::{CopyError, TransferError, copy_spawn_try_join};
use supertunnel::proto::*;
use supertunnel::util::{DecodedSinkWriter, EncodedStreamReader};
use supertunnel::{FrameSize, Protocol};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "A server-side proxy forwarding supertunnel client connections to internet destinations"
)]
struct Args {
    /// Address to listen for supertunnel connections
    #[arg(short, long, value_name = "ADDR:PORT", default_value = "0.0.0.0:8080")]
    listen: String,
}

/// Initializes the server, parses arguments, and starts listening for SuperTunnel connections.
///
/// This function performs the following steps:
/// 1. Initializes the logger.
/// 2. Parses command-line arguments for the listening address.
/// 3. Binds a `TcpListener` to the specified address.
/// 4. Creates a `ResumptionMap` to store state for resumable client sessions.
/// 5. Enters an infinite loop to accept new incoming connections, spawning a new `handle_connection`
///    task for each one.
///
/// # Returns
///
/// * `io::Result<()>` - Returns an error if the listener fails to bind to the specified address,
///   or we fail to accept a connection from the listener.
#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Start listener for incoming supertunnel connections.
    let listener = TcpListener::bind(&args.listen).await?;
    log::info!("Listening on {}", args.listen);

    // Keep state for session resumption.
    let resume_map = ResumptionMap::new();

    loop {
        // Each incoming server connection is a new tunnel.
        let (inbound, _) = listener.accept().await?; // Exit on error.
        let map = resume_map.clone();
        tokio::spawn(handle_connection(inbound, map));
    }
}

type MapInner = Reliability<RoutingServer<TcpPayload, TcpPayloadFactory>>;

// We multiplex multiple streams over a single tunnel.
/// Handles a new incoming connection from a SuperTunnel client.
///
/// Each incoming connection is treated as a distinct tunnel. This function sets up the
/// server-side protocol stack for the connection, including `Framing`, `Resumption`,
/// `Reliability`, and `Routing`. The state of the connection is stored in the shared
/// `ResumptionMap` to allow clients to resume their sessions after a disconnect.
///
/// # Inputs
///
/// * `inbound: TcpStream` - The TCP stream from the connecting client.
/// * `map: ResumptionMap<MapInner>` - A cloned handle to the shared map that stores session states for resumption.
async fn handle_connection(inbound: TcpStream, map: ResumptionMap<MapInner>) {
    log::info!(
        "New incoming connection {:?} -> {:?}",
        inbound.peer_addr(),
        inbound.local_addr()
    );

    // Compute the max payload chunk size for our stack.
    let stack_mss = PayloadCodec::mss(RoutingCodec::mss(ReliabilityCodec::mss(
        ResumptionCodec::mss(FramingCodec::mss(FramingCodec::mtu())),
    )));

    // The tunnel server connects new applications using tcp.
    let connector = TcpPayloadFactory::new(stack_mss);
    let tunnel = RoutingServer::new(connector).await;
    let resume = ResumptionServer::new_with(Reliability::new(tunnel), map);
    let stack = Framing::new(resume);

    // Copy everything between the network and our stack. If there is an error
    // during the transfer, the server state will persist in the map for a while
    // so the client can try to resume.
    let result = transfer(stack, inbound).await;
    log::info!("Transfer task completed: {result:?}");
}

/// Manages the bidirectional data transfer between the protocol stack and the network stream.
///
/// This function sets up and runs a `transfer_try_join` operation, which copies data
/// between the protocol stack and the underlying TCP connection. It runs until an error
/// or EOF is encountered.
///
/// # Inputs
///
/// * `stack: T` - The server-side protocol stack.
/// * `net: TcpStream` - The TCP stream connected to the client.
///
/// # Returns
///
/// * `Result<(u64, u64), TransferError>` - On success or failure, returns the result of the
///   `transfer_try_join` operation, containing bytes transferred or a `TransferError`.
async fn transfer<T>(stack: T, net: TcpStream) -> Result<(usize, usize), TransferError<CopyError>>
where
    T: Protocol + Send + 'static,
    <T as Protocol>::Codec: Send,
    <T as Protocol>::Message: Send,
    <T as Protocol>::StreamHalf: Unpin + Send,
    <T as Protocol>::SinkHalf: Unpin + Send,
{
    let (stream, sink) = stack.into_split();
    let stack_reader = EncodedStreamReader::<T>::new(stream, T::codec());
    let stack_writer = DecodedSinkWriter::<T>::new(sink, T::codec());

    let (net_reader, net_writer) = net.into_split();

    let (_, result) = copy_spawn_try_join(
        stack_reader,
        stack_writer,
        net_reader,
        net_writer,
        None,
        Some(io::ErrorKind::UnexpectedEof.into()),
    )
    .await;
    result
}
