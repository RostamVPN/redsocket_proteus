//! # SuperTunnel
//!
//! A modular, asynchronous networking framework designed for building stateful TCP
//! tunnels that make network disruptions transparent to application streams.

//! Super Tunnel enables you to route application connections through a proxy server
//! while adding resiliency features that enable your tunnels to survive network
//! disconnections. Specifically, you can build resilient tunnels by stacking Super
//! Tunnel's framing, reliability, session resumption, and stream multiplexing
//! layers with your own security protocol implementation.
//!
//! SuperTunnel is designed to be composed with a security protocol that provides
//! security features such as encryption and resistance to network traffic analysis.
//! SuperTunnel itself does NOT provide security; it provides stateful session
//! resumption and stream multiplexing features while allowing you to focus on
//! developing strong security protocols.
//!
//! ## For Protocol Integrators
//!
//! If your goal is to integrate SuperTunnel into your existing applications
//! without writing custom protocol logic, you can leverage the pre-built layers
//! provided in the [`proto`] module.
//!
//! The standard SuperTunnel stack generally consists of:
//! * **Payload ([`proto::payload`])**: Chunks raw application data into
//!   discrete messages.
//! * **Routing ([`proto::routing`])**: Multiplexes multiple distinct logical
//!   sessions over a single tunnel.
//! * **Reliability ([`proto::reliability`])**: Guarantees ordered delivery and
//!   handles retransmissions.
//! * **Resumption ([`proto::resumption`])**: Manages session identifiers and
//!   facilitates seamless reconnection.
//! * **Framing ([`proto::framing`])**: Encapsulates messages into a continuous
//!   byte stream for transport.
//!
//! **Getting Started:** The best way to understand how to wire these layers
//! together is to review the internal source code of the [reference
//! implementation examples]:
//! * See `examples/client.rs` for establishing a multiplexed outbound tunnel.
//! * See `examples/server.rs` for accepting, demultiplexing, and routing
//!   inbound tunnel connections.
//!
//! ## For Protocol Implementors
//!
//! SuperTunnel is designed to be extensible. You can write your own protocol
//! layers by implementing the [`Protocol`] trait and injecting them anywhere in
//! a SuperTunnel stack.
//!
//! #### The [`Protocol`] Trait
//!
//! The [`Protocol`] trait represents a single transformation layer. It
//! typically takes an underlying asynchronous stream and sink (representing the
//! layer above it) and returns a new upgraded stream and sink (representing
//! this layer's interface to the layer below).
//!
//! #### Building Custom Protocols
//!
//! When writing a new [`Protocol`] implementation, you will often need to
//! manage concurrent state, encode/decode messages, or handle multiple inner
//! streams. The library provides utilities to make this easier:
//!
//! * **The [`util`] Module**: Contains abstractions for I/O transformation.
//!   * Use [`EncodedStream`](crate::util::EncodedStream) and
//!     [`DecodedSink`](crate::util::DecodedSink) to bridge between raw bytes
//!     and your typed Rust structs using a Codec.
//!   * Use [`MuxedEncodedStream`](crate::util::MuxedEncodedStream) and
//!     [`DemuxedDecodedSink`](crate::util::DemuxedDecodedSink) if your protocol
//!     needs to funnel multiple logical data flows into a single transport
//!     layer.
//!
//! * **The [`sync`] Module**: Contains synchronization primitives for
//!   asynchronous state machines where standard locks are unsuitable.
//!   * Use [`PollMutex`](crate::sync::PollMutex) to safely share state between
//!     the split read and write halves of your protocol. It provides a
//!     poll-based lock that integrates cleanly with `Stream` and `Sink`
//!     implementations.
//!   * Use [`SharedStream`](crate::sync::SharedStream) or
//!     [`SharedSink`](crate::sync::SharedSink) when multiple asynchronous tasks
//!     need safe, concurrent access to a single underlying I/O resource.
//!
//! **Getting Started:** To see these utilities applied in concrete
//! implementations, you can study the internal source code of the [reference
//! implementation protocols] provided in this library:
//!
//! * **State Sharing**: See [`proto::reliability`]. Its `SharedReliabilityState`
//!   demonstrates how to use [`PollMutex`](sync::PollMutex) to safely share
//!   sequence numbers and acknowledgment tracking between the concurrent read
//!   and write halves of the reliability layer.
//! * **Multiplexing**: See [`proto::routing`]. Both the client and server routing
//!   implementations heavily rely on
//!   [`MuxedEncodedStream`](util::MuxedEncodedStream) and
//!   [`DemuxedDecodedSink`](util::DemuxedDecodedSink) to multiplex numerous
//!   dynamic client sessions into a single underlying transport stream.
//! * **Codec Bridging**: See [`proto::framing`]. It contains a straightforward
//!   example of using [`EncodedStream`](util::EncodedStream) and
//!   [`DecodedSink`](util::DecodedSink) to apply a `Codec` directly to raw byte
//!   streams.
//!
//! [reference implementation examples]: <https://github.com/unblockable/supertunnel/examples>
//! [reference implementation protocols]: <https://github.com/unblockable/supertunnel/src/proto>

use futures::{Sink, Stream};
use tokio_util::codec::{Decoder, Encoder};

use crate::net::NetworkTarget;

pub mod io;
pub mod net;
pub mod proto;
pub mod sync;
pub mod util;

#[cfg(test)]
pub mod test;

/// Trait defining the size constraints for the framing protocol.
///
/// Dictates the maximum allowable payload sizes to ensure frames do not exceed
/// buffer capacities or network MTUs.
pub trait FrameSize {
    /// The maximum number of bytes that can be transmitted for a single
    /// message. This usually depends on the size of the length field uses in
    /// the message encoding scheme.
    fn mtu() -> usize;

    /// The maximum supported length of a payload that ensures the full message
    /// length can still be encoded to fit within the `target_mtu`.
    fn mss(target_mtu: usize) -> usize;
}

/// The core trait defining a discrete layer in the protocol stack.
///
/// Implementors of this trait wrap an underlying stream/sink and provide
/// an upgraded interface (e.g., adding encryption, framing, or reliability).
pub trait Protocol
where
    // All returned errors can be converted into io::Errors.
    <Self::SinkHalf as Sink<Self::Message>>::Error: Into<std::io::Error>,
    <Self::Codec as Encoder<Self::Message>>::Error: Into<std::io::Error>,
    <Self::Codec as Decoder>::Error: Into<std::io::Error>,
{
    /// The concrete type of message understood by this protocol.
    type Message;
    /// The stream half produces instances of this protocol's message type.
    type StreamHalf: Stream<Item = Self::Message>;
    /// The sink half consumes instances of this protocol's message type.
    type SinkHalf: Sink<Self::Message>;
    /// The codec must be able to encode, decode, and define framing boundaries
    /// for this protocol's message type.
    type Codec: Encoder<Self::Message> + Decoder<Item = Self::Message> + FrameSize;

    /// Split the protocol into two parts that can be used to concurrently
    /// produce and consume messages from other protocols.
    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf);

    /// Create a Codec that can be used to encode and decode messages understood
    /// by this protocol.
    fn codec() -> Self::Codec;
}

/// Trait for objects that possess a unique identifier.
///
/// Used extensively by multiplexers and demultiplexers to route packets to the correct session.
pub trait Identify {
    /// Returns a value that can be used to uniquely identify this object.
    fn id(&self) -> u64;
}

/// Trait for establishing outbound network connections.
///
/// Implemented by the server's routing layer to instantiate new outbound streams
/// based on client routing commands. This is a protocol factory: if the connection
/// succeeds, it will return a new instance of an object that implements the
/// protocol defined by the `Item` type.`
pub trait SessionConnector
where
    <Self::Item as Protocol>::Message: Identify,
{
    /// The `Protocol` instance that will be created upon a successful connection.
    type Item: Protocol;

    /// Attempts to connect to the given network target, returning the given id
    /// and connect result upon completion.
    ///
    /// Note: implementations will likely want to clone all data from self so
    /// that self is not directly referenced inside the returned future.
    fn connect(
        &self,
        id: u64,
        target: NetworkTarget,
    ) -> impl Future<Output = (u64, std::io::Result<Self::Item>)> + Send + 'static;
}
