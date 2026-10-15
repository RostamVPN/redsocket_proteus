//! Tools and adapters for managing streams and sinks and for stacking
//! multiple [`crate::Protocol`] layers.
//!
//! Contains foundational tools for multiplexing/demultiplexing and encoding/decoding,
//! streams and sinks, and for converting between a stream/sink and a read/write interface.
mod demux;
mod mux;
mod read;
mod sink;
mod stream;
mod write;

pub use demux::DemuxedDecodedSink;
pub use mux::{EndMethod, MuxedEncodedStream};
pub use read::EncodedStreamReader;
pub use sink::DecodedSink;
pub use stream::EncodedStream;
pub use write::DecodedSinkWriter;
