//! Synchronization and shared state primitives.
//!
//! This module provides specialized, thread-safe wrappers and mutexes
//! designed for use within asynchronous state machines. It enables
//! shared access to I/O streams and sinks across multiple concurrent tasks.

mod mutex;
mod sink;
mod stream;

pub use mutex::{PollMutex, PollMutexGuard};
pub use sink::{ChannelCommand, ChannelSink, SharedSink};
pub use stream::{ChannelStream, SharedReplaceableStream, SharedStream};
