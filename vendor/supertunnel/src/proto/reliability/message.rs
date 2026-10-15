use std::cmp::Ordering;
use std::fmt::Debug;

use bytes::Bytes;

pub type DataCursor = u64;

/// A protocol message for ensuring reliable data delivery.
///
/// Contains sequence numbers, acknowledgment numbers, and control commands (e.g., Forward, Rewind, Acknowledge).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliabilityMessage {
    /// Similar to TCP sequence number.
    pub write: DataCursor,
    /// Similar to TCP acknowledgment number.
    pub read: DataCursor,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Forward(Data),
    Rewind,
    RewindAck,
    Acknowledge,
    Shut,
    ShutAck1,
    ShutAck2,
    Reset,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Data {
    /// The encapsulated data bytes chunk.
    pub chunk: Bytes,
}

impl From<Bytes> for Data {
    fn from(value: Bytes) -> Self {
        Data { chunk: value }
    }
}

impl Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Payload(len: {})", self.chunk.len())
    }
}

impl Ord for ReliabilityMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        self.write.cmp(&other.write)
    }
}

impl PartialOrd for ReliabilityMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ReliabilityMessage {
    /// Creates a new `ReliabilityMessage`.
    ///
    /// # Inputs
    ///
    /// * `write: DataCursor` - The sequence number for this message.
    /// * `read: DataCursor` - The acknowledgment number for data received from the peer.
    /// * `command: Command` - The command to be executed (e.g., `Forward`, `Rewind`).
    pub fn new(write: DataCursor, read: DataCursor, command: Command) -> Self {
        Self {
            write,
            read,
            command,
        }
    }
}

#[cfg(test)]
impl ReliabilityMessage {
    pub fn forward(write: DataCursor, read: DataCursor, data: Bytes) -> Self {
        Self::new(write, read, Command::Forward(data.into()))
    }

    pub fn rewind(write: DataCursor, read: DataCursor) -> Self {
        Self::new(write, read, Command::Rewind)
    }

    pub fn rewind_ack(write: DataCursor, read: DataCursor) -> Self {
        Self::new(write, read, Command::RewindAck)
    }

    pub fn acknowledge(write: DataCursor, read: DataCursor) -> Self {
        Self::new(write, read, Command::Acknowledge)
    }

    pub fn shut(write: DataCursor, read: DataCursor) -> Self {
        Self::new(write, read, Command::Shut)
    }

    pub fn shut_ack1(write: DataCursor, read: DataCursor) -> Self {
        Self::new(write, read, Command::ShutAck1)
    }

    pub fn shut_ack2(write: DataCursor, read: DataCursor) -> Self {
        Self::new(write, read, Command::ShutAck1)
    }

    pub fn reset(write: DataCursor, read: DataCursor) -> Self {
        Self {
            write,
            read,
            command: Command::Reset,
        }
    }
}

#[cfg(test)]
mod tests {}
