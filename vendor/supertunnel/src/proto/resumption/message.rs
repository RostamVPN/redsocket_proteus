use std::fmt::Debug;

use bytes::Bytes;

/// A control message used during the session resumption handshake.
///
/// Carries commands such as `Start`, `Resume`, and  `Forward`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumptionMessage {
    pub command: Command,
}

/// Commands used during the session resumption handshake process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Client sends session ID to the server for later resumption.
    Start(u64),
    /// Client requests the server to resume an existing session using the provided ID.
    Resume(u64),
    /// Server response acknowledging a successful resumption.
    ResumeOk(u64),
    /// Server response indicating that an attempted resumption failed.
    ResumeErr(u64),
    /// Forward bytes to the next layer.
    Forward(Data),
}

#[derive(Clone, Eq, PartialEq)]
pub struct Data {
    /// The application data payload bytes.
    pub chunk: Bytes,
}

impl From<Bytes> for Data {
    fn from(value: Bytes) -> Self {
        Data { chunk: value }
    }
}

impl Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Data(len: {})", self.chunk.len())
    }
}

impl From<Bytes> for Command {
    fn from(value: Bytes) -> Self {
        Command::Forward(Data::from(value))
    }
}

impl From<Command> for ResumptionMessage {
    fn from(command: Command) -> Self {
        ResumptionMessage::new(command)
    }
}

impl From<Bytes> for ResumptionMessage {
    fn from(value: Bytes) -> Self {
        ResumptionMessage::from(Command::from(value))
    }
}

impl ResumptionMessage {
    /// Creates a new `ResumptionMessage`.
    ///
    /// # Inputs
    ///
    /// * `command: Command` - The resumption command to encapsulate.
    pub fn new(command: Command) -> Self {
        Self { command }
    }
}
