use std::fmt::Debug;

use bytes::Bytes;

use crate::net::NetworkTarget;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingMessage {
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Client requests the server to open a connection and assigns a session
    /// id. The server will hold a successful connection in a pending state
    /// until receiving a subsequent Add command from the client.
    Connect((u64, NetworkTarget)),
    /// Server connection succeeded. The server is expecting an Add command and
    /// then forwarded payloads for this session id.
    ConnectOk(u64),
    /// A server connection to the requested target failed.
    ConnectErr(u64),
    /// The client notifies the server the a connected session should be moved
    /// from its pending state into its input/output pools.
    Add(u64),
    /// The client notifies the server the a connected session should be removed
    /// from its input/output pools.
    Remove(u64),
    /// Peers forwarding encapsulated stream bytes to each other.
    Forward(Data),
    /// On sink end, requests the peer to shut down its read side. This means
    /// they stop reading and then sending us payloads that we need to receive
    /// and then write.
    ShutRead,
    /// On stream end (EOF), requests the peer to shut down its write side. This
    /// means we will stop reading and then sending them payloads that they need
    /// to receive and then write.
    ShutWrite,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Data {
    /// The application data payload bytes.
    pub chunk: Bytes,
}

impl From<Bytes> for Data {
    fn from(data: Bytes) -> Self {
        Data { chunk: data }
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

impl From<Command> for RoutingMessage {
    fn from(command: Command) -> Self {
        RoutingMessage::new(command)
    }
}

impl From<Bytes> for RoutingMessage {
    fn from(value: Bytes) -> Self {
        RoutingMessage::from(Command::from(value))
    }
}

impl RoutingMessage {
    pub fn new(command: Command) -> Self {
        Self { command }
    }
}
