use bytes::Bytes;

use crate::Identify;

#[derive(Clone, Debug, Eq, PartialEq)]
/// A chunk of application data encapsulated for transport.
///
/// Associates a segment of raw bytes with a specific multiplexed session ID.
pub struct PayloadMessage {
    pub id: u64,
    pub data: Bytes,
}

impl PayloadMessage {
    /// Creates a new `PayloadMessage`.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The session identifier for this payload.
    /// * `data: Bytes` - The raw payload data.
    pub fn new(id: u64, data: Bytes) -> Self {
        Self { id, data }
    }
}

impl Identify for PayloadMessage {
    fn id(&self) -> u64 {
        self.id
    }
}
