use bytes::Bytes;

/// A discrete frame of data.
///
/// Includes the core payload and padding to obscure traffic patterns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramingMessage {
    pub data: Bytes,
    pub padding: Bytes,
}

impl FramingMessage {
    /// Creates a new [`FramingMessage`].
    ///
    /// # Inputs
    ///
    /// * `data: Bytes` - The primary data payload.
    /// * `padding: Bytes` - The padding bytes to obscure the true message length.
    pub fn new(data: Bytes, padding: Bytes) -> Self {
        Self { data, padding }
    }

    /// Creates a new [`FramingMessage`] with a zero-length padding field.
    ///
    /// # Inputs
    ///
    /// * `data: Bytes` - The primary data payload.
    pub fn new_data(data: Bytes) -> Self {
        Self::new(data, Bytes::new())
    }

    /// Creates a new [`FramingMessage`] with a zero-length data field.
    ///
    /// # Inputs
    ///
    /// * `padding: Bytes` - The padding bytes to obscure the true message length.
    pub fn new_padding(padding: Bytes) -> Self {
        Self::new(Bytes::new(), padding)
    }
}
