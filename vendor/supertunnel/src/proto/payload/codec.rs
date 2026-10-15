use std::io::{self, Cursor};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::FrameSize;
use crate::proto::payload::PayloadMessage;

/// Encodes and decodes `PayloadMessage` objects to and from raw byte buffers.
#[derive(Clone, Debug, Default)]
pub struct PayloadCodec;

impl Encoder<PayloadMessage> for PayloadCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: PayloadMessage, dst: &mut BytesMut) -> io::Result<()> {
        if msg.data.len() > Self::mss(Self::mtu()) {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }

        dst.reserve(Self::max_header_len() + msg.data.len());

        dst.put_u64(msg.id);
        dst.put_u16(u16::try_from(msg.data.len()).unwrap());
        dst.extend_from_slice(&msg.data);

        Ok(())
    }
}

impl Decoder for PayloadCodec {
    type Item = PayloadMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        // If we return Ok(None), we want the src buffer to be unmodified.
        let mut reader = Cursor::new(src as &BytesMut);

        if reader.remaining() >= 10 {
            let id = reader.get_u64();
            let len = reader.get_u16() as usize;
            if reader.remaining() >= len {
                // We have everything, skip up to the payload.
                src.advance(10);
                // Zero-copy from the src buf.
                let payload = src.split_to(len).freeze();
                Ok(Some(PayloadMessage::new(id, payload)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

impl PayloadCodec {
    /// Creates a new `PayloadCodec`.
    pub fn new() -> Self {
        Self
    }

    /// The maximum number of bytes of overhead added by the codec to any
    /// message carrying payload bytes. This helps us calculate how many payload
    /// bytes to add to each message to enforce an mtu.
    const fn max_header_len() -> usize {
        // This *must* be kept synchronized with our encoding scheme.
        // For session id (8) and length (2) fields.
        8 + 2
    }
}

impl FrameSize for PayloadCodec {
    /// The maximum number of bytes that can be transmitted for a single
    /// message, based on the current encoding scheme.
    fn mtu() -> usize {
        u16::MAX as usize // 2^16 = 65536 bytes
    }

    /// The maximum supported length of a payload that ensures the full message
    /// length can be encoded to fit within `target_mtu`.
    fn mss(target_mtu: usize) -> usize {
        let mtu = target_mtu.min(Self::mtu());
        mtu.checked_sub(Self::max_header_len()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::test::TestPayload;

    fn assert_encode_decode(msg: PayloadMessage) {
        let mut buf = BytesMut::new();

        let encode_result = PayloadCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_ok());

        let decode_result = PayloadCodec.decode(&mut buf);
        assert!(matches!(decode_result, Ok(Some(_))));

        let encoded_decoded_msg = decode_result.unwrap().unwrap();
        assert_eq!(msg, encoded_decoded_msg);
    }

    fn message(payload: Bytes) -> PayloadMessage {
        PayloadMessage::new(1, payload)
    }

    fn gen_payload(len: usize) -> Bytes {
        // BytesMut::zeroed(len).freeze()
        TestPayload::bytes(len)
    }

    fn test_valid_command(payload: Bytes) {
        assert_encode_decode(message(payload));
    }

    #[test]
    fn valid_bytes() {
        test_valid_command(Bytes::from("This is the payload."));
    }

    #[test]
    fn invalid_payload_length() {
        // Max supported payload length.
        let max_len = PayloadCodec::mss(PayloadCodec::mtu());
        let bytes = gen_payload(max_len);
        test_valid_command(bytes);

        // This payload is larger than supported.
        let bytes = gen_payload(max_len + 1);
        let msg = message(bytes);

        // Should get encode error.
        let mut buf = BytesMut::new();
        let encode_result = PayloadCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_err());
    }
}
