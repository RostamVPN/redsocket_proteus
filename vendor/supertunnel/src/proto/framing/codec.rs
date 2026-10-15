use std::io::{self, Cursor};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use xxhash_rust::xxh3::xxh3_64;

use crate::FrameSize;
use crate::proto::framing::FramingMessage;

/// Encodes and decodes `FramingMessage` structures, handling length prefixes.
#[derive(Clone, Debug, Default)]
pub struct FramingCodec;

impl Encoder<FramingMessage> for FramingCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: FramingMessage, dst: &mut BytesMut) -> io::Result<()> {
        // If we return early, we want the dst buffer to be unmodified.
        // Make sure we can encode the payload len in our len field.
        let payload_len = msg.data.len() + msg.padding.len();
        if payload_len > Self::mss(Self::mtu()) {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }

        // Success, start adding encoded bytes in dst after current position.
        // See the `max_header_len()` comment for layout.
        let total_len = Self::max_header_len() + payload_len;
        dst.reserve(total_len);

        let total_len = u16::try_from(total_len).unwrap();
        let data_len = u16::try_from(msg.data.len()).unwrap();

        let len_pos = dst.len();
        let payload_pos = len_pos + 12;

        dst.put_u16(total_len);
        dst.put_u16(data_len);
        dst.put_u64(xxh3_64(&dst[len_pos..len_pos + 4]));

        // extend_from_slice() takes a ref, so it must copy.
        // dst.extend_from_slice(&msg.payload);
        // put() consumes the data, so may be able to zero-copy.
        dst.put(msg.data);
        dst.put(msg.padding);
        dst.put_u64(xxh3_64(&dst[payload_pos..payload_pos + payload_len]));

        Ok(())
    }
}

impl Decoder for FramingCodec {
    type Item = FramingMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        // If we return Ok(None), we want the src buffer to be unmodified.
        let mut reader = Cursor::new(src as &BytesMut);

        // We first need the total len (2 bytes), data len (2 bytes) and len_crc (8 bytes).
        if reader.remaining() < 12 {
            return Ok(None);
        }

        // Compute crc of both length fields.
        let len_crc_dst = xxh3_64(&src[0..4]);

        let total_len = reader.get_u16();
        let data_len = reader.get_u16();
        let len_crc_src = reader.get_u64();

        // Ensure the len checksum matches.
        if len_crc_src != len_crc_dst {
            log::debug!("Framing codec: invalid length crc");
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        // The lens are valid.
        let total_len = total_len as usize;
        let data_len = data_len as usize;
        let padding_len = total_len - Self::max_header_len() - data_len;

        // Validate len value is in the correct range. We expect at least 20 bytes
        // (4 for lens, 8 for len_crc, 8 for data_crc) and at most u16::MAX.
        if total_len < Self::max_header_len() {
            log::debug!("Framing codec: invalid length value");
            return Err(std::io::ErrorKind::InvalidInput.into());
        }

        // No need to decode the rest if we don't have everything yet.
        if src.len() < total_len {
            return Ok(None);
        }

        // OK, we have the entire message. Let's zero-copy it from src.
        let mut msg_bytes = src.split_to(total_len);

        // Cut the lens and len_crc from the front, we already processed those.
        msg_bytes.advance(12);

        // Compute crc of both data fields.
        let payload_crc_dst = xxh3_64(&msg_bytes[0..data_len + padding_len]);

        // Get the remaining data, padding, and crc.
        let data = msg_bytes.split_to(data_len).freeze();
        let padding = msg_bytes.split_to(padding_len).freeze();
        let payload_crc_src = msg_bytes.get_u64();

        // Check the data crc before processing the data further.
        if payload_crc_src != payload_crc_dst {
            log::debug!("Framing codec: invalid payload crc");
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        // Success, now we know the data is valid.
        Ok(Some(FramingMessage::new(data, padding)))
    }
}

impl FramingCodec {
    /// Creates a new [`FramingCodec`].
    pub fn new() -> Self {
        Self
    }

    /// The maximum number of bytes of overhead added by the codec to any
    /// message carrying payload bytes. This helps us calculate how many payload
    /// bytes to add to each message to enforce an mtu (i.e., `u16::MAX`).
    ///
    /// The codec adds 20 bytes of overhead:
    /// - total length (2 bytes)
    /// - data length (2 bytes)
    /// - lengths crc (8 bytes)
    /// - data (at most `mss()` bytes)
    /// - padding (at most `mss()-data.len()` bytes)
    /// - data+padding crc (8 bytes)
    const fn max_header_len() -> usize {
        // This *must* be kept synchronized with our encoding scheme.
        2 + 2 + 8 + 8
    }
}

impl FrameSize for FramingCodec {
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

    fn assert_encode_decode(msg: FramingMessage) {
        let mut buf = BytesMut::new();

        let encode_result = FramingCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_ok());

        let decode_result = FramingCodec.decode(&mut buf);
        assert!(matches!(decode_result, Ok(Some(_))));

        let encoded_decoded_msg = decode_result.unwrap().unwrap();
        assert_eq!(msg, encoded_decoded_msg);
    }

    fn message(data: Bytes, padding: Option<Bytes>) -> FramingMessage {
        FramingMessage::new(data, padding.unwrap_or_default())
    }

    fn payload(len: usize) -> Bytes {
        TestPayload::bytes(len)
    }

    fn padding(len: usize) -> Bytes {
        BytesMut::zeroed(len).freeze()
    }

    fn test_valid_command(data: Bytes) {
        assert_encode_decode(message(data, None));
    }

    #[test]
    fn valid_bytes() {
        test_valid_command(Bytes::from("This is the payload."));
    }

    #[test]
    fn valid_payload_length() {
        // Max supported payload length.
        let max_len = FramingCodec::mss(FramingCodec::mtu());
        for n in [0, 1, 2, 10, max_len - 1, max_len] {
            test_valid_command(payload(n));
        }
    }

    #[test]
    fn valid_padding_length() {
        // Max supported payload length.
        let max_len = FramingCodec::mss(FramingCodec::mtu());
        for n in [0, 1, 2, 10, max_len - 1, max_len] {
            assert_encode_decode(message(payload(max_len - n), Some(padding(n))));
        }
    }

    #[test]
    fn invalid_payload_length() {
        // Max supported payload length.
        let max_len = FramingCodec::mss(FramingCodec::mtu());

        // This payload is larger than supported.
        let bytes = payload(max_len + 1);
        let msg = message(bytes, None);

        // Should get encode error.
        let mut buf = BytesMut::new();
        let encode_result = FramingCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_err());
    }

    #[test]
    fn invalid_padding_length() {
        // Max supported payload length.
        let max_len = FramingCodec::mss(FramingCodec::mtu());

        // This payload is larger than supported.
        for n in [0, 1, 2, 10, max_len - 1, max_len] {
            let msg = message(payload(max_len - n), Some(padding(n + 1)));
            // Should get encode error.
            let mut buf = BytesMut::new();
            let encode_result = FramingCodec.encode(msg.clone(), &mut buf);
            assert!(encode_result.is_err());
        }
    }

    fn test_invalid(data: Bytes, padding: Option<Bytes>, byte_to_stomp: usize) {
        let mut buf = BytesMut::new();

        let msg = message(data, padding);
        assert!(FramingCodec.encode(msg, &mut buf).is_ok());

        buf[byte_to_stomp] = 99; // stomp a byte

        assert!(FramingCodec.decode(&mut buf).is_err());
    }

    #[test]
    fn invalid_payload_bytes() {
        // Max supported payload length.
        let max_len = FramingCodec::mss(FramingCodec::mtu());

        // If we stomp a payload byte, the checksum should fail.
        // We are using `padding()` here to get zeros, because the
        // stomped byte will become nonzero.
        test_invalid(padding(max_len), None, 10_000);
        test_invalid(padding(0), Some(padding(max_len)), 10_000);
        test_invalid(padding(50), Some(padding(50)), 49);
        test_invalid(padding(50), Some(padding(50)), 50);
    }

    #[test]
    fn valid_checksum() {
        let max_len = FramingCodec::mss(FramingCodec::mtu());
        let bytes = payload(max_len);
        let checksum_src = xxh3_64(&bytes);
        let checksum_dst = xxh3_64(&bytes);
        assert_eq!(checksum_src, checksum_dst);
    }

    #[test]
    fn invalid_checksum() {
        let max_len = FramingCodec::mss(FramingCodec::mtu());
        let bytes = payload(max_len);
        let mut buf = BytesMut::from(bytes);
        let n = buf.len();

        buf[n - 1] = 1;
        let checksum_src = xxh3_64(&buf);

        buf[n - 1] = 0;
        let checksum_dst = xxh3_64(&buf);

        assert_ne!(checksum_src, checksum_dst);
    }
}
