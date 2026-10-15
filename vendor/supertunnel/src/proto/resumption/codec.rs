use std::io::{self, Cursor};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::FrameSize;
use crate::proto::resumption::{Command, ResumptionMessage};

/// Encodes and decodes `ResumptionMessage` objects.
#[derive(Clone, Debug, Default)]
pub struct ResumptionCodec;

impl Encoder<ResumptionMessage> for ResumptionCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ResumptionMessage, dst: &mut BytesMut) -> io::Result<()> {
        // If we return early, we want the dst buffer to be unmodified.
        // Make sure we will be able to encode the payload len.
        let payload_len = match &msg.command {
            Command::Forward(payload) => payload.chunk.len(),
            _ => 0,
        };

        if payload_len > Self::mss(Self::mtu()) {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }

        // OK, we think we can successfully encode the msg now, so start
        // encoding directly into the dst buffer.

        let len = Self::max_header_len() + payload_len;
        dst.reserve(len);

        dst.put_u8(Self::command_to_type(&msg.command));

        match msg.command {
            Command::Start(tid) => dst.put_u64(tid),
            Command::Resume(tid) => dst.put_u64(tid),
            Command::ResumeOk(tid) => dst.put_u64(tid),
            Command::ResumeErr(tid) => dst.put_u64(tid),
            Command::Forward(payload) => {
                dst.put_u16(u16::try_from(payload.chunk.len()).unwrap());
                // extend_from_slice() takes a ref, so it must copy.
                // dst.extend_from_slice(&payload.data);
                // put() consumes the data, so may be able to zero-copy.
                dst.put(payload.chunk);
            }
        }

        Ok(())
    }
}

impl Decoder for ResumptionCodec {
    type Item = ResumptionMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        // If we return Ok(None), we want the src buffer to be unmodified.
        let mut reader = Cursor::new(src as &BytesMut);

        // We first have the command type.
        if reader.remaining() < 1 {
            return Ok(None); // Need more bytes.
        }

        // If the command type is invalid, this will return an error.
        // Note, any subfields will be set as empty for now.
        // let mut command = Self::type_to_command(reader.get_u8())?;

        // Decode the subfields.
        let maybe_command = match reader.get_u8() {
            0 => (reader.remaining() >= 8).then(|| Command::Start(reader.get_u64())),
            1 => (reader.remaining() >= 8).then(|| Command::Resume(reader.get_u64())),
            2 => (reader.remaining() >= 8).then(|| Command::ResumeOk(reader.get_u64())),
            3 => (reader.remaining() >= 8).then(|| Command::ResumeErr(reader.get_u64())),
            4 => {
                // Special case for payload, so we can split src and avoid copying.
                if reader.remaining() < 2 {
                    return Ok(None); // Need more bytes.
                }

                let payload_len = reader.get_u16() as usize;
                if reader.remaining() < payload_len {
                    return Ok(None); // Need more bytes.
                }

                src.advance(reader.position() as usize);
                let data = src.split_to(payload_len).freeze();
                return Ok(Some(ResumptionMessage::from(data)));
            }
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };

        if let Some(command) = maybe_command {
            src.advance(reader.position() as usize);
            Ok(Some(ResumptionMessage::from(command)))
        } else {
            Ok(None) // Need more bytes.
        }
    }
}

impl ResumptionCodec {
    /// Creates a new `ResumptionCodec`.
    pub fn new() -> Self {
        Self
    }

    /// The maximum number of bytes of overhead added by the codec to any
    /// message carrying payload bytes. This helps us calculate how many payload
    /// bytes to add to each message to enforce an mtu.
    const fn max_header_len() -> usize {
        // This *must* be kept synchronized with our encoding scheme.
        // cmd (1) + payload_len (2)
        1 + 2
    }

    fn command_to_type(command: &Command) -> u8 {
        match command {
            Command::Start(_) => 0,
            Command::Resume(_) => 1,
            Command::ResumeOk(_) => 2,
            Command::ResumeErr(_) => 3,
            Command::Forward(_) => 4,
        }
    }
}

impl FrameSize for ResumptionCodec {
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

    fn assert_encode_decode(msg: ResumptionMessage) {
        let mut buf = BytesMut::new();

        let encode_result = ResumptionCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_ok());

        let decode_result = ResumptionCodec.decode(&mut buf);
        assert!(matches!(decode_result, Ok(Some(_))));

        let encoded_decoded_msg = decode_result.unwrap().unwrap();
        assert_eq!(msg, encoded_decoded_msg);
    }

    fn gen_payload(len: usize) -> Bytes {
        // BytesMut::zeroed(len).freeze()
        TestPayload::bytes(len)
    }

    fn test_valid_command(command: Command) {
        assert_encode_decode(ResumptionMessage::from(command));
    }

    #[test]
    fn valid_start() {
        test_valid_command(Command::Start(123));
    }

    #[test]
    fn valid_resume() {
        test_valid_command(Command::Resume(123));
    }

    #[test]
    fn valid_resumeok() {
        test_valid_command(Command::ResumeOk(123));
    }

    #[test]
    fn valid_resumeerr() {
        test_valid_command(Command::ResumeErr(123));
    }

    #[test]
    fn valid_forward() {
        test_valid_command(Command::from(Bytes::from("This is the payload.")));
    }

    #[test]
    fn invalid_payload_length() {
        // Max supported payload length.
        let max_len = ResumptionCodec::mss(ResumptionCodec::mtu());
        let bytes = gen_payload(max_len);
        test_valid_command(Command::from(bytes));

        // This payload is larger than supported.
        let bytes = gen_payload(max_len + 1);
        let msg = ResumptionMessage::from(bytes);

        // Should get encode error.
        let mut buf = BytesMut::new();
        let encode_result = ResumptionCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_err());
    }

    fn test_invalid(command: Command, byte_to_stomp: usize) {
        let mut buf = BytesMut::new();

        let msg = ResumptionMessage::from(command);
        assert!(ResumptionCodec.encode(msg, &mut buf).is_ok());

        buf[byte_to_stomp] = 99; // stomp a byte

        assert!(ResumptionCodec.decode(&mut buf).is_err());
    }

    #[test]
    fn invalid_command_kind() {
        // The command kind is the 1st byte (index 0).
        test_invalid(Command::Start(111), 0);
    }
}
