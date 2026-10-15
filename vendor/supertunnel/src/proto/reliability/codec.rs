use std::io::{self, Cursor};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::FrameSize;
use crate::proto::reliability::{Command, Data, ReliabilityMessage};

/// Encodes and decodes `ReliabilityMessage` objects for wire transport.
#[derive(Clone, Debug, Default)]
pub struct ReliabilityCodec;

impl Encoder<ReliabilityMessage> for ReliabilityCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ReliabilityMessage, dst: &mut BytesMut) -> io::Result<()> {
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

        dst.put_u64(msg.write);
        dst.put_u64(msg.read);
        dst.put_u8(Self::command_to_type(&msg.command));

        if let Command::Forward(payload) = msg.command {
            dst.put_u16(u16::try_from(payload.chunk.len()).unwrap());
            // extend_from_slice() takes a ref, so it must copy.
            // dst.extend_from_slice(&payload.data);
            // put() consumes the data, so may be able to zero-copy.
            dst.put(payload.chunk);
        }

        Ok(())
    }
}

impl Decoder for ReliabilityCodec {
    type Item = ReliabilityMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        // If we return Ok(None), we want the src buffer to be unmodified.
        let mut reader = Cursor::new(src as &BytesMut);

        // We first have the two cursors and the command type.
        if reader.remaining() < 17 {
            return Ok(None); // Need more bytes.
        }

        let write = reader.get_u64();
        let read = reader.get_u64();

        // If the command type is invalid, this will return an error.
        // Note, if there is a payload field, it was set as empty for now.
        let mut command = Self::type_to_command(reader.get_u8())?;

        // Check for payload to ensure src has enough available bytes.
        let payload_len = match &command {
            Command::Forward(_) => {
                if reader.remaining() < 2 {
                    return Ok(None); // Need more bytes.
                }
                reader.get_u16() as usize
            }
            _ => 0,
        };

        if reader.remaining() < payload_len {
            return Ok(None); // Need more bytes.
        }

        // All needed bytes are available, marked those already processed as consumed.
        let num_consumed = reader.position() as usize;
        src.advance(num_consumed);

        // Finally, if we need payload, zero-copy that from src.
        if let Command::Forward(payload) = &mut command
            && payload_len > 0
        {
            payload.chunk = src.split_to(payload_len).freeze();
        }

        Ok(Some(ReliabilityMessage {
            write,
            read,
            command,
        }))
    }
}

impl ReliabilityCodec {
    /// Creates a new `ReliabilityCodec`.
    pub fn new() -> Self {
        Self
    }

    /// The maximum number of bytes of overhead added by the codec to any
    /// message carrying payload bytes. This helps us calculate how many payload
    /// bytes to add to each message to enforce an mtu.
    const fn max_header_len() -> usize {
        // This *must* be kept synchronized with our encoding scheme.
        // overhead = write (8) + read (8) + cmd (1) + payload_len (2)
        8 + 8 + 1 + 2
    }

    fn command_to_type(command: &Command) -> u8 {
        match command {
            Command::Forward(_) => 0,
            Command::Acknowledge => 1,
            Command::Rewind => 2,
            Command::RewindAck => 3,
            Command::Shut => 4,
            Command::ShutAck1 => 5,
            Command::ShutAck2 => 6,
            Command::Reset => 7,
        }
    }

    fn type_to_command(value: u8) -> io::Result<Command> {
        let cmd = match value {
            0 => Command::Forward(Data::from(Bytes::new())),
            1 => Command::Acknowledge,
            2 => Command::Rewind,
            3 => Command::RewindAck,
            4 => Command::Shut,
            5 => Command::ShutAck1,
            6 => Command::ShutAck2,
            7 => Command::Reset,
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };
        Ok(cmd)
    }
}

impl FrameSize for ReliabilityCodec {
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

    fn assert_encode_decode(msg: ReliabilityMessage) {
        let mut buf = BytesMut::new();

        let encode_result = ReliabilityCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_ok());

        let decode_result = ReliabilityCodec.decode(&mut buf);
        assert!(matches!(decode_result, Ok(Some(_))));

        let encoded_decoded_msg = decode_result.unwrap().unwrap();
        assert_eq!(msg, encoded_decoded_msg);
    }

    fn gen_payload(len: usize) -> Bytes {
        BytesMut::zeroed(len).freeze()
    }

    fn message(command: Command) -> ReliabilityMessage {
        ReliabilityMessage {
            write: 123,
            read: 321,
            command,
        }
    }

    fn test_valid_command(command: Command) {
        assert_encode_decode(message(command));
    }

    #[test]
    fn command_forward() {
        test_valid_command(Command::Forward(Data::from(Bytes::from(
            "This is the payload.",
        ))));
    }

    #[test]
    fn command_rewind() {
        test_valid_command(Command::Rewind);
    }

    #[test]
    fn command_rewind_ack() {
        test_valid_command(Command::RewindAck);
    }

    #[test]
    fn command_acknowledge() {
        test_valid_command(Command::Acknowledge);
    }

    #[test]
    fn command_shut() {
        test_valid_command(Command::Shut);
    }

    #[test]
    fn command_shut_ack1() {
        test_valid_command(Command::ShutAck1);
    }

    #[test]
    fn command_shut_ack2() {
        test_valid_command(Command::ShutAck2);
    }

    #[test]
    fn reset() {
        test_valid_command(Command::Reset);
    }

    #[test]
    fn invalid_payload_length() {
        // Max supported payload length.
        let max_len = ReliabilityCodec::mss(ReliabilityCodec::mtu());

        let payload = Data::from(gen_payload(max_len));
        test_valid_command(Command::Forward(payload));

        // This payload is larger than supported.
        let payload = Data::from(gen_payload(max_len + 1));
        let msg = message(Command::Forward(payload));

        // Should get encode error.
        let mut buf = BytesMut::new();
        let encode_result = ReliabilityCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_err());
    }

    fn test_invalid(command: Command, byte_to_stomp: usize) {
        let mut buf = BytesMut::new();

        let msg = message(command);
        assert!(ReliabilityCodec.encode(msg, &mut buf).is_ok());

        buf[byte_to_stomp] = 99; // stomp a byte

        assert!(ReliabilityCodec.decode(&mut buf).is_err());
    }

    #[test]
    fn invalid_command() {
        // The command type is the 17th byte (index 16).
        test_invalid(Command::Shut, 16);
    }
}
