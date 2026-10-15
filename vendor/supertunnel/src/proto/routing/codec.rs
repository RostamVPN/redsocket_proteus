use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::FrameSize;
use crate::net::{NetworkAddress, NetworkTarget};
use crate::proto::routing::message::{Command, RoutingMessage};

/// Encodes and decodes routing control commands (e.g., Connect, Add, Remove).
#[derive(Clone, Debug, Default)]
pub struct RoutingCodec;

impl Encoder<RoutingMessage> for RoutingCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: RoutingMessage, dst: &mut BytesMut) -> io::Result<()> {
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
            Command::Connect((sid, target)) => {
                dst.put_u64(sid);
                self.encode_target(target, dst)?;
            }
            Command::ConnectOk(sid) => dst.put_u64(sid),
            Command::ConnectErr(sid) => dst.put_u64(sid),
            Command::Add(sid) => dst.put_u64(sid),
            Command::Remove(sid) => dst.put_u64(sid),
            Command::Forward(payload) => {
                dst.put_u16(u16::try_from(payload.chunk.len()).unwrap());
                // extend_from_slice() takes a ref, so it must copy.
                // dst.extend_from_slice(&payload.data);
                // put() consumes the data, so may be able to zero-copy.
                dst.put(payload.chunk);
            }
            Command::ShutRead => {}
            Command::ShutWrite => {}
        }

        Ok(())
    }
}

impl Decoder for RoutingCodec {
    type Item = RoutingMessage;

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
            0 => {
                if reader.remaining() >= 8 {
                    let sid = reader.get_u64();
                    self.decode_target(&mut reader)?
                        .map(|target| Command::Connect((sid, target)))
                } else {
                    None
                }
            }
            1 => (reader.remaining() >= 8).then(|| Command::ConnectOk(reader.get_u64())),
            2 => (reader.remaining() >= 8).then(|| Command::ConnectErr(reader.get_u64())),
            3 => (reader.remaining() >= 8).then(|| Command::Add(reader.get_u64())),
            4 => (reader.remaining() >= 8).then(|| Command::Remove(reader.get_u64())),
            5 => {
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
                return Ok(Some(RoutingMessage::from(data)));
            }
            6 => Some(Command::ShutRead),
            7 => Some(Command::ShutWrite),
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };

        if let Some(command) = maybe_command {
            src.advance(reader.position() as usize);
            Ok(Some(RoutingMessage::from(command)))
        } else {
            Ok(None) // Need more bytes.
        }
    }
}

impl RoutingCodec {
    /// Creates a new `RoutingCodec`.
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
            Command::Connect(_) => 0,
            Command::ConnectOk(_) => 1,
            Command::ConnectErr(_) => 2,
            Command::Add(_) => 3,
            Command::Remove(_) => 4,
            Command::Forward(_) => 5,
            Command::ShutRead => 6,
            Command::ShutWrite => 7,
        }
    }

    fn encode_target(&mut self, target: NetworkTarget, dst: &mut BytesMut) -> io::Result<()> {
        let address = target.addr();

        const PORT_LEN: usize = 2;
        const KIND_LEN: usize = 1;
        let address_len = match &address {
            NetworkAddress::IpAddr(IpAddr::V4(_)) => 4,
            NetworkAddress::IpAddr(IpAddr::V6(_)) => 6,
            NetworkAddress::Name(name) => 1 + name.len().min(u8::MAX as usize), // len + name
        };
        dst.reserve(PORT_LEN + KIND_LEN + address_len);

        // Encode port.
        dst.put_u16(target.port());

        // Encode kind.
        let kind = match &address {
            NetworkAddress::IpAddr(addr) => match addr {
                IpAddr::V4(_) => 0,
                IpAddr::V6(_) => 1,
            },
            NetworkAddress::Name(_) => 2,
        };
        dst.put_u8(kind);

        // Encode address.
        match &address {
            NetworkAddress::IpAddr(IpAddr::V4(addr)) => dst.put_slice(&addr.octets()),
            NetworkAddress::IpAddr(IpAddr::V6(addr)) => dst.put_slice(&addr.octets()),
            NetworkAddress::Name(name) => {
                let len = name.len().min(u8::MAX as usize);
                dst.put_u8(len as u8);
                dst.put_slice(&name.as_bytes()[0..len]);
            }
        };

        Ok(())
    }

    fn decode_target(&mut self, src: &mut Cursor<&BytesMut>) -> io::Result<Option<NetworkTarget>> {
        if src.remaining() < 3 {
            return Ok(None);
        }

        let port = src.get_u16();
        let kind = src.get_u8();

        let address = match kind {
            0 => {
                if src.remaining() < 4 {
                    return Ok(None);
                }

                let mut octets = [0u8; 4];
                src.copy_to_slice(&mut octets);

                let addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                NetworkAddress::from(IpAddr::from(addr))
            }
            1 => {
                if src.remaining() < 16 {
                    return Ok(None);
                }

                let mut seg = [0u16; 8];
                for item in &mut seg {
                    *item = src.get_u16();
                }

                let addr = Ipv6Addr::new(
                    seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                );
                NetworkAddress::IpAddr(IpAddr::from(addr))
            }
            2 => {
                if src.remaining() < 1 {
                    return Ok(None);
                }

                let name_len = src.get_u8() as usize;

                if src.remaining() < name_len {
                    return Ok(None);
                }

                let name_bytes = src.copy_to_bytes(name_len);
                let name = String::from_utf8_lossy(&name_bytes).to_string();
                NetworkAddress::from(name)
            }
            _ => return Err(std::io::ErrorKind::InvalidData.into()),
        };

        Ok(Some(NetworkTarget::new(address, port)))
    }
}

impl FrameSize for RoutingCodec {
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;
    use crate::net::{NetworkAddress, NetworkTarget};
    use crate::test::TestPayload;

    fn assert_encode_decode(msg: RoutingMessage) {
        let mut buf = BytesMut::new();

        let encode_result = RoutingCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_ok());

        let decode_result = RoutingCodec.decode(&mut buf);
        assert!(matches!(decode_result, Ok(Some(_))));

        let encoded_decoded_msg = decode_result.unwrap().unwrap();
        assert_eq!(msg, encoded_decoded_msg);
    }

    fn gen_payload(len: usize) -> Bytes {
        // BytesMut::zeroed(len).freeze()
        TestPayload::bytes(len)
    }

    fn test_valid_command(command: Command) {
        assert_encode_decode(RoutingMessage::from(command));
    }

    #[test]
    fn valid_shutread() {
        test_valid_command(Command::ShutRead);
    }

    #[test]
    fn valid_shutwrite() {
        test_valid_command(Command::ShutWrite);
    }

    #[test]
    fn valid_connect() {
        let addresses = vec![
            NetworkAddress::from(String::from("test.com")),
            NetworkAddress::from(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1))),
            NetworkAddress::from(IpAddr::V6(Ipv6Addr::new(8, 7, 6, 5, 4, 3, 2, 1))),
        ];

        for addr in addresses {
            test_valid_command(Command::Connect((123, NetworkTarget::new(addr, 12345))));
        }
    }

    #[test]
    fn valid_connectok() {
        test_valid_command(Command::ConnectOk(123));
    }

    #[test]
    fn valid_connecterr() {
        test_valid_command(Command::ConnectErr(123));
    }

    #[test]
    fn valid_add() {
        test_valid_command(Command::Add(123));
    }

    #[test]
    fn valid_remove() {
        test_valid_command(Command::Remove(123));
    }

    #[test]
    fn valid_forward() {
        test_valid_command(Command::from(Bytes::from("This is the payload.")));
    }

    #[test]
    fn invalid_payload_length() {
        // Max supported payload length.
        let max_len = RoutingCodec::mss(RoutingCodec::mtu());
        let bytes = gen_payload(max_len);
        test_valid_command(Command::from(bytes));

        // This payload is larger than supported.
        let bytes = gen_payload(max_len + 1);
        let msg = RoutingMessage::from(bytes);

        // Should get encode error.
        let mut buf = BytesMut::new();
        let encode_result = RoutingCodec.encode(msg.clone(), &mut buf);
        assert!(encode_result.is_err());
    }

    fn test_invalid(command: Command, byte_to_stomp: usize) {
        let mut buf = BytesMut::new();

        let msg = RoutingMessage::from(command);
        assert!(RoutingCodec.encode(msg, &mut buf).is_ok());

        buf[byte_to_stomp] = 99; // stomp a byte

        assert!(RoutingCodec.decode(&mut buf).is_err());
    }

    #[test]
    fn invalid_command_kind() {
        // The command kind is the 1st byte (index 0).
        test_invalid(Command::ShutRead, 0);
    }

    #[test]
    fn invalid_network_target_kind() {
        let addr = NetworkAddress::from(String::from("test.com"));
        let port = 0;
        let target = NetworkTarget::new(addr, port);
        let sid = 123;
        // The network target kind is the 12th byte (index 11).
        test_invalid(Command::Connect((sid, target)), 11);
    }
}
