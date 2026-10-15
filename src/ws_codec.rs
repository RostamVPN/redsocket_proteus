// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Synchronous, incremental, push-based WebSocket server-side codec (RFC 6455).

const OP_CONT: u8 = 0x0;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Maximum accepted single-frame payload length. Matches the reference.
pub const MAX_FRAME: u64 = 16 * 1024 * 1024;

/// A fully-decoded, application-level WebSocket event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    /// A complete (reassembled) binary message.
    Binary(Vec<u8>),
    /// A ping control frame's payload.
    Ping(Vec<u8>),
    /// A pong control frame's payload.
    Pong(Vec<u8>),
    Close,
}

/// A protocol-level error that makes the stream unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    /// A frame declared a payload length greater than [`MAX_FRAME`].
    FrameTooLarge(u64),
}

impl core::fmt::Display for WsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WsError::FrameTooLarge(n) => {
                write!(f, "ws frame too large: {} > {}", n, MAX_FRAME)
            }
        }
    }
}

impl std::error::Error for WsError {}

/// Incremental server-side WebSocket frame decoder.
pub struct WsDecoder {
    /// Unconsumed wire bytes (a possibly-partial frame at the front).
    buf: Vec<u8>,
    /// Reassembly buffer for BINARY/CONT fragments across frames.
    frag: Vec<u8>,
}

impl Default for WsDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl WsDecoder {
    /// Create an empty decoder.
    pub fn new() -> Self {
        WsDecoder {
            buf: Vec::new(),
            frag: Vec::new(),
        }
    }

    /// Create a decoder pre-seeded with `prefix` — leftover bytes already read past
    /// the HTTP upgrade headers. These are parsed together with the first (and
    /// subsequent) `stats()` calls.
    pub fn with_prefix(prefix: Vec<u8>) -> Self {
        WsDecoder {
            buf: prefix,
            frag: Vec::new(),
        }
    }

    /// Stats newly-received bytes. Returns every event that is now fully decoded.
    pub fn stats(&mut self, data: &[u8]) -> Result<Vec<WsEvent>, WsError> {
        self.buf.extend_from_slice(data);

        let mut events = Vec::new();
        let mut pos = 0usize;

        loop {
            match parse_frame(&self.buf[pos..])? {
                None => break,
                Some((consumed, fin, op, payload)) => {
                    pos += consumed;
                    match op {
                        OP_CLOSE => {
                            events.push(WsEvent::Close);

                            self.buf.clear();
                            return Ok(events);
                        }
                        OP_PING => events.push(WsEvent::Ping(payload)),
                        OP_PONG => events.push(WsEvent::Pong(payload)),
                        OP_BINARY | OP_CONT => {
                            self.frag.extend_from_slice(&payload);
                            if fin {
                                events.push(WsEvent::Binary(std::mem::take(&mut self.frag)));
                            }
                        }
                        _ => { }
                    }
                }
            }
        }

        if pos > 0 {
            self.buf.drain(..pos);
        }
        Ok(events)
    }
}

/// A parsed frame: `(bytes_consumed, fin, opcode, unmasked_payload)`.
type ParsedFrame = (usize, bool, u8, Vec<u8>);

/// Try to parse a single frame from the front of `data`.
fn parse_frame(data: &[u8]) -> Result<Option<ParsedFrame>, WsError> {
    if data.len() < 2 {
        return Ok(None);
    }
    let b0 = data[0];
    let b1 = data[1];
    let fin = b0 & 0x80 != 0;
    let op = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7F) as u64;

    let mut cursor = 2usize;

    let len: u64 = if len7 == 126 {
        if data.len() < cursor + 2 {
            return Ok(None);
        }
        let l = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as u64;
        cursor += 2;
        l
    } else if len7 == 127 {
        if data.len() < cursor + 8 {
            return Ok(None);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[cursor..cursor + 8]);
        let l = u64::from_be_bytes(b);
        cursor += 8;
        l
    } else {
        len7
    };

    if len > MAX_FRAME {
        return Err(WsError::FrameTooLarge(len));
    }

    let mask = if masked {
        if data.len() < cursor + 4 {
            return Ok(None);
        }
        let m = [
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ];
        cursor += 4;
        Some(m)
    } else {
        None
    };

    let len = len as usize;
    if data.len() < cursor + len {
        return Ok(None);
    }
    let mut payload = data[cursor..cursor + len].to_vec();
    cursor += len;

    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
    }

    Ok(Some((cursor, fin, op, payload)))
}

/// Build a server→client frame header + payload (unmasked, FIN set).
fn frame_bytes(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 10);
    v.push(0x80 | op);
    if payload.len() < 126 {
        v.push(payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        v.push(126);
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        v.push(127);
        v.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    v.extend_from_slice(payload);
    v
}

/// Encode an unmasked server→client BINARY frame (opcode 0x2, FIN set).
pub fn encode_binary(payload: &[u8]) -> Vec<u8> {
    frame_bytes(OP_BINARY, payload)
}

/// Encode an unmasked server→client PONG frame (opcode 0xA, FIN set).
pub fn encode_pong(payload: &[u8]) -> Vec<u8> {
    frame_bytes(OP_PONG, payload)
}

/// Encode an unmasked server→client CLOSE frame (opcode 0x8, FIN set, empty).
pub fn encode_close() -> Vec<u8> {
    frame_bytes(OP_CLOSE, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a client→server frame the way a real browser/client does: masked, with
    /// the 4-byte key XORed over the payload.
    fn masked(op: u8, fin: bool, payload: &[u8], key: [u8; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(if fin { 0x80 | op } else { op });
        let n = payload.len();
        if n < 126 {
            v.push(0x80 | n as u8);
        } else if n <= 0xFFFF {
            v.push(0x80 | 126);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            v.push(0x80 | 127);
            v.extend_from_slice(&(n as u64).to_be_bytes());
        }
        v.extend_from_slice(&key);
        v.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        v
    }

    #[test]
    fn decodes_a_masked_binary_frame() {
        let mut d = WsDecoder::new();
        let ev = d
            .stats(&masked(OP_BINARY, true, b"hello", [0xDE, 0xAD, 0xBE, 0xEF]))
            .unwrap();
        assert_eq!(ev, vec![WsEvent::Binary(b"hello".to_vec())]);
    }

    /// Unmasking must be applied — a decoder that forgets the XOR still produces
    /// the right *length*, so only a content check catches it.
    #[test]
    fn masking_is_actually_undone() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut d = WsDecoder::new();
        let ev = d
            .stats(&masked(OP_BINARY, true, payload, [0x01, 0x02, 0x03, 0x04]))
            .unwrap();
        assert_eq!(ev, vec![WsEvent::Binary(payload.to_vec())]);
    }

    #[test]
    fn all_three_length_forms_decode() {
        for len in [0usize, 1, 125, 126, 127, 65535, 65536, 70000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut d = WsDecoder::new();
            let ev = d
                .stats(&masked(OP_BINARY, true, &payload, [9, 8, 7, 6]))
                .unwrap();
            assert_eq!(ev, vec![WsEvent::Binary(payload)], "len {len} failed");
        }
    }

    #[test]
    fn fragments_are_reassembled_in_order() {
        let mut d = WsDecoder::new();
        assert!(d
            .stats(&masked(OP_BINARY, false, b"one ", [1, 2, 3, 4]))
            .unwrap()
            .is_empty());
        assert!(d
            .stats(&masked(OP_CONT, false, b"two ", [5, 6, 7, 8]))
            .unwrap()
            .is_empty());
        let ev = d
            .stats(&masked(OP_CONT, true, b"three", [9, 10, 11, 12]))
            .unwrap();
        assert_eq!(ev, vec![WsEvent::Binary(b"one two three".to_vec())]);
    }

    /// A ping between fragments must be delivered without disturbing the message
    /// being reassembled.
    #[test]
    fn control_frames_interleave_without_corrupting_reassembly() {
        let mut d = WsDecoder::new();
        d.stats(&masked(OP_BINARY, false, b"AA", [1, 1, 1, 1]))
            .unwrap();
        let ev = d
            .stats(&masked(OP_PING, true, b"pong me", [2, 2, 2, 2]))
            .unwrap();
        assert_eq!(ev, vec![WsEvent::Ping(b"pong me".to_vec())]);
        let ev = d.stats(&masked(OP_CONT, true, b"BB", [3, 3, 3, 3])).unwrap();
        assert_eq!(ev, vec![WsEvent::Binary(b"AABB".to_vec())]);
    }

    /// TCP delivers arbitrary slices; a frame split anywhere must still decode
    /// exactly once. This is the regression that bulk transfers expose.
    #[test]
    fn a_frame_split_at_every_offset_decodes_once() {
        let payload: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let frame = masked(OP_BINARY, true, &payload, [0x5A, 0x3C, 0x11, 0x77]);
        for split in 1..frame.len() {
            let mut d = WsDecoder::new();
            let mut got = d.stats(&frame[..split]).unwrap();
            got.extend(d.stats(&frame[split..]).unwrap());
            assert_eq!(
                got,
                vec![WsEvent::Binary(payload.clone())],
                "split at {split}"
            );
        }
    }

    #[test]
    fn byte_at_a_time_delivery_decodes() {
        let frame = masked(OP_BINARY, true, b"dribble", [4, 3, 2, 1]);
        let mut d = WsDecoder::new();
        let mut got = Vec::new();
        for b in &frame {
            got.extend(d.stats(&[*b]).unwrap());
        }
        assert_eq!(got, vec![WsEvent::Binary(b"dribble".to_vec())]);
    }

    #[test]
    fn several_frames_in_one_read_all_decode() {
        let mut wire = masked(OP_BINARY, true, b"first", [1, 2, 3, 4]);
        wire.extend(masked(OP_BINARY, true, b"second", [5, 6, 7, 8]));
        wire.extend(masked(OP_PING, true, b"p", [9, 9, 9, 9]));
        let mut d = WsDecoder::new();
        assert_eq!(
            d.stats(&wire).unwrap(),
            vec![
                WsEvent::Binary(b"first".to_vec()),
                WsEvent::Binary(b"second".to_vec()),
                WsEvent::Ping(b"p".to_vec()),
            ]
        );
    }

    #[test]
    fn with_prefix_parses_bytes_read_past_the_upgrade_headers() {
        let frame = masked(OP_BINARY, true, b"leftover", [7, 7, 7, 7]);
        let (head, tail) = frame.split_at(3);
        let mut d = WsDecoder::with_prefix(head.to_vec());
        assert_eq!(
            d.stats(tail).unwrap(),
            vec![WsEvent::Binary(b"leftover".to_vec())]
        );
    }

    #[test]
    fn close_is_reported_and_stops_processing() {
        let mut wire = masked(OP_CLOSE, true, &[], [1, 2, 3, 4]);
        wire.extend(masked(OP_BINARY, true, b"after close", [1, 2, 3, 4]));
        let mut d = WsDecoder::new();
        assert_eq!(d.stats(&wire).unwrap(), vec![WsEvent::Close]);

        assert!(d.stats(&[]).unwrap().is_empty());
    }

    #[test]
    fn an_oversized_frame_is_a_protocol_error() {
        let mut v = vec![0x80 | OP_BINARY, 127];
        v.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        let mut d = WsDecoder::new();
        assert_eq!(d.stats(&v), Err(WsError::FrameTooLarge(MAX_FRAME + 1)));
    }

    #[test]
    fn unknown_opcodes_are_ignored_not_fatal() {
        let mut wire = masked(0x3, true, b"reserved", [1, 2, 3, 4]);
        wire.extend(masked(OP_BINARY, true, b"ok", [1, 2, 3, 4]));
        let mut d = WsDecoder::new();
        assert_eq!(
            d.stats(&wire).unwrap(),
            vec![WsEvent::Binary(b"ok".to_vec())]
        );
    }

    /// RFC 6455: server→client frames must NOT be masked. A masked server frame is
    /// a protocol violation that some clients drop the connection over.
    #[test]
    fn encoders_never_set_the_mask_bit_and_set_fin() {
        for f in [encode_binary(b"x"), encode_pong(b"x"), encode_close()] {
            assert_eq!(f[0] & 0x80, 0x80, "FIN must be set: {f:02x?}");
            assert_eq!(f[1] & 0x80, 0x00, "server frame must be unmasked: {f:02x?}");
        }
        assert_eq!(encode_binary(b"hi")[0] & 0x0F, OP_BINARY);
        assert_eq!(encode_pong(b"hi")[0] & 0x0F, OP_PONG);
        assert_eq!(encode_close()[0] & 0x0F, OP_CLOSE);
        assert_eq!(encode_close().len(), 2, "close carries no payload");
    }

    #[test]
    fn encoder_output_round_trips_through_the_decoder() {
        for len in [0usize, 1, 125, 126, 65535, 65536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut d = WsDecoder::new();
            let ev = d.stats(&encode_binary(&payload)).unwrap();
            assert_eq!(ev, vec![WsEvent::Binary(payload)], "len {len}");
        }
    }

    #[test]
    fn encoder_picks_the_minimal_length_form() {
        assert_eq!(encode_binary(&[0u8; 125])[1] & 0x7F, 125);
        assert_eq!(encode_binary(&[0u8; 126])[1] & 0x7F, 126);
        assert_eq!(encode_binary(&[0u8; 65535])[1] & 0x7F, 126);
        assert_eq!(encode_binary(&[0u8; 65536])[1] & 0x7F, 127);
    }
}
