//! Length-prefix framing and chunking for Noise transport messages.
//!
//! `snow` does no framing at all: it hands back a byte string and expects the
//! caller to deliver it whole and in order. On a stream transport that means a
//! 2-byte big-endian length prefix, which is also the natural fit because a
//! Noise message can never exceed 65535 bytes.
//!
//! That hard ceiling is why chunking lives here rather than in the application:
//! a caller that hands `send` a 100 KiB payload must not get a silently
//! truncated write. Each chunk carries a one-byte continuation flag *inside the
//! encrypted plaintext*, so an attacker cannot splice, truncate, or reorder a
//! multi-chunk message without failing the AEAD — a length prefix alone is
//! unauthenticated and would let an on-path attacker drop the tail of a message
//! and have the receiver accept the prefix as complete.

use std::io::{Read, Write};

use crate::error::{Error, Result};

/// A Noise message is length-prefixed with two bytes, so it cannot exceed this.
pub const NOISE_MAX_MESSAGE_LEN: usize = 65535;
/// ChaCha20-Poly1305 tag appended to every encrypted Noise message.
pub const NOISE_TAG_LEN: usize = 16;
/// Largest plaintext `snow` will encrypt into one message.
pub const NOISE_MAX_PLAINTEXT_LEN: usize = NOISE_MAX_MESSAGE_LEN - NOISE_TAG_LEN;
/// The continuation flag prepended to every chunk's plaintext.
pub const CHUNK_HEADER_LEN: usize = 1;
/// Largest slice of caller payload that fits in one chunk.
pub const MAX_CHUNK_PAYLOAD_LEN: usize = NOISE_MAX_PLAINTEXT_LEN - CHUNK_HEADER_LEN;

/// Cap on a reassembled message. This bounds *memory*, and only memory: a chunk
/// whose body is empty adds nothing to the total, so the byte cap alone would
/// never be reached by a peer that streams empty continuation chunks. The chunk
/// ceiling and the empty-continuation rejection in [`crate::noise::NoiseSession`]
/// are what bound the time a single message may occupy a session thread.
pub const DEFAULT_MAX_MESSAGE_LEN: usize = 4 * 1024 * 1024;

pub(crate) const FLAG_FINAL: u8 = 0x00;
pub(crate) const FLAG_MORE: u8 = 0x01;

/// Outcome of reading one frame from a stream.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameRead {
    /// A complete frame was read into the caller's buffer.
    Frame,
    /// The peer closed the connection cleanly, on a frame boundary.
    Eof,
}

/// Write one length-prefixed Noise message.
pub fn write_frame<W: Write>(writer: &mut W, message: &[u8]) -> Result<()> {
    if message.len() > NOISE_MAX_MESSAGE_LEN {
        return Err(Error::FrameTooLarge {
            len: message.len(),
            max: NOISE_MAX_MESSAGE_LEN,
        });
    }
    let len = u16::try_from(message.len()).map_err(|_| Error::FrameTooLarge {
        len: message.len(),
        max: NOISE_MAX_MESSAGE_LEN,
    })?;
    writer.write_all(&len.to_be_bytes()).map_err(Error::Io)?;
    writer.write_all(message).map_err(Error::Io)?;
    Ok(())
}

/// Read one length-prefixed Noise message into `out`, replacing its contents.
pub fn read_frame<R: Read>(reader: &mut R, out: &mut Vec<u8>) -> Result<FrameRead> {
    let mut len_bytes = [0u8; 2];
    match read_exact_or_eof(reader, &mut len_bytes)? {
        0 => return Ok(FrameRead::Eof),
        2 => {}
        got => return Err(Error::TruncatedFrame { got, want: 2 }),
    }
    let want = usize::from(u16::from_be_bytes(len_bytes));
    out.clear();
    out.resize(want, 0);
    let got = read_exact_or_eof(reader, out)?;
    if got != want {
        out.clear();
        return Err(Error::TruncatedFrame { got, want });
    }
    Ok(FrameRead::Frame)
}

/// Fill `buf`, returning how many bytes were read before EOF.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(filled)
}

/// Split a payload into chunk plaintexts, each prefixed with its continuation
/// flag. An empty payload still yields one (final, empty-bodied) chunk so that
/// zero-length application messages survive the round trip.
pub(crate) fn split_into_chunks(payload: &[u8]) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        return vec![vec![FLAG_FINAL]];
    }
    let total = payload.len().div_ceil(MAX_CHUNK_PAYLOAD_LEN);
    payload
        .chunks(MAX_CHUNK_PAYLOAD_LEN)
        .enumerate()
        .map(|(i, part)| {
            let flag = if i + 1 == total {
                FLAG_FINAL
            } else {
                FLAG_MORE
            };
            let mut chunk = Vec::with_capacity(CHUNK_HEADER_LEN + part.len());
            chunk.push(flag);
            chunk.extend_from_slice(part);
            chunk
        })
        .collect()
}

/// Strip and interpret a chunk's continuation flag.
pub(crate) fn split_chunk_header(chunk: &[u8]) -> Result<(bool, &[u8])> {
    let (&flag, body) = chunk.split_first().ok_or(Error::EmptyChunk)?;
    match flag {
        FLAG_FINAL => Ok((true, body)),
        FLAG_MORE => Ok((false, body)),
        flag => Err(Error::BadContinuationFlag { flag }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_payload_still_produces_one_final_chunk() {
        let chunks = split_into_chunks(&[]);
        assert_eq!(chunks, vec![vec![FLAG_FINAL]]);
    }

    #[test]
    fn chunk_boundary_math() {
        assert_eq!(MAX_CHUNK_PAYLOAD_LEN, 65518);
        assert_eq!(
            split_into_chunks(&vec![7u8; MAX_CHUNK_PAYLOAD_LEN]).len(),
            1
        );
        assert_eq!(
            split_into_chunks(&vec![7u8; MAX_CHUNK_PAYLOAD_LEN + 1]).len(),
            2
        );
        let exact_two = split_into_chunks(&vec![7u8; MAX_CHUNK_PAYLOAD_LEN * 2]);
        assert_eq!(exact_two.len(), 2);
        assert_eq!(exact_two[0][0], FLAG_MORE);
        assert_eq!(exact_two[1][0], FLAG_FINAL);
    }

    #[test]
    fn unknown_continuation_flag_is_rejected() {
        assert!(matches!(
            split_chunk_header(&[0x02, 1, 2, 3]),
            Err(Error::BadContinuationFlag { flag: 0x02 })
        ));
        assert!(matches!(split_chunk_header(&[]), Err(Error::EmptyChunk)));
    }

    #[test]
    fn frame_roundtrip_and_clean_eof() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"hello").expect("write");
        let mut cursor = Cursor::new(wire);
        let mut out = Vec::new();
        assert_eq!(
            read_frame(&mut cursor, &mut out).expect("read"),
            FrameRead::Frame
        );
        assert_eq!(out, b"hello");
        assert_eq!(
            read_frame(&mut cursor, &mut out).expect("read eof"),
            FrameRead::Eof
        );
    }

    #[test]
    fn truncated_frame_is_a_typed_error_not_a_hang() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"hello").expect("write");
        wire.truncate(4);
        let mut out = Vec::new();
        let err = read_frame(&mut Cursor::new(wire), &mut out).expect_err("must fail");
        assert!(matches!(err, Error::TruncatedFrame { got: 2, want: 5 }));
    }
}
