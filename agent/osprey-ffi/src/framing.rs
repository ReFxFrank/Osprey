//! Wire framing, exposed so Swift can drive a socket without reimplementing it.
//!
//! Osprey frames every Noise message with a 2-byte big-endian length prefix.
//! `osprey-core` reads and writes those frames through `std::io::Read`/`Write`,
//! which assumes a blocking stream: `read_frame` cannot say "this is a valid
//! frame so far, send me more". A phone driving a non-blocking socket needs
//! exactly that, so the *completeness predicate* lives here while the actual
//! parse still runs through `osprey_core::noise::read_frame` — the core stays
//! the only implementation of the format itself.

use std::io::Cursor;

use osprey_core::noise::{
    read_frame, write_frame, FrameRead, MAX_CHUNK_PAYLOAD_LEN, NOISE_MAX_MESSAGE_LEN,
};

use crate::error::{OspreyError, Result};

/// Bytes the length prefix occupies.
pub(crate) const LENGTH_PREFIX_LEN: usize = 2;

/// Cap on unparsed bytes an object will hold. Two full Noise messages, which is
/// enough to absorb a socket read that straddles a frame boundary without
/// letting a peer that never completes a frame grow the buffer without bound.
pub(crate) const MAX_INBOUND_BUFFER: usize = 2 * (NOISE_MAX_MESSAGE_LEN + LENGTH_PREFIX_LEN);

/// Result of looking for one complete frame at the head of a buffer.
#[derive(Debug, uniffi::Record)]
pub struct FrameScan {
    /// The frame body, or `None` when the buffer does not yet hold a whole one.
    pub frame: Option<Vec<u8>>,
    /// Bytes to drop from the head of the buffer. Zero when `frame` is `None`.
    pub consumed: u64,
}

/// Length of the complete frame at the head of `buffer`, prefix included, or
/// `None` if more bytes are needed.
///
/// The 2-byte prefix is re-read here rather than delegated because `read_frame`
/// reports a short buffer as `TruncatedFrame`, which is indistinguishable from a
/// peer that closed mid-frame — a hard error where this needs "not yet".
pub(crate) fn complete_frame_len(buffer: &[u8]) -> Option<usize> {
    let prefix = buffer.get(..LENGTH_PREFIX_LEN)?;
    let mut len_bytes = [0u8; LENGTH_PREFIX_LEN];
    len_bytes.copy_from_slice(prefix);
    let body = usize::from(u16::from_be_bytes(len_bytes));
    let total = LENGTH_PREFIX_LEN + body;
    (buffer.len() >= total).then_some(total)
}

/// Pull one complete frame off the head of `buffer`, removing its bytes.
pub(crate) fn take_frame(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    let Some(total) = complete_frame_len(buffer) else {
        return Ok(None);
    };
    let mut cursor = Cursor::new(&buffer[..total]);
    let mut frame = Vec::new();
    match read_frame(&mut cursor, &mut frame)? {
        FrameRead::Frame => {}
        // Unreachable: `complete_frame_len` already proved the bytes are there.
        // Reported rather than asserted, because an assertion here would be a
        // panic on a remote-input path.
        FrameRead::Eof => {
            return Err(OspreyError::Framing {
                detail: "frame vanished between length check and parse".to_string(),
            })
        }
    }
    buffer.drain(..total);
    Ok(Some(frame))
}

/// Append socket bytes to an inbound buffer, refusing unbounded growth.
pub(crate) fn push_bounded(buffer: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if buffer.len() + data.len() > MAX_INBOUND_BUFFER {
        return Err(OspreyError::InboundOverflow {
            limit: MAX_INBOUND_BUFFER as u64,
        });
    }
    buffer.extend_from_slice(data);
    Ok(())
}

/// Add the length prefix to one Noise message.
#[uniffi::export]
pub fn frame_encode(message: Vec<u8>) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + message.len());
    write_frame(&mut out, &message)?;
    Ok(out)
}

/// Strip one length-prefixed frame from the head of `buffer`.
///
/// Returns `frame: None, consumed: 0` when `buffer` does not yet hold a complete
/// frame, so a caller can push more socket bytes and retry.
#[uniffi::export]
pub fn frame_decode(buffer: Vec<u8>) -> Result<FrameScan> {
    let mut owned = buffer;
    let before = owned.len();
    match take_frame(&mut owned)? {
        Some(frame) => Ok(FrameScan {
            frame: Some(frame),
            consumed: (before - owned.len()) as u64,
        }),
        None => Ok(FrameScan {
            frame: None,
            consumed: 0,
        }),
    }
}

/// The 65535-byte ceiling a single Noise message cannot exceed.
#[uniffi::export]
pub fn noise_max_message_len() -> u64 {
    NOISE_MAX_MESSAGE_LEN as u64
}

/// Largest slice of caller payload that fits in one chunk. A payload longer than
/// this is split across several frames by [`crate::NoiseTransport::encrypt`].
#[uniffi::export]
pub fn max_chunk_payload_len() -> u64 {
    MAX_CHUNK_PAYLOAD_LEN as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partial_frame_asks_for_more_instead_of_failing() {
        let framed = frame_encode(b"hello".to_vec()).expect("encode");
        for cut in 0..framed.len() {
            let scan = frame_decode(framed[..cut].to_vec()).expect("partial scan");
            assert!(scan.frame.is_none(), "cut at {cut} should need more bytes");
            assert_eq!(scan.consumed, 0);
        }
        let scan = frame_decode(framed.clone()).expect("full scan");
        assert_eq!(scan.frame.as_deref(), Some(&b"hello"[..]));
        assert_eq!(scan.consumed, framed.len() as u64);
    }

    #[test]
    fn a_trailing_frame_is_left_for_the_next_call() {
        let mut wire = frame_encode(b"one".to_vec()).expect("encode");
        wire.extend(frame_encode(b"two".to_vec()).expect("encode"));
        let scan = frame_decode(wire.clone()).expect("scan");
        assert_eq!(scan.frame.as_deref(), Some(&b"one"[..]));
        let rest = wire[scan.consumed as usize..].to_vec();
        let scan = frame_decode(rest).expect("scan");
        assert_eq!(scan.frame.as_deref(), Some(&b"two"[..]));
    }

    #[test]
    fn an_oversized_message_is_refused_not_truncated() {
        let err = frame_encode(vec![0u8; NOISE_MAX_MESSAGE_LEN + 1]).expect_err("must refuse");
        assert!(matches!(err, OspreyError::Framing { .. }), "{err:?}");
    }

    #[test]
    fn the_inbound_bound_is_enforced() {
        let mut buffer = Vec::new();
        push_bounded(&mut buffer, &vec![0u8; MAX_INBOUND_BUFFER]).expect("fits exactly");
        let err = push_bounded(&mut buffer, &[0u8]).expect_err("one byte over");
        assert!(matches!(err, OspreyError::InboundOverflow { .. }), "{err:?}");
    }
}
