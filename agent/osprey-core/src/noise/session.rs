//! Established Noise transport: chunked, framed, authenticated messages.

use std::io::{Read, Write};

use snow::TransportState;

use crate::error::{Error, Result};
use crate::noise::framing::{
    read_frame, split_chunk_header, split_into_chunks, write_frame, FrameRead,
    DEFAULT_MAX_MESSAGE_LEN, NOISE_MAX_MESSAGE_LEN,
};

pub struct NoiseSession {
    state: TransportState,
    remote_static: [u8; 32],
    max_message_len: usize,
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field("remote_static", &hex::encode(self.remote_static))
            .finish_non_exhaustive()
    }
}

impl NoiseSession {
    pub(crate) fn new(state: TransportState, remote_static: [u8; 32]) -> Self {
        Self {
            state,
            remote_static,
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
        }
    }

    /// The peer's X25519 static, as authenticated by the handshake. This is the
    /// value a caller compares against its pin.
    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }

    /// Cap on a single reassembled message. Lower it on paths that should never
    /// see large payloads; it is a memory-exhaustion bound, not a policy knob.
    pub fn set_max_message_len(&mut self, max: usize) {
        self.max_message_len = max;
    }

    /// Encrypt and write `payload`, chunking it across as many Noise messages as
    /// the 65535-byte ceiling requires.
    pub fn send<W: Write>(&mut self, payload: &[u8], writer: &mut W) -> Result<()> {
        let mut cipher = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        for chunk in split_into_chunks(payload) {
            let n = self
                .state
                .write_message(&chunk, &mut cipher)
                .map_err(Error::TransportAuth)?;
            write_frame(writer, &cipher[..n])?;
        }
        writer.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Read, decrypt and reassemble one logical message.
    ///
    /// `Ok(None)` means the peer closed cleanly on a message boundary. A close
    /// *mid*-message is an error, because accepting the prefix of a truncated
    /// message is how truncation attacks succeed.
    pub fn recv<R: Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        let mut assembled: Vec<u8> = Vec::new();
        let mut frame = Vec::new();
        let mut plain = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let mut first = true;
        loop {
            match read_frame(reader, &mut frame)? {
                FrameRead::Eof if first => return Ok(None),
                FrameRead::Eof => return Err(Error::TruncatedFrame { got: 0, want: 2 }),
                FrameRead::Frame => {}
            }
            first = false;
            let n = self
                .state
                .read_message(&frame, &mut plain)
                .map_err(Error::TransportAuth)?;
            let (final_chunk, body) = split_chunk_header(&plain[..n])?;
            if assembled.len() + body.len() > self.max_message_len {
                return Err(Error::MessageTooLarge {
                    max: self.max_message_len,
                });
            }
            assembled.extend_from_slice(body);
            if final_chunk {
                return Ok(Some(assembled));
            }
        }
    }
}
