//! Established Noise transport: chunked, framed, authenticated messages.

use std::io::{Read, Write};

use snow::TransportState;

use crate::error::{Error, Result};
use crate::noise::framing::{
    read_frame, split_chunk_header, split_into_chunks, write_frame, FrameRead,
    DEFAULT_MAX_MESSAGE_LEN, MAX_CHUNK_PAYLOAD_LEN, NOISE_MAX_MESSAGE_LEN,
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

    /// How many chunks an honest sender could need for a message of the
    /// permitted size. The `+ 2` absorbs a partial final chunk and the single
    /// chunk a zero-length message still produces.
    fn max_chunks(&self) -> usize {
        self.max_message_len / MAX_CHUNK_PAYLOAD_LEN + 2
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
    ///
    /// Two independent bounds apply, because the byte cap alone is not a
    /// progress bound: an authenticated peer can emit continuation chunks whose
    /// bodies are empty, adding zero bytes per chunk and pinning the thread
    /// forever. So an empty non-final chunk is refused outright, and the total
    /// chunk count is capped as well.
    pub fn recv<R: Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        let max_chunks = self.max_chunks();
        let mut assembled: Vec<u8> = Vec::new();
        let mut frame = Vec::new();
        let mut plain = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let mut chunks = 0usize;
        loop {
            match read_frame(reader, &mut frame)? {
                FrameRead::Eof if chunks == 0 => return Ok(None),
                FrameRead::Eof => return Err(Error::TruncatedFrame { got: 0, want: 2 }),
                FrameRead::Frame => {}
            }
            chunks += 1;
            if chunks > max_chunks {
                return Err(Error::TooManyChunks { max: max_chunks });
            }
            let n = self
                .state
                .read_message(&frame, &mut plain)
                .map_err(Error::TransportAuth)?;
            let (final_chunk, body) = split_chunk_header(&plain[..n])?;
            if !final_chunk && body.is_empty() {
                return Err(Error::EmptyContinuationChunk);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::framing::{FLAG_FINAL, FLAG_MORE};
    use snow::Builder;

    /// Two transport states with no I/O and no identities, so the reassembly
    /// bounds can be exercised without standing up a pairing fixture. `NN`
    /// carries no static keys; `remote_static` is never read by these tests.
    fn transport_pair() -> (NoiseSession, NoiseSession) {
        let params = "Noise_NN_25519_ChaChaPoly_BLAKE2s"
            .parse::<snow::params::NoiseParams>()
            .expect("noise params");
        let mut initiator = Builder::new(params.clone())
            .build_initiator()
            .expect("initiator");
        let mut responder = Builder::new(params).build_responder().expect("responder");

        let mut a = [0u8; 1024];
        let mut b = [0u8; 1024];
        let n = initiator.write_message(&[], &mut a).expect("msg1");
        responder.read_message(&a[..n], &mut b).expect("read msg1");
        let n = responder.write_message(&[], &mut b).expect("msg2");
        initiator.read_message(&b[..n], &mut a).expect("read msg2");

        (
            NoiseSession::new(
                initiator
                    .into_transport_mode()
                    .expect("initiator transport"),
                [0u8; 32],
            ),
            NoiseSession::new(
                responder
                    .into_transport_mode()
                    .expect("responder transport"),
                [0u8; 32],
            ),
        )
    }

    /// Encrypt one chunk plaintext verbatim, bypassing `send`'s chunker. This is
    /// what a hostile-but-authenticated peer can do that `send` never will.
    fn write_raw_chunk(sender: &mut NoiseSession, plaintext: &[u8], wire: &mut Vec<u8>) {
        let mut cipher = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = sender
            .state
            .write_message(plaintext, &mut cipher)
            .expect("encrypt chunk");
        write_frame(wire, &cipher[..n]).expect("frame chunk");
    }

    #[test]
    fn an_empty_continuation_chunk_is_rejected() {
        let (mut sender, mut receiver) = transport_pair();
        let mut wire = Vec::new();
        write_raw_chunk(&mut sender, &[FLAG_MORE], &mut wire);
        write_raw_chunk(&mut sender, &[FLAG_FINAL], &mut wire);

        let err = receiver
            .recv(&mut std::io::Cursor::new(wire))
            .expect_err("an empty MORE chunk must be refused");
        assert!(
            matches!(err, Error::EmptyContinuationChunk),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn the_chunk_count_is_bounded_well_below_the_byte_cap() {
        let (mut sender, mut receiver) = transport_pair();
        let max_chunks = receiver.max_chunks();
        assert_eq!(
            max_chunks,
            DEFAULT_MAX_MESSAGE_LEN / MAX_CHUNK_PAYLOAD_LEN + 2
        );

        // One payload byte per chunk: the byte cap is 4 MiB and would not be
        // reached for ~4 million chunks, so this fails on the chunk ceiling or
        // not at all.
        let mut wire = Vec::new();
        for _ in 0..=max_chunks {
            write_raw_chunk(&mut sender, &[FLAG_MORE, 0x7f], &mut wire);
        }

        let err = receiver
            .recv(&mut std::io::Cursor::new(wire))
            .expect_err("an unbounded chunk stream must be refused");
        assert!(
            matches!(err, Error::TooManyChunks { max } if max == max_chunks),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn a_message_at_the_chunk_ceiling_still_round_trips() {
        let (mut sender, mut receiver) = transport_pair();
        let payload = vec![3u8; MAX_CHUNK_PAYLOAD_LEN * 2 + 7];
        let mut wire = Vec::new();
        sender.send(&payload, &mut wire).expect("send");
        let received = receiver
            .recv(&mut std::io::Cursor::new(wire))
            .expect("recv")
            .expect("a message");
        assert_eq!(received, payload);
    }
}
