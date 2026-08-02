//! Noise handshake driver: role/pattern validation, framed message exchange.

use std::io::{Read, Write};

use snow::{Builder, HandshakeState};

use crate::error::{Error, HandshakeStage, Result};
use crate::noise::framing::{read_frame, write_frame, FrameRead, NOISE_MAX_MESSAGE_LEN};
use crate::noise::session::NoiseSession;
use crate::pairing::PairingSecret;

/// Which of the two handshakes is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// First contact, authenticated by the QR secret.
    Pairing,
    /// Every session afterwards, authenticated by the pinned statics.
    Session,
}

impl Pattern {
    pub fn params(self) -> &'static str {
        match self {
            Self::Pairing => "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
            Self::Session => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        }
    }
}

/// IK is asymmetric: only the initiator supplies the peer's static up front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

pub struct HandshakeConfig<'a> {
    pub pattern: Pattern,
    pub role: Role,
    /// Raw 32-byte X25519 private key.
    pub local_static: &'a [u8; 32],
    /// The peer's X25519 static. Required for the initiator, ignored otherwise.
    pub remote_static: Option<&'a [u8; 32]>,
    /// Required for [`Pattern::Pairing`], rejected for [`Pattern::Session`].
    pub psk: Option<&'a PairingSecret>,
}

fn build_error(source: snow::Error) -> Error {
    Error::Handshake {
        stage: HandshakeStage::Build,
        source,
    }
}

pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    pub fn new(config: HandshakeConfig<'_>) -> Result<Self> {
        // A missing PSK on the pairing pattern would silently downgrade first
        // contact to unauthenticated-until-pinned, which is exactly the hostile
        // relay's opening. Refuse rather than default.
        match (config.pattern, config.psk) {
            (Pattern::Pairing, None) => {
                return Err(Error::HandshakeConfig(
                    "pairing pattern requires the QR pairing secret as PSK",
                ))
            }
            (Pattern::Session, Some(_)) => {
                return Err(Error::HandshakeConfig(
                    "session pattern must not carry a pairing PSK",
                ))
            }
            _ => {}
        }
        if config.role == Role::Initiator && config.remote_static.is_none() {
            return Err(Error::HandshakeConfig(
                "IK initiator requires the responder's static key up front",
            ));
        }

        let params = config
            .pattern
            .params()
            .parse::<snow::params::NoiseParams>()
            .map_err(|_| Error::HandshakeConfig("unparseable noise pattern string"))?;
        let mut builder = Builder::new(params)
            .local_private_key(config.local_static)
            .map_err(build_error)?;
        if let Some(remote) = config.remote_static {
            builder = builder.remote_public_key(remote).map_err(build_error)?;
        }
        if let Some(psk) = config.psk {
            // Position 2: the PSK is mixed in the second handshake message,
            // which is what `IKpsk2` names.
            builder = builder.psk(2, psk.as_bytes()).map_err(build_error)?;
        }
        let state = match config.role {
            Role::Initiator => builder.build_initiator().map_err(build_error)?,
            Role::Responder => builder.build_responder().map_err(build_error)?,
        };
        Ok(Self { state })
    }

    /// Produce the next handshake message carrying `payload`.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|source| Error::Handshake {
                stage: HandshakeStage::Write,
                source,
            })?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume a handshake message, returning its decrypted payload.
    ///
    /// A tampered byte anywhere in `message` surfaces here as
    /// [`HandshakeStage::Read`]. It never panics and it is never silently
    /// tolerated.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(|source| Error::Handshake {
                stage: HandshakeStage::Read,
                source,
            })?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Promote to transport mode, capturing the peer's authenticated static key.
    pub fn into_session(self) -> Result<NoiseSession> {
        let remote = self
            .state
            .get_remote_static()
            .ok_or(Error::MissingRemoteStatic)?;
        let remote_static: [u8; 32] =
            <[u8; 32]>::try_from(remote).map_err(|_| Error::BadKeyLength {
                label: "peer noise static",
                len: remote.len(),
            })?;
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|source| Error::Handshake {
                stage: HandshakeStage::Transport,
                source,
            })?;
        Ok(NoiseSession::new(transport, remote_static))
    }

    /// Run the initiator half of a two-message IK/IKpsk2 handshake over `stream`.
    ///
    /// Returns the session and the responder's decrypted second-message payload.
    pub fn run_initiator<S: Read + Write>(
        mut self,
        stream: &mut S,
        payload: &[u8],
    ) -> Result<(NoiseSession, Vec<u8>)> {
        let msg1 = self.write_message(payload)?;
        write_frame(stream, &msg1)?;
        stream.flush().map_err(Error::Io)?;
        let mut msg2 = Vec::new();
        if read_frame(stream, &mut msg2)? == FrameRead::Eof {
            return Err(Error::TruncatedFrame { got: 0, want: 2 });
        }
        let response = self.read_message(&msg2)?;
        Ok((self.into_session()?, response))
    }

    /// Run the responder half. `reply` is the payload for the second message;
    /// the initiator's first-message payload is returned alongside the session.
    pub fn run_responder<S: Read + Write>(
        mut self,
        stream: &mut S,
        reply: &[u8],
    ) -> Result<(NoiseSession, Vec<u8>)> {
        let mut msg1 = Vec::new();
        if read_frame(stream, &mut msg1)? == FrameRead::Eof {
            return Err(Error::TruncatedFrame { got: 0, want: 2 });
        }
        let request = self.read_message(&msg1)?;
        let msg2 = self.write_message(reply)?;
        write_frame(stream, &msg2)?;
        stream.flush().map_err(Error::Io)?;
        Ok((self.into_session()?, request))
    }
}
