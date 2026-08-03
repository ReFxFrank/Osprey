//! Waiting for a transport to become readable, without consuming from it.
//!
//! The session loop has to wake on a schedule to push metrics while also
//! blocking on the peer's next request. The obvious approach — a short read
//! timeout on the socket — is wrong here: `NoiseSession::recv` reads a whole
//! multi-frame message, so a deadline that expired *between* two chunks would
//! leave the framing permanently desynchronised and the session unrecoverable.
//!
//! So readiness is only ever *observed*. The bytes stay in the socket until
//! `recv` takes the message whole, under the long idle deadline that was
//! already there.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

/// A transport that can be polled for readability with a deadline.
pub trait WaitReadable {
    /// Block for at most `slice`.
    ///
    /// `Ok(true)` means the next read will not block — either data has arrived
    /// or the peer has closed, and the caller distinguishes those by reading.
    /// `Ok(false)` means the slice expired with nothing to read.
    fn wait_readable(&mut self, slice: Duration) -> io::Result<bool>;
}

impl WaitReadable for TcpStream {
    fn wait_readable(&mut self, slice: Duration) -> io::Result<bool> {
        let previous = self.read_timeout()?;
        self.set_read_timeout(Some(slice))?;

        let mut probe = [0u8; 1];
        // `peek` leaves the byte in the socket buffer, which is the whole point:
        // whatever arrives is still there for `recv` to frame correctly.
        let outcome = match self.peek(&mut probe) {
            Ok(_) => Ok(true),
            Err(err) if is_timeout(err.kind()) => Ok(false),
            Err(err) => Err(err),
        };

        // Restored before returning either way, so the session's long idle
        // deadline governs the actual message read rather than the tick slice.
        self.set_read_timeout(previous)?;
        outcome
    }
}

/// A socket receive deadline surfaces differently per platform: Windows reports
/// `TimedOut`, Unix `WouldBlock`. Both mean the same thing here.
fn is_timeout(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream as Stream};
    use std::time::Instant;

    fn connected_pair() -> (Stream, Stream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = Stream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    #[test]
    fn an_idle_socket_reports_not_readable_after_the_slice() {
        let (mut client, _server) = connected_pair();
        let started = Instant::now();
        let readable = client
            .wait_readable(Duration::from_millis(150))
            .expect("wait");
        assert!(!readable, "nothing was sent, so nothing can be readable");
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "returned too early to have waited the slice"
        );
    }

    #[test]
    fn pending_data_is_reported_and_left_in_the_socket() {
        let (mut client, mut server) = connected_pair();
        server.write_all(b"hello").expect("write");
        server.flush().expect("flush");

        assert!(
            client
                .wait_readable(Duration::from_secs(2))
                .expect("wait"),
            "written bytes must show as readable"
        );

        // The bytes must still be there — consuming them in the probe would
        // eat the first byte of a Noise frame.
        let mut buf = [0u8; 5];
        std::io::Read::read_exact(&mut client, &mut buf).expect("read");
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn a_closed_peer_reports_readable_so_the_caller_sees_the_eof() {
        let (mut client, server) = connected_pair();
        drop(server);
        assert!(
            client.wait_readable(Duration::from_secs(2)).expect("wait"),
            "a closed peer must wake the loop rather than time out"
        );
    }

    #[test]
    fn the_original_read_timeout_is_restored() {
        let (mut client, _server) = connected_pair();
        let original = Duration::from_secs(300);
        client.set_read_timeout(Some(original)).expect("set");
        let _ = client.wait_readable(Duration::from_millis(50));
        assert_eq!(
            client.read_timeout().expect("get"),
            Some(original),
            "the tick slice leaked into the message read deadline"
        );
    }
}
