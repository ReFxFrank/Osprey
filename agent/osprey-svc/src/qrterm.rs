//! Rendering the pairing QR into a terminal.
//!
//! The QR has to be photographed off the host's own screen — that is what makes
//! "physical access is required to enrol a controller" (brief §6.1) a property
//! of the system rather than a promise. P1 draws it in the tray helper's window;
//! P0 has only a console, so it is drawn with Unicode half-block characters,
//! two module rows per text row (execution plan §2 #5).

use anyhow::{Context, Result};
use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};

/// Terminal columns a rendered code needs, including its quiet zone.
pub fn width_in_columns(rendered: &str) -> usize {
    rendered
        .lines()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0)
}

/// Render `payload` as half-block text.
///
/// Error correction is fixed at the lowest level on purpose. The payload
/// approaches 600 bytes and a phone camera held 30 cm from a monitor has no
/// meaningful error rate; spending capacity on redundancy instead buys a larger
/// symbol, and a symbol wider than the terminal cannot be scanned at all.
pub fn render(payload: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(payload, EcLevel::L).with_context(|| {
        format!(
            "pairing payload of {} bytes does not fit in a QR symbol",
            payload.len()
        )
    })?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_half_blocks_with_a_quiet_zone() {
        let rendered = render("osprey-test-payload").expect("render");
        assert!(rendered.lines().count() > 8);
        assert!(rendered.contains('█'));
        // A quiet zone means the first row is blank rather than module data.
        let first = rendered.lines().next().expect("a first line");
        assert!(!first.contains('█'), "expected a blank quiet-zone row");
    }

    #[test]
    fn a_realistic_pairing_payload_fits_a_terminal() {
        // Roughly the size of a QrPayload: two 32-byte keys, a 64-byte
        // signature and a 32-byte secret, all hex, plus urls and ids.
        let payload = "x".repeat(640);
        let rendered = render(&payload).expect("render");
        assert!(
            width_in_columns(&rendered) <= 120,
            "rendered {} columns wide",
            width_in_columns(&rendered)
        );
    }

    #[test]
    fn an_oversized_payload_is_an_error_not_a_panic() {
        let payload = "x".repeat(8000);
        assert!(render(&payload).is_err());
    }
}
