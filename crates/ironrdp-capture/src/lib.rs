//! Offline decoding support for RDP packet captures.

mod error;
mod gateway;
mod gateway_rpch;
mod tls;
mod transport;

pub use error::CaptureError;
pub use gateway::{extract_tunneled_rdp, is_gateway_tunnel};
pub use gateway_rpch::{extract_rpch_from_flows, extract_rpch_tunneled_rdp};
pub use tls::{Plaintext, decrypt_tls};
pub use transport::{Capture, Endpoint, Flow, PacketStream, TlsKeyLog, read_capture};

/// Decrypt the RDP plaintext of a capture.
///
/// This unwraps a supported RD Gateway WebSocket or RPC-over-HTTP tunnel before
/// decrypting its inner TLS session.
pub fn decrypt_rdp(capture: &Capture) -> Result<Plaintext, CaptureError> {
    let mut decrypted = Vec::new();
    let mut decrypt_error = None;
    for flow in core::iter::once(&capture.flow).chain(capture.gateway_alternates.iter()) {
        match tls::decrypt_tls_streams(&flow.client_stream, &flow.server_stream, capture.tls_key_log.as_str()) {
            Ok(plaintext) => decrypted.push(plaintext),
            Err(error) => {
                if decrypt_error.is_none() {
                    decrypt_error = Some(error);
                }
            }
        }
    }

    if let Some(outer) = decrypted.iter().find(|plaintext| is_gateway_tunnel(plaintext)) {
        let tunneled = extract_tunneled_rdp(outer)?;
        return decrypt_tunneled_rdp(&tunneled, capture);
    }
    if let Some(tunneled) = extract_rpch_from_flows(&decrypted)? {
        return decrypt_tunneled_rdp(&tunneled, capture);
    }
    if let Some(plaintext) = decrypted.into_iter().next() {
        return Ok(plaintext);
    }

    // INVARIANT: the primary flow is always attempted, so this error is set when no flow was decrypted.
    match decrypt_error {
        Some(error) => Err(error),
        None => unreachable!("capture flow was not decrypted"),
    }
}

fn decrypt_tunneled_rdp(tunneled: &Plaintext, capture: &Capture) -> Result<Plaintext, CaptureError> {
    tls::decrypt_tls_streams(&tunneled.client, &tunneled.server, capture.tls_key_log.as_str()).map_err(|error| {
        if matches!(error, CaptureError::MissingTlsSecret) {
            CaptureError::MissingTunneledTlsSecret
        } else {
            error
        }
    })
}
