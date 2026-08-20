//! Fail-closed native-messaging host primitives for the selected Edge surface.
//!
//! No CORE transport is implemented here yet. In particular, this crate has no
//! raw named-pipe address or bearer credential. A future broker must supply a
//! distinct OS-authenticated browser-producer connection before `read_message`
//! is reachable in the production binary.

use std::fmt;
use std::io::{self, Read};

use stein_platform_windows::{
    BrowserObservationEnvelope, EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES,
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostErrorKind {
    AdmissionUnavailable,
    MalformedFrame,
    OversizeFrame,
    UnexpectedEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostError {
    pub kind: HostErrorKind,
    pub summary: &'static str,
}

impl std::error::Error for HostError {}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.summary)
    }
}

/// Non-forgeable in API shape: there is no public constructor, clone, byte
/// accessor, or serializer. The missing broker will own construction later.
pub struct BrowserProducerConnection {
    _private: (),
}

impl fmt::Debug for BrowserProducerConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserProducerConnection([redacted])")
    }
}

/// Current production behavior. Launch evidence is intentionally insufficient
/// to construct a browser-producer connection.
pub fn connect_os_authenticated_core_ingress() -> Result<BrowserProducerConnection, HostError> {
    Err(error(HostErrorKind::AdmissionUnavailable))
}

pub fn read_message(
    _connection: &BrowserProducerConnection,
    reader: &mut impl Read,
) -> Result<BrowserObservationEnvelope, HostError> {
    let length = read_length(reader)?;
    let mut payload = vec![0_u8; length];
    if let Err(source) = reader.read_exact(&mut payload) {
        payload.zeroize();
        return Err(map_read_error(source));
    }
    let message = decode_payload(&payload);
    payload.zeroize();
    message
}

fn decode_payload(payload: &[u8]) -> Result<BrowserObservationEnvelope, HostError> {
    serde_json::from_slice(payload).map_err(|_| error(HostErrorKind::MalformedFrame))
}

fn read_length(reader: &mut impl Read) -> Result<usize, HostError> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(map_read_error)?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 {
        return Err(error(HostErrorKind::MalformedFrame));
    }
    if length > EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES {
        return Err(error(HostErrorKind::OversizeFrame));
    }
    Ok(length)
}

fn map_read_error(source: io::Error) -> HostError {
    if source.kind() == io::ErrorKind::UnexpectedEof {
        error(HostErrorKind::UnexpectedEnd)
    } else {
        error(HostErrorKind::MalformedFrame)
    }
}

const fn error(kind: HostErrorKind) -> HostError {
    HostError {
        kind,
        summary: "The Edge native-messaging host rejected the input.",
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn fixture_json() -> Vec<u8> {
        br#"{
            "protocol_version":1,
            "authority_epoch":9,
            "sequence":1,
            "profile_binding_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "browser_session_id":"22222222222222222222222222222222",
            "selection_id":"33333333333333333333333333333333",
            "tab_id":41,
            "window_id":7,
            "active":true,
            "window_focused":true,
            "incognito":false,
            "top_frame":true,
            "page_kind":"standard_web_page",
            "site_sha256":"4444444444444444444444444444444444444444444444444444444444444444",
            "origin_sha256":"5555555555555555555555555555555555555555555555555555555555555555",
            "location":{"origin":"https://atlas.example","path":"/research","query":null,"fragment":null},
            "visible_text":null,
            "observed_at_unix_ms":1800000000000
        }"#
        .to_vec()
    }

    fn fixture_connection() -> BrowserProducerConnection {
        BrowserProducerConnection { _private: () }
    }

    #[test]
    fn production_core_ingress_is_explicitly_unavailable() {
        assert_eq!(
            connect_os_authenticated_core_ingress().unwrap_err().kind,
            HostErrorKind::AdmissionUnavailable
        );
    }

    #[test]
    fn bounded_little_endian_frame_decodes_only_after_admission() {
        let payload = fixture_json();
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        let decoded = read_message(&fixture_connection(), &mut Cursor::new(frame)).unwrap();
        assert_eq!(decoded.sequence, 1);
        assert!(!format!("{decoded:?}").contains("atlas.example"));
    }

    #[test]
    fn malformed_oversize_unknown_and_truncated_frames_fail_closed() {
        let mut oversize = ((EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES + 1) as u32)
            .to_le_bytes()
            .to_vec();
        assert_eq!(
            read_message(&fixture_connection(), &mut Cursor::new(&mut oversize))
                .unwrap_err()
                .kind,
            HostErrorKind::OversizeFrame
        );

        let mut truncated = 100_u32.to_le_bytes().to_vec();
        truncated.extend_from_slice(b"{}");
        assert_eq!(
            read_message(&fixture_connection(), &mut Cursor::new(truncated))
                .unwrap_err()
                .kind,
            HostErrorKind::UnexpectedEnd
        );

        let payload = br#"{"protocol_version":1,"unexpected_private_field":"synthetic-secret"}"#;
        let mut unknown = (payload.len() as u32).to_le_bytes().to_vec();
        unknown.extend_from_slice(payload);
        let error = read_message(&fixture_connection(), &mut Cursor::new(unknown)).unwrap_err();
        assert_eq!(error.kind, HostErrorKind::MalformedFrame);
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }

    #[test]
    fn raw_frame_storage_is_explicitly_zeroized_after_decode() {
        let mut payload = fixture_json();
        let decoded = decode_payload(&payload).unwrap();
        payload.zeroize();
        assert!(payload.iter().all(|byte| *byte == 0));
        assert!(!format!("{decoded:?}").contains("atlas.example"));
    }
}
