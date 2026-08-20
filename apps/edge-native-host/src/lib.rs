//! Fail-closed native-messaging host primitives for the selected Edge surface.
//!
//! The production transport is a distinct, one-way producer pipe. It can send
//! only bounded native-messaging values and receive one typed capture plan; it
//! has no CORE private-client protocol, bearer credential, or state-query API.

use std::fmt;
use std::io::{self, Read};
#[cfg(windows)]
use std::{os::windows::io::AsHandle, time::Duration};

#[cfg(windows)]
use stein_broker_windows::{ExpectedCoreServer, current_process_user_sid, verify_core_pipe_server};
use stein_platform_windows::{
    BrowserObservationEnvelope, EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES,
    EDGE_BROWSER_PRODUCER_PIPE, EdgeBrowserCapturePlan, EdgeBrowserSelectionOffer,
    EdgeBrowserSourceStatus,
};
#[cfg(windows)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    time::sleep,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostErrorKind {
    AdmissionUnavailable,
    MalformedFrame,
    OversizeFrame,
    UnexpectedEnd,
    WriteFailed,
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

/// Non-forgeable in API shape: there is no public constructor, clone, raw
/// handle accessor, address override, or serializer.
pub struct BrowserProducerConnection {
    #[cfg(windows)]
    pipe: Option<NamedPipeClient>,
    #[cfg(not(windows))]
    _private: (),
}

impl fmt::Debug for BrowserProducerConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserProducerConnection([redacted])")
    }
}

/// Connects only to the fixed browser-producer endpoint and verifies the exact
/// signed CORE image before a native-message byte is forwarded.
#[cfg(windows)]
pub async fn connect_os_authenticated_core_ingress(
    core_executable_sha256: [u8; 32],
) -> Result<BrowserProducerConnection, HostError> {
    let owner_sid = current_process_user_sid().map_err(|_| admission_unavailable())?;
    let expected = ExpectedCoreServer::new(owner_sid, core_executable_sha256)
        .map_err(|_| admission_unavailable())?;
    let started = tokio::time::Instant::now();
    loop {
        match ClientOptions::new().open(EDGE_BROWSER_PRODUCER_PIPE) {
            Ok(pipe) => {
                verify_core_pipe_server(pipe.as_handle(), &expected)
                    .map_err(|_| admission_unavailable())?;
                return Ok(BrowserProducerConnection { pipe: Some(pipe) });
            }
            Err(source)
                if transient_connect_error(&source)
                    && started.elapsed() < Duration::from_secs(3) =>
            {
                sleep(Duration::from_millis(75)).await;
            }
            Err(_) => return Err(admission_unavailable()),
        }
    }
}

#[cfg(not(windows))]
pub async fn connect_os_authenticated_core_ingress(
    _core_executable_sha256: [u8; 32],
) -> Result<BrowserProducerConnection, HostError> {
    Err(admission_unavailable())
}

/// Runs the narrow native-messaging bridge. The only CORE-to-extension value
/// is one validated capture plan; all subsequent traffic is producer-to-CORE.
#[cfg(windows)]
pub async fn run_producer_bridge(
    connection: &mut BrowserProducerConnection,
    reader: &mut impl Read,
    writer: &mut impl io::Write,
    expected_extension_id: &str,
    expected_extension_version: &str,
) -> Result<(), HostError> {
    let pipe = connection.pipe.as_mut().ok_or_else(admission_unavailable)?;
    let offer_payload = read_frame(reader)?;
    let offer: EdgeBrowserSelectionOffer =
        serde_json::from_slice(&offer_payload).map_err(|_| error(HostErrorKind::MalformedFrame))?;
    offer
        .into_initial_location_binding(expected_extension_id, expected_extension_version)
        .map_err(|_| error(HostErrorKind::MalformedFrame))?;
    write_pipe_frame(pipe, &offer_payload).await?;

    let plan_payload = read_pipe_frame(pipe).await?;
    let plan: EdgeBrowserCapturePlan =
        serde_json::from_slice(&plan_payload).map_err(|_| error(HostErrorKind::MalformedFrame))?;
    plan.validate_for_release(expected_extension_id, expected_extension_version)
        .map_err(|_| error(HostErrorKind::MalformedFrame))?;
    write_frame(writer, &plan_payload)?;

    loop {
        let Some(payload) = read_optional_frame(reader)? else {
            return Ok(());
        };
        if !strict_producer_value(&payload) {
            return Err(error(HostErrorKind::MalformedFrame));
        }
        write_pipe_frame(pipe, &payload).await?;
    }
}

pub fn read_message(
    _connection: &BrowserProducerConnection,
    reader: &mut impl Read,
) -> Result<BrowserObservationEnvelope, HostError> {
    let payload = read_frame(reader)?;
    decode_payload(&payload)
}

fn read_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, HostError> {
    let length = read_length(reader)?;
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    if let Err(source) = reader.read_exact(&mut payload) {
        return Err(map_read_error(source));
    }
    Ok(payload)
}

fn read_optional_frame(reader: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>, HostError> {
    let mut prefix = [0_u8; 4];
    match reader.read(&mut prefix[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("the requested read is one byte"),
        Err(source) => return Err(map_read_error(source)),
    }
    reader
        .read_exact(&mut prefix[1..])
        .map_err(map_read_error)?;
    let length = bounded_prefix(prefix)?;
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    reader.read_exact(&mut payload).map_err(map_read_error)?;
    Ok(Some(payload))
}

fn write_frame(writer: &mut impl io::Write, payload: &[u8]) -> Result<(), HostError> {
    let length = bounded_length(payload)?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(|_| error(HostErrorKind::WriteFailed))
}

#[cfg(windows)]
async fn read_pipe_frame(pipe: &mut NamedPipeClient) -> Result<Zeroizing<Vec<u8>>, HostError> {
    let mut prefix = [0_u8; 4];
    pipe.read_exact(&mut prefix)
        .await
        .map_err(|_| admission_unavailable())?;
    let length = bounded_prefix(prefix)?;
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    pipe.read_exact(&mut payload)
        .await
        .map_err(|_| admission_unavailable())?;
    Ok(payload)
}

#[cfg(windows)]
async fn write_pipe_frame(pipe: &mut NamedPipeClient, payload: &[u8]) -> Result<(), HostError> {
    let length = bounded_length(payload)?;
    pipe.write_all(&length.to_le_bytes())
        .await
        .map_err(|_| admission_unavailable())?;
    pipe.write_all(payload)
        .await
        .map_err(|_| admission_unavailable())?;
    pipe.flush().await.map_err(|_| admission_unavailable())
}

fn strict_producer_value(payload: &[u8]) -> bool {
    serde_json::from_slice::<BrowserObservationEnvelope>(payload).is_ok()
        || serde_json::from_slice::<EdgeBrowserSourceStatus>(payload).is_ok()
}

fn decode_payload(payload: &[u8]) -> Result<BrowserObservationEnvelope, HostError> {
    serde_json::from_slice(payload).map_err(|_| error(HostErrorKind::MalformedFrame))
}

fn read_length(reader: &mut impl Read) -> Result<usize, HostError> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(map_read_error)?;
    bounded_prefix(prefix)
}

fn bounded_prefix(prefix: [u8; 4]) -> Result<usize, HostError> {
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 {
        return Err(error(HostErrorKind::MalformedFrame));
    }
    if length > EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES {
        return Err(error(HostErrorKind::OversizeFrame));
    }
    Ok(length)
}

fn bounded_length(payload: &[u8]) -> Result<u32, HostError> {
    u32::try_from(payload.len())
        .ok()
        .filter(|length| {
            *length > 0 && *length as usize <= EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES
        })
        .ok_or_else(|| error(HostErrorKind::OversizeFrame))
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

const fn admission_unavailable() -> HostError {
    error(HostErrorKind::AdmissionUnavailable)
}

#[cfg(windows)]
fn transient_connect_error(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) || source.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
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
        BrowserProducerConnection {
            #[cfg(windows)]
            pipe: None,
            #[cfg(not(windows))]
            _private: (),
        }
    }

    #[test]
    fn connection_debug_is_content_free() {
        assert_eq!(
            format!("{:?}", fixture_connection()),
            "BrowserProducerConnection([redacted])"
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
    fn producer_stream_accepts_only_clean_boundary_eof() {
        assert!(
            read_optional_frame(&mut Cursor::new(Vec::<u8>::new()))
                .unwrap()
                .is_none()
        );

        let partial_prefix = vec![1_u8, 0];
        assert_eq!(
            read_optional_frame(&mut Cursor::new(partial_prefix))
                .unwrap_err()
                .kind,
            HostErrorKind::UnexpectedEnd
        );

        let mut partial_payload = 10_u32.to_le_bytes().to_vec();
        partial_payload.extend_from_slice(b"{}");
        assert_eq!(
            read_optional_frame(&mut Cursor::new(partial_payload))
                .unwrap_err()
                .kind,
            HostErrorKind::UnexpectedEnd
        );
    }

    #[test]
    fn producer_role_rejects_unknown_private_commands() {
        let private_command = br#"{"kind":"query_owner_state","private_value":"synthetic-secret"}"#;
        assert!(!strict_producer_value(private_command));

        let status = br#"{
            "protocol_version":1,
            "kind":"source_status",
            "authority_epoch":9,
            "selection_id":"33333333333333333333333333333333",
            "state":"paused",
            "reason":"paused_background"
        }"#;
        assert!(strict_producer_value(status));
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
