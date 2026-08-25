//! Closed one-way ingress contract for an authenticated Edge producer.
//!
//! Production admission owns the fixed named-pipe server and the exact
//! PFN/AUMID peer proof for the whole connection. Edge Add-ons provenance and
//! direct-launch package identity still require an installed fixture, so caller
//! origin, ancestry, or Authenticode evidence alone never makes the host a CORE
//! client or turns production capability health on.

use std::fmt;
#[cfg(windows)]
use std::{ffi::c_void, os::windows::io::AsHandle, time::Instant};

#[cfg(windows)]
use stein_broker_windows::{
    ConnectionAuthority, ExpectedPackageIdentity, PackagePeerClass, PrivatePipeSecurity,
    admit_named_pipe_peer,
};
use stein_core::{
    BrowserLocationGranularity, DeviceId, FocusSessionId, PermissionGrantId, ResourceId,
};
#[cfg(windows)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};
#[cfg(windows)]
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
#[cfg(windows)]
use zeroize::Zeroizing;

use crate::BrowserValidationOutcome;
use crate::{
    BrowserCaptureCancellation, BrowserIngressError, BrowserObservationEnvelope,
    BrowserObservationPacket, BrowserObservationValidator, EdgeBrowserCapturePlan,
    EdgeBrowserCapturePolicy, EdgeBrowserSelectionOffer, EdgeBrowserSourcePauseReason,
    EdgeBrowserSourceStatus, WindowsBrowserSurfaceBinding,
};

pub const EDGE_BROWSER_PRODUCER_APPLICATION_ID: &str = "BrowserObservationProducer";
pub const EDGE_BROWSER_PRODUCER_PIPE: &str =
    r"\\.\pipe\LOCAL\stein-browser-observation-producer-v1";
pub const EDGE_BROWSER_PRODUCER_SOURCE_ID: &str = "windows.edge.selected_surface";
pub const EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON: &str =
    "Published Edge Add-ons provenance and direct-launch package identity are not verified.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserProducerIngressErrorKind {
    AdmissionUnavailable,
    ConnectionChanged,
    AuthorityUnavailable,
    AuthorityChanged,
    PacketRejected,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserProducerIngressError {
    pub kind: BrowserProducerIngressErrorKind,
    pub summary: &'static str,
}

impl std::error::Error for BrowserProducerIngressError {}

impl fmt::Display for BrowserProducerIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.summary)
    }
}

/// Immutable selection identity issued by CORE after explicit approval.
///
/// These values are never accepted from a browser packet. The daemon adapter
/// builds this reference from its authenticated owner snapshot and capture
/// plan, then the reloader proves the exact values are still current for every
/// packet.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserProducerAuthorityReference {
    session_id: FocusSessionId,
    session_revision: u64,
    grant_id: PermissionGrantId,
    grant_revision: u64,
    resource_id: ResourceId,
    resource_revision: u64,
    device_id: DeviceId,
    policy: EdgeBrowserCapturePolicy,
}

impl fmt::Debug for BrowserProducerAuthorityReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserProducerAuthorityReference")
            .field("session_revision", &self.session_revision)
            .field("grant_revision", &self.grant_revision)
            .field("resource_revision", &self.resource_revision)
            .finish_non_exhaustive()
    }
}

impl BrowserProducerAuthorityReference {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: FocusSessionId,
        session_revision: u64,
        grant_id: PermissionGrantId,
        grant_revision: u64,
        resource_id: ResourceId,
        resource_revision: u64,
        device_id: DeviceId,
        policy: EdgeBrowserCapturePolicy,
    ) -> Result<Self, BrowserProducerIngressError> {
        if session_id.as_uuid().is_nil()
            || grant_id.as_uuid().is_nil()
            || resource_id.as_uuid().is_nil()
            || device_id.as_uuid().is_nil()
            || session_revision == 0
            || grant_revision == 0
            || resource_revision == 0
            || policy.validate().is_err()
        {
            return Err(authority_changed());
        }
        Ok(Self {
            session_id,
            session_revision,
            grant_id,
            grant_revision,
            resource_id,
            resource_revision,
            device_id,
            policy,
        })
    }

    pub const fn session_id(&self) -> FocusSessionId {
        self.session_id
    }

    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub const fn grant_id(&self) -> PermissionGrantId {
        self.grant_id
    }

    pub const fn grant_revision(&self) -> u64 {
        self.grant_revision
    }

    pub const fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    pub const fn resource_revision(&self) -> u64 {
        self.resource_revision
    }

    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub const fn policy(&self) -> &EdgeBrowserCapturePolicy {
        &self.policy
    }
}

/// Fresh result of one authenticated owner-state reload.
///
/// The daemon implementation must obtain this by calling
/// `SecondMindRuntime::owner_state_snapshot(PrivateCapabilityBound, owner)` and
/// filtering one active session, current exact-scope grant, BrowserSurface
/// resource, and their current revisions. It must not return a cached value.
#[derive(Clone, Eq, PartialEq)]
pub struct CurrentBrowserProducerAuthority {
    session_id: FocusSessionId,
    session_revision: u64,
    grant_id: PermissionGrantId,
    grant_revision: u64,
    resource_id: ResourceId,
    resource_revision: u64,
    device_id: DeviceId,
    policy: EdgeBrowserCapturePolicy,
}

impl fmt::Debug for CurrentBrowserProducerAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentBrowserProducerAuthority")
            .field("session_revision", &self.session_revision)
            .field("grant_revision", &self.grant_revision)
            .field("resource_revision", &self.resource_revision)
            .finish_non_exhaustive()
    }
}

impl CurrentBrowserProducerAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: FocusSessionId,
        session_revision: u64,
        grant_id: PermissionGrantId,
        grant_revision: u64,
        resource_id: ResourceId,
        resource_revision: u64,
        device_id: DeviceId,
        policy: EdgeBrowserCapturePolicy,
    ) -> Result<Self, BrowserProducerIngressError> {
        BrowserProducerAuthorityReference::new(
            session_id,
            session_revision,
            grant_id,
            grant_revision,
            resource_id,
            resource_revision,
            device_id,
            policy.clone(),
        )?;
        Ok(Self {
            session_id,
            session_revision,
            grant_id,
            grant_revision,
            resource_id,
            resource_revision,
            device_id,
            policy,
        })
    }

    fn matches(&self, expected: &BrowserProducerAuthorityReference) -> bool {
        self.session_id == expected.session_id
            && self.session_revision == expected.session_revision
            && self.grant_id == expected.grant_id
            && self.grant_revision == expected.grant_revision
            && self.resource_id == expected.resource_id
            && self.resource_revision == expected.resource_revision
            && self.device_id == expected.device_id
            && self.policy == expected.policy
    }
}

/// Daemon-side adapter that reloads current durable authority for every value.
///
/// `reference` is connection state created by CORE, not a wire claim. A load
/// error, inactive/recovering/stopping session, revoked/expired/superseded
/// grant, resource deletion/revision change, owner/device mismatch, or scope
/// mismatch must return a content-free error.
pub trait BrowserAuthoritySnapshotPort: Send + Sync {
    fn reload_current(
        &self,
        reference: &BrowserProducerAuthorityReference,
        received_at_unix_ms: i64,
    ) -> Result<CurrentBrowserProducerAuthority, BrowserProducerIngressError>;
}

/// Opaque owner of one admitted kernel connection.
///
/// The pipe object and OS-produced admission proof move together into this
/// value. No caller can substitute a numeric handle after admission, and drop
/// closes the exact connection before its authority disappears.
pub struct BrowserProducerConnectionAuthority {
    inner: BrowserProducerConnectionInner,
}

enum BrowserProducerConnectionInner {
    #[cfg(windows)]
    Owned {
        pipe: NamedPipeServer,
        _authority: ConnectionAuthority,
        _daemon_instance: [u8; 16],
    },
    #[cfg(test)]
    Synthetic,
}

impl fmt::Debug for BrowserProducerConnectionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserProducerConnectionAuthority([redacted])")
    }
}

impl BrowserProducerConnectionAuthority {
    #[cfg(test)]
    fn synthetic() -> Self {
        Self {
            inner: BrowserProducerConnectionInner::Synthetic,
        }
    }

    #[cfg(windows)]
    fn pipe_mut(&mut self) -> Result<&mut NamedPipeServer, BrowserProducerIngressError> {
        match &mut self.inner {
            BrowserProducerConnectionInner::Owned { pipe, .. } => Ok(pipe),
            #[cfg(test)]
            BrowserProducerConnectionInner::Synthetic => {
                Err(error(BrowserProducerIngressErrorKind::ConnectionChanged))
            }
        }
    }

    #[cfg(windows)]
    pub async fn read_selection_offer(
        &mut self,
        expected_extension_id: &str,
        expected_extension_version: &str,
        granularity: BrowserLocationGranularity,
    ) -> Result<WindowsBrowserSurfaceBinding, BrowserProducerIngressError> {
        let payload = read_frame(self.pipe_mut()?).await?;
        let offer: EdgeBrowserSelectionOffer = serde_json::from_slice(&payload)
            .map_err(|_| error(BrowserProducerIngressErrorKind::PacketRejected))?;
        offer
            .into_binding(
                expected_extension_id,
                expected_extension_version,
                granularity,
            )
            .map_err(packet_rejected)
    }

    #[cfg(windows)]
    async fn read_message(
        &mut self,
    ) -> Result<BrowserProducerMessage, BrowserProducerIngressError> {
        let payload = read_frame(self.pipe_mut()?).await?;
        if let Ok(observation) = serde_json::from_slice(&payload) {
            return Ok(BrowserProducerMessage::Observation(Box::new(observation)));
        }
        serde_json::from_slice(&payload)
            .map(BrowserProducerMessage::SourceStatus)
            .map_err(|_| error(BrowserProducerIngressErrorKind::PacketRejected))
    }

    #[cfg(windows)]
    async fn write_capture_plan(
        &mut self,
        plan: &EdgeBrowserCapturePlan,
    ) -> Result<(), BrowserProducerIngressError> {
        let payload = Zeroizing::new(
            serde_json::to_vec(plan)
                .map_err(|_| error(BrowserProducerIngressErrorKind::PacketRejected))?,
        );
        write_frame(self.pipe_mut()?, &payload).await
    }
}

#[cfg(windows)]
pub struct BrowserProducerListener {
    expected: ExpectedPackageIdentity,
    daemon_instance: [u8; 16],
}

#[cfg(windows)]
impl BrowserProducerListener {
    pub fn new(
        expected: ExpectedPackageIdentity,
        daemon_instance: [u8; 16],
    ) -> Result<Self, BrowserProducerIngressError> {
        if daemon_instance.iter().all(|byte| *byte == 0) {
            return Err(error(BrowserProducerIngressErrorKind::AdmissionUnavailable));
        }
        Ok(Self {
            expected,
            daemon_instance,
        })
    }

    /// Accepts exactly one package-admitted producer. A fresh kernel pipe
    /// object is created for each connection; the returned owner closes it.
    pub async fn accept(
        &self,
    ) -> Result<BrowserProducerConnectionAuthority, BrowserProducerIngressError> {
        let pipe = {
            let security = PrivatePipeSecurity::new(&self.expected)
                .map_err(|_| error(BrowserProducerIngressErrorKind::AdmissionUnavailable))?;
            let mut attributes: SECURITY_ATTRIBUTES = security.attributes();
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(true)
                .max_instances(1)
                .reject_remote_clients(true)
                .in_buffer_size(crate::EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES as u32)
                .out_buffer_size(crate::EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES as u32);
            // SAFETY: the descriptor and attributes remain live through this
            // synchronous CreateNamedPipe call. Windows copies the descriptor.
            unsafe {
                options.create_with_security_attributes_raw(
                    EDGE_BROWSER_PRODUCER_PIPE,
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
                )
            }
            .map_err(|_| error(BrowserProducerIngressErrorKind::AdmissionUnavailable))?
        };
        pipe.connect()
            .await
            .map_err(|_| error(BrowserProducerIngressErrorKind::AdmissionUnavailable))?;
        admit_release_managed_edge_producer(
            pipe,
            &self.expected,
            self.daemon_instance,
            Instant::now() + std::time::Duration::from_secs(5),
        )
    }
}

/// Admits only the exact packaged browser-producer identity and consumes the
/// connected server endpoint so pipe ownership cannot be separated from the
/// opaque authority proof.
#[cfg(windows)]
pub fn admit_release_managed_edge_producer(
    pipe: NamedPipeServer,
    expected: &ExpectedPackageIdentity,
    daemon_instance: [u8; 16],
    expires_at: Instant,
) -> Result<BrowserProducerConnectionAuthority, BrowserProducerIngressError> {
    let authority = admit_named_pipe_peer(
        pipe.as_handle(),
        expected,
        PackagePeerClass::BrowserObservationProducer,
        daemon_instance,
        expires_at,
    )
    .map_err(|_| error(BrowserProducerIngressErrorKind::AdmissionUnavailable))?;
    if !authority.is_current_for(pipe.as_handle(), &daemon_instance, Instant::now()) {
        return Err(error(BrowserProducerIngressErrorKind::ConnectionChanged));
    }
    Ok(BrowserProducerConnectionAuthority {
        inner: BrowserProducerConnectionInner::Owned {
            pipe,
            _authority: authority,
            _daemon_instance: daemon_instance,
        },
    })
}

#[cfg(windows)]
enum BrowserProducerMessage {
    Observation(Box<crate::BrowserObservationEnvelope>),
    SourceStatus(EdgeBrowserSourceStatus),
}

pub enum BrowserProducerIngressEvent {
    Observation(Option<AuthorizedBrowserObservation>),
    SourcePaused(EdgeBrowserSourcePauseReason),
}

pub struct AuthorizedBrowserObservation {
    pub session_id: FocusSessionId,
    pub session_revision: u64,
    pub grant_id: PermissionGrantId,
    pub grant_revision: u64,
    pub resource_id: ResourceId,
    pub resource_revision: u64,
    pub device_id: DeviceId,
    pub packet: BrowserObservationPacket,
}

impl fmt::Debug for AuthorizedBrowserObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedBrowserObservation")
            .field("session_revision", &self.session_revision)
            .field("grant_revision", &self.grant_revision)
            .field("resource_revision", &self.resource_revision)
            .field("packet", &self.packet)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct BrowserObservationProducerIngress<R> {
    connection: BrowserProducerConnectionAuthority,
    reference: BrowserProducerAuthorityReference,
    authority: R,
    validator: BrowserObservationValidator,
}

impl<R: BrowserAuthoritySnapshotPort> BrowserObservationProducerIngress<R> {
    pub fn new(
        connection: BrowserProducerConnectionAuthority,
        reference: BrowserProducerAuthorityReference,
        authority: R,
    ) -> Result<Self, BrowserProducerIngressError> {
        let validator =
            BrowserObservationValidator::new(reference.policy.clone()).map_err(packet_rejected)?;
        Ok(Self {
            connection,
            reference,
            authority,
            validator,
        })
    }

    fn ingest(
        &mut self,
        envelope: BrowserObservationEnvelope,
        received_at_unix_ms: i64,
    ) -> Result<Option<AuthorizedBrowserObservation>, BrowserProducerIngressError> {
        let current = self
            .authority
            .reload_current(&self.reference, received_at_unix_ms)
            .map_err(|_| {
                self.validator.cancel(BrowserCaptureCancellation::Revoked);
                error(BrowserProducerIngressErrorKind::AuthorityUnavailable)
            })?;
        if !current.matches(&self.reference) {
            self.validator.cancel(BrowserCaptureCancellation::Revoked);
            return Err(authority_changed());
        }
        match self
            .validator
            .ingest(envelope, received_at_unix_ms)
            .map_err(packet_rejected)?
        {
            BrowserValidationOutcome::Coalesced => Ok(None),
            BrowserValidationOutcome::Emit(packet) => Ok(Some(AuthorizedBrowserObservation {
                session_id: current.session_id,
                session_revision: current.session_revision,
                grant_id: current.grant_id,
                grant_revision: current.grant_revision,
                resource_id: current.resource_id,
                resource_revision: current.resource_revision,
                device_id: current.device_id,
                packet,
            })),
        }
    }

    #[cfg(windows)]
    pub async fn send_capture_plan(
        &mut self,
        plan: &EdgeBrowserCapturePlan,
    ) -> Result<(), BrowserProducerIngressError> {
        if plan.authority_epoch != self.reference.policy.authority_epoch {
            return Err(error(BrowserProducerIngressErrorKind::AuthorityChanged));
        }
        self.connection.write_capture_plan(plan).await
    }

    #[cfg(windows)]
    pub async fn receive(
        &mut self,
        received_at_unix_ms: i64,
    ) -> Result<BrowserProducerIngressEvent, BrowserProducerIngressError> {
        match self.connection.read_message().await? {
            BrowserProducerMessage::Observation(envelope) => self
                .ingest(*envelope, received_at_unix_ms)
                .map(BrowserProducerIngressEvent::Observation),
            BrowserProducerMessage::SourceStatus(status) => {
                status
                    .validate(&self.reference.policy)
                    .map_err(packet_rejected)?;
                Ok(BrowserProducerIngressEvent::SourcePaused(status.reason))
            }
        }
    }

    pub fn cancel(&mut self, reason: BrowserCaptureCancellation) {
        self.validator.cancel(reason);
    }
}

#[cfg(windows)]
async fn read_frame(
    pipe: &mut NamedPipeServer,
) -> Result<Zeroizing<Vec<u8>>, BrowserProducerIngressError> {
    let mut prefix = [0_u8; 4];
    pipe.read_exact(&mut prefix)
        .await
        .map_err(|_| error(BrowserProducerIngressErrorKind::ConnectionChanged))?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 || length > crate::EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES {
        return Err(error(BrowserProducerIngressErrorKind::PacketRejected));
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    pipe.read_exact(&mut payload)
        .await
        .map_err(|_| error(BrowserProducerIngressErrorKind::ConnectionChanged))?;
    Ok(payload)
}

#[cfg(windows)]
async fn write_frame(
    pipe: &mut NamedPipeServer,
    payload: &[u8],
) -> Result<(), BrowserProducerIngressError> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|length| {
            *length > 0 && *length as usize <= crate::EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES
        })
        .ok_or_else(|| error(BrowserProducerIngressErrorKind::PacketRejected))?;
    pipe.write_all(&length.to_le_bytes())
        .await
        .map_err(|_| error(BrowserProducerIngressErrorKind::ConnectionChanged))?;
    pipe.write_all(payload)
        .await
        .map_err(|_| error(BrowserProducerIngressErrorKind::ConnectionChanged))?;
    pipe.flush()
        .await
        .map_err(|_| error(BrowserProducerIngressErrorKind::ConnectionChanged))
}

fn packet_rejected(error: BrowserIngressError) -> BrowserProducerIngressError {
    if error.kind == crate::BrowserIngressErrorKind::Cancelled {
        self::error(BrowserProducerIngressErrorKind::Cancelled)
    } else {
        self::error(BrowserProducerIngressErrorKind::PacketRejected)
    }
}

const fn authority_changed() -> BrowserProducerIngressError {
    BrowserProducerIngressError {
        kind: BrowserProducerIngressErrorKind::AuthorityChanged,
        summary: "The current browser observation authority no longer matches the selection.",
    }
}

const fn error(kind: BrowserProducerIngressErrorKind) -> BrowserProducerIngressError {
    BrowserProducerIngressError {
        kind,
        summary: "The Edge browser producer ingress rejected the value.",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use stein_core::BrowserLocationGranularity;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        BrowserCaptureScope, BrowserLocationFields, BrowserPageKind, EdgeBrowserSelection,
        WindowsBrowserSurfaceBinding,
    };

    const NOW: i64 = 1_800_000_000_000;

    #[derive(Clone)]
    struct FakeAuthority {
        state: Arc<Mutex<FakeState>>,
    }

    struct FakeState {
        reloads: usize,
        current: Result<CurrentBrowserProducerAuthority, BrowserProducerIngressError>,
    }

    impl BrowserAuthoritySnapshotPort for FakeAuthority {
        fn reload_current(
            &self,
            _reference: &BrowserProducerAuthorityReference,
            _received_at_unix_ms: i64,
        ) -> Result<CurrentBrowserProducerAuthority, BrowserProducerIngressError> {
            let mut state = self.state.lock().unwrap();
            state.reloads += 1;
            state.current.clone()
        }
    }

    fn policy() -> EdgeBrowserCapturePolicy {
        let selection = EdgeBrowserSelection::new(
            [0x11; 32],
            [0x22; 16],
            [0x33; 16],
            41,
            7,
            "atlas.example",
            "https://atlas.example",
            BrowserLocationGranularity {
                origin: true,
                path: true,
                query: false,
                fragment: false,
            },
        )
        .unwrap();
        EdgeBrowserCapturePolicy {
            binding: WindowsBrowserSurfaceBinding::from_selection(&selection),
            scope: BrowserCaptureScope::Location,
            authority_epoch: 9,
            maximum_payload_bytes: 2 * 1024,
            minimum_interval: Duration::from_secs(5),
        }
    }

    fn ids() -> (FocusSessionId, PermissionGrantId, ResourceId, DeviceId) {
        (
            FocusSessionId::new_v7(),
            PermissionGrantId::new_v7(),
            ResourceId::new_v7(),
            DeviceId::new_v7(),
        )
    }

    fn reference() -> BrowserProducerAuthorityReference {
        let (session, grant, resource, device) = ids();
        BrowserProducerAuthorityReference::new(session, 3, grant, 5, resource, 7, device, policy())
            .unwrap()
    }

    fn current(reference: &BrowserProducerAuthorityReference) -> CurrentBrowserProducerAuthority {
        CurrentBrowserProducerAuthority::new(
            reference.session_id,
            reference.session_revision,
            reference.grant_id,
            reference.grant_revision,
            reference.resource_id,
            reference.resource_revision,
            reference.device_id,
            reference.policy.clone(),
        )
        .unwrap()
    }

    fn envelope(sequence: u64) -> BrowserObservationEnvelope {
        fn hex(value: u8, bytes: usize) -> Zeroizing<String> {
            std::iter::repeat_n(format!("{value:02x}"), bytes)
                .collect::<String>()
                .into()
        }
        use sha2::{Digest, Sha256};
        let site: [u8; 32] = Sha256::digest(b"atlas.example").into();
        let origin: [u8; 32] = Sha256::digest(b"https://atlas.example").into();
        BrowserObservationEnvelope {
            protocol_version: 1,
            authority_epoch: 9,
            sequence,
            profile_binding_sha256: hex(0x11, 32),
            browser_session_id: hex(0x22, 16),
            selection_id: hex(0x33, 16),
            tab_id: 41,
            window_id: 7,
            active: true,
            window_focused: true,
            incognito: false,
            top_frame: true,
            page_kind: BrowserPageKind::StandardWebPage,
            site_sha256: site
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .into(),
            origin_sha256: origin
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .into(),
            location: Some(BrowserLocationFields {
                origin: Some("https://atlas.example".to_owned().into()),
                path: Some("/research".to_owned().into()),
                query: None,
                fragment: None,
            }),
            visible_text: None,
            observed_at_unix_ms: NOW,
        }
    }

    fn ingress(
        reference: BrowserProducerAuthorityReference,
    ) -> (
        BrowserObservationProducerIngress<FakeAuthority>,
        Arc<Mutex<FakeState>>,
    ) {
        let state = Arc::new(Mutex::new(FakeState {
            reloads: 0,
            current: Ok(current(&reference)),
        }));
        let ingress = BrowserObservationProducerIngress::new(
            BrowserProducerConnectionAuthority::synthetic(),
            reference,
            FakeAuthority {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        (ingress, state)
    }

    #[test]
    fn unavailable_reason_retains_the_external_installed_fixture_gate() {
        assert!(!EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON.is_empty());
    }

    #[test]
    fn fresh_authority_is_required_for_every_packet() {
        let (mut ingress, state) = ingress(reference());
        let first = ingress.ingest(envelope(1), NOW).unwrap();
        assert!(first.is_some());
        assert_eq!(state.lock().unwrap().reloads, 1);
        assert!(ingress.ingest(envelope(2), NOW + 5_000).unwrap().is_some());
        assert_eq!(state.lock().unwrap().reloads, 2);
    }

    #[test]
    fn revision_change_or_revocation_cancels_and_rejects_late_packets() {
        let reference = reference();
        let (mut active_ingress, state) = ingress(reference.clone());
        let mut changed = current(&reference);
        changed.grant_revision += 1;
        state.lock().unwrap().current = Ok(changed);
        assert_eq!(
            active_ingress.ingest(envelope(1), NOW).unwrap_err().kind,
            BrowserProducerIngressErrorKind::AuthorityChanged
        );

        let (mut revoked, state) = ingress(reference);
        state.lock().unwrap().current =
            Err(error(BrowserProducerIngressErrorKind::AuthorityUnavailable));
        assert_eq!(
            revoked.ingest(envelope(1), NOW).unwrap_err().kind,
            BrowserProducerIngressErrorKind::AuthorityUnavailable
        );
        assert_eq!(
            revoked.ingest(envelope(2), NOW).unwrap_err().kind,
            BrowserProducerIngressErrorKind::AuthorityUnavailable
        );
        assert_eq!(state.lock().unwrap().reloads, 2);
    }

    #[test]
    fn debug_and_errors_never_expose_selected_content_or_identity() {
        let reference = reference();
        let current = current(&reference);
        let (mut ingress, _) = ingress(reference);
        let value = ingress.ingest(envelope(1), NOW).unwrap().unwrap();
        for debug in [format!("{current:?}"), format!("{value:?}")] {
            assert!(!debug.contains("atlas.example"));
            assert!(!debug.contains("/research"));
        }
    }
}
