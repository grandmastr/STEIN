//! Closed one-way ingress contract for an authenticated Edge producer.
//!
//! This module intentionally has no production authority constructor. Edge
//! Add-ons provenance and direct-launch package identity are not yet proven by
//! a native fixture, so caller origin, ancestry, or Authenticode evidence must
//! not make the host a CORE client. The state machine and current-authority
//! reload contract can be integrated once that OS admission exists.

use std::fmt;

use stein_core::{DeviceId, FocusSessionId, PermissionGrantId, ResourceId};

use crate::{
    BrowserCaptureCancellation, BrowserIngressError, BrowserObservationPacket,
    BrowserObservationValidator, EdgeBrowserCapturePolicy,
};
#[cfg(test)]
use crate::{BrowserObservationEnvelope, BrowserValidationOutcome};

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

    #[cfg(test)]
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

/// Opaque proof for one exact kernel connection handle.
///
/// No production constructor exists in this slice. A future Windows broker can
/// construct it only after the peer token proves the dedicated packaged host
/// AUMID and a clean-VM fixture proves Edge's launch retains that identity.
pub struct BrowserProducerConnectionAuthority {
    connection_handle: usize,
    admission_epoch: [u8; 16],
}

impl fmt::Debug for BrowserProducerConnectionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserProducerConnectionAuthority([redacted])")
    }
}

impl Drop for BrowserProducerConnectionAuthority {
    fn drop(&mut self) {
        self.connection_handle = 0;
        self.admission_epoch.fill(0);
    }
}

impl BrowserProducerConnectionAuthority {
    #[cfg(test)]
    fn synthetic(connection_handle: usize) -> Self {
        Self {
            connection_handle,
            admission_epoch: [0x51; 16],
        }
    }
}

/// Production remains unavailable rather than accepting weaker launch text.
pub fn admit_release_managed_edge_producer()
-> Result<BrowserProducerConnectionAuthority, BrowserProducerIngressError> {
    Err(error(BrowserProducerIngressErrorKind::AdmissionUnavailable))
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

    /// Semantic fixture only. Production ingestion is deliberately absent
    /// until one type owns the admitted pipe for its entire lifetime; comparing
    /// a borrowed numeric HANDLE would permit handle-value reuse after close.
    #[cfg(test)]
    fn ingest_for_handle(
        &mut self,
        connection_handle: usize,
        envelope: BrowserObservationEnvelope,
        received_at_unix_ms: i64,
    ) -> Result<Option<AuthorizedBrowserObservation>, BrowserProducerIngressError> {
        if connection_handle == 0 || connection_handle != self.connection.connection_handle {
            self.validator
                .cancel(BrowserCaptureCancellation::SourceLost);
            return Err(error(BrowserProducerIngressErrorKind::ConnectionChanged));
        }
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

    pub fn cancel(&mut self, reason: BrowserCaptureCancellation) {
        self.validator.cancel(reason);
    }
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
    const HANDLE: usize = 0x5151;

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
            BrowserProducerConnectionAuthority::synthetic(HANDLE),
            reference,
            FakeAuthority {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        (ingress, state)
    }

    #[test]
    fn production_admission_is_closed_without_published_and_native_provenance() {
        assert_eq!(
            admit_release_managed_edge_producer().unwrap_err().kind,
            BrowserProducerIngressErrorKind::AdmissionUnavailable
        );
        assert!(!EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON.is_empty());
    }

    #[test]
    fn exact_handle_and_fresh_authority_are_required_for_every_packet() {
        let (mut ingress, state) = ingress(reference());
        let first = ingress.ingest_for_handle(HANDLE, envelope(1), NOW).unwrap();
        assert!(first.is_some());
        assert_eq!(state.lock().unwrap().reloads, 1);
        assert!(
            ingress
                .ingest_for_handle(HANDLE, envelope(2), NOW + 5_000)
                .unwrap()
                .is_some()
        );
        assert_eq!(state.lock().unwrap().reloads, 2);
    }

    #[test]
    fn wrong_handle_is_rejected_before_authority_or_content_processing() {
        let (mut ingress, state) = ingress(reference());
        assert_eq!(
            ingress
                .ingest_for_handle(HANDLE + 1, envelope(1), NOW)
                .unwrap_err()
                .kind,
            BrowserProducerIngressErrorKind::ConnectionChanged
        );
        assert_eq!(state.lock().unwrap().reloads, 0);
        assert_eq!(
            ingress
                .ingest_for_handle(HANDLE, envelope(2), NOW)
                .unwrap_err()
                .kind,
            BrowserProducerIngressErrorKind::Cancelled
        );
    }

    #[test]
    fn revision_change_or_revocation_cancels_and_rejects_late_packets() {
        let reference = reference();
        let (mut active_ingress, state) = ingress(reference.clone());
        let mut changed = current(&reference);
        changed.grant_revision += 1;
        state.lock().unwrap().current = Ok(changed);
        assert_eq!(
            active_ingress
                .ingest_for_handle(HANDLE, envelope(1), NOW)
                .unwrap_err()
                .kind,
            BrowserProducerIngressErrorKind::AuthorityChanged
        );

        let (mut revoked, state) = ingress(reference);
        state.lock().unwrap().current =
            Err(error(BrowserProducerIngressErrorKind::AuthorityUnavailable));
        assert_eq!(
            revoked
                .ingest_for_handle(HANDLE, envelope(1), NOW)
                .unwrap_err()
                .kind,
            BrowserProducerIngressErrorKind::AuthorityUnavailable
        );
        assert_eq!(
            revoked
                .ingest_for_handle(HANDLE, envelope(2), NOW)
                .unwrap_err()
                .kind,
            BrowserProducerIngressErrorKind::AuthorityUnavailable
        );
        assert_eq!(state.lock().unwrap().reloads, 2);
    }

    #[test]
    fn debug_and_errors_never_expose_selected_content_or_identity() {
        let reference = reference();
        let current = current(&reference);
        let (mut ingress, _) = ingress(reference);
        let value = ingress
            .ingest_for_handle(HANDLE, envelope(1), NOW)
            .unwrap()
            .unwrap();
        for debug in [format!("{current:?}"), format!("{value:?}")] {
            assert!(!debug.contains("atlas.example"));
            assert!(!debug.contains("/research"));
        }
    }
}
