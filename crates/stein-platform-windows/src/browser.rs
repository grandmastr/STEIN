//! Exact, transient Microsoft Edge browser-observation validation.
//!
//! This module deliberately stops before transport admission. Native messaging
//! caller text and stdio are not an ADR 0011 capability. The future Windows
//! browser broker must create an OS-bound producer connection before any value
//! accepted here can enter CORE's [`stein_core::ObservationPort`].

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stein_core::{BrowserLocationGranularity, SensitiveText};
use url::Url;
use zeroize::Zeroizing;

pub const EDGE_NATIVE_HOST_NAME: &str = "com.stein.personal_intelligence.browser";
pub const EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES: usize = 64 * 1024;
pub const EDGE_BROWSER_EXTRACTION_VERSION: &str = "edge-mv3-visible-text-v1";
pub const EDGE_BROWSER_REDACTION_VERSION: &str = "stein-local-sensitive-text-v1";

const BINDING_PREFIX: &str = "winbrowser:v1:edge-stable";
const MAXIMUM_BINDING_BYTES: usize = 512;
const MAXIMUM_LOCATION_COMPONENT_BYTES: usize = 4 * 1024;
const MAXIMUM_VISIBLE_TEXT_INPUT_BYTES: usize = 48 * 1024;
const MAXIMUM_OUTPUT_BYTES: usize = 16 * 1024;
const MAXIMUM_FUTURE_SKEW_MILLISECONDS: i64 = 5_000;
const MAXIMUM_STALE_MILLISECONDS: i64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserCaptureScope {
    Location,
    VisibleText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserCaptureCancellation {
    Locked,
    Revoked,
    SourceLost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum BrowserSelectionOfferKind {
    SelectionOffer,
}

/// First, direct-user native-messaging value emitted by the exact selected
/// Edge profile and tab. Raw site and origin are transient validation input;
/// Debug output deliberately omits them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBrowserSelectionOffer {
    protocol_version: u16,
    kind: BrowserSelectionOfferKind,
    extension_id: String,
    extension_version: String,
    profile_binding_sha256: Zeroizing<String>,
    browser_session_id: Zeroizing<String>,
    selection_id: Zeroizing<String>,
    tab_id: u32,
    window_id: u32,
    active: bool,
    incognito: bool,
    page_kind: BrowserPageKind,
    site: Zeroizing<String>,
    origin: Zeroizing<String>,
    site_sha256: Zeroizing<String>,
    origin_sha256: Zeroizing<String>,
}

impl fmt::Debug for EdgeBrowserSelectionOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EdgeBrowserSelectionOffer")
            .field("protocol_version", &self.protocol_version)
            .field("tab_bound", &(self.tab_id != 0))
            .field("window_bound", &(self.window_id != 0))
            .finish_non_exhaustive()
    }
}

impl EdgeBrowserSelectionOffer {
    /// Initial accepted URL bound from ADR 0014/0017: origin and path only;
    /// query and fragment remain excluded until a future explicit UI contract.
    pub fn into_initial_location_binding(
        self,
        expected_extension_id: &str,
        expected_extension_version: &str,
    ) -> Result<WindowsBrowserSurfaceBinding, BrowserIngressError> {
        self.into_binding(
            expected_extension_id,
            expected_extension_version,
            BrowserLocationGranularity {
                origin: true,
                path: true,
                query: false,
                fragment: false,
            },
        )
    }

    /// Converts the transient offer to the path/URL-free binding that CORE may
    /// persist. The exact release identity and version are trusted build
    /// inputs; extension claims cannot choose them.
    pub fn into_binding(
        self,
        expected_extension_id: &str,
        expected_extension_version: &str,
        granularity: BrowserLocationGranularity,
    ) -> Result<WindowsBrowserSurfaceBinding, BrowserIngressError> {
        if self.protocol_version != 1
            || self.kind != BrowserSelectionOfferKind::SelectionOffer
            || !valid_extension_id(expected_extension_id)
            || !valid_extension_version(expected_extension_version)
            || self.extension_id != expected_extension_id
            || self.extension_version != expected_extension_version
            || !self.active
            || self.incognito
            || self.page_kind != BrowserPageKind::StandardWebPage
        {
            return Err(malformed());
        }
        let selection = EdgeBrowserSelection::new(
            decode_fixed(&self.profile_binding_sha256)?,
            decode_fixed(&self.browser_session_id)?,
            decode_fixed(&self.selection_id)?,
            self.tab_id,
            self.window_id,
            self.site.as_str(),
            self.origin.as_str(),
            granularity,
        )?;
        let binding = WindowsBrowserSurfaceBinding::from_selection(&selection);
        compare_hex(
            &self.site_sha256,
            &binding.site_sha256,
            BrowserIngressErrorKind::WrongSite,
        )?;
        compare_hex(
            &self.origin_sha256,
            &binding.origin_sha256,
            BrowserIngressErrorKind::WrongOrigin,
        )?;
        Ok(binding)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeBrowserWireScope {
    Location,
    VisibleText,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBrowserWireGranularity {
    pub origin: bool,
    pub path: bool,
    pub query: bool,
    pub fragment: bool,
}

/// The sole bounded CORE-to-extension response. It contains no observation,
/// user content, general protocol capability, or reusable authority material.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBrowserCapturePlan {
    pub protocol_version: u16,
    pub kind: EdgeBrowserControlKind,
    pub extension_id: String,
    pub extension_version: String,
    pub scope: EdgeBrowserWireScope,
    pub authority_epoch: u64,
    pub profile_binding_sha256: String,
    pub browser_session_id: String,
    pub selection_id: String,
    pub tab_id: u32,
    pub window_id: u32,
    pub site_sha256: String,
    pub origin_sha256: String,
    pub granularity: EdgeBrowserWireGranularity,
    pub maximum_payload_bytes: usize,
    pub minimum_interval_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeBrowserControlKind {
    CapturePlan,
    Cancel,
}

impl EdgeBrowserCapturePlan {
    pub fn from_policy(
        policy: &EdgeBrowserCapturePolicy,
        expected_extension_id: &str,
        expected_extension_version: &str,
    ) -> Result<Self, BrowserIngressError> {
        policy.validate()?;
        if !valid_extension_id(expected_extension_id)
            || !valid_extension_version(expected_extension_version)
        {
            return Err(invalid_configuration());
        }
        let binding = &policy.binding;
        Ok(Self {
            protocol_version: 1,
            kind: EdgeBrowserControlKind::CapturePlan,
            extension_id: expected_extension_id.to_owned(),
            extension_version: expected_extension_version.to_owned(),
            scope: match policy.scope {
                BrowserCaptureScope::Location => EdgeBrowserWireScope::Location,
                BrowserCaptureScope::VisibleText => EdgeBrowserWireScope::VisibleText,
            },
            authority_epoch: policy.authority_epoch,
            profile_binding_sha256: encode_bytes(&binding.profile_binding_sha256),
            browser_session_id: encode_bytes(&binding.browser_session_id),
            selection_id: encode_bytes(&binding.selection_id),
            tab_id: binding.tab_id,
            window_id: binding.window_id,
            site_sha256: encode_bytes(&binding.site_sha256),
            origin_sha256: encode_bytes(&binding.origin_sha256),
            granularity: EdgeBrowserWireGranularity {
                origin: binding.granularity.origin,
                path: binding.granularity.path,
                query: binding.granularity.query,
                fragment: binding.granularity.fragment,
            },
            maximum_payload_bytes: policy.maximum_payload_bytes,
            minimum_interval_ms: u64::try_from(policy.minimum_interval.as_millis())
                .map_err(|_| invalid_configuration())?,
        })
    }

    pub fn validate_for_release(
        &self,
        expected_extension_id: &str,
        expected_extension_version: &str,
    ) -> Result<(), BrowserIngressError> {
        if self.protocol_version != 1
            || self.kind != EdgeBrowserControlKind::CapturePlan
            || self.extension_id != expected_extension_id
            || self.extension_version != expected_extension_version
        {
            return Err(malformed());
        }
        let binding = WindowsBrowserSurfaceBinding {
            profile_binding_sha256: decode_fixed(&self.profile_binding_sha256)?,
            browser_session_id: decode_fixed(&self.browser_session_id)?,
            selection_id: decode_fixed(&self.selection_id)?,
            tab_id: self.tab_id,
            window_id: self.window_id,
            site_sha256: decode_fixed(&self.site_sha256)?,
            origin_sha256: decode_fixed(&self.origin_sha256)?,
            granularity: BrowserLocationGranularity {
                origin: self.granularity.origin,
                path: self.granularity.path,
                query: self.granularity.query,
                fragment: self.granularity.fragment,
            },
        };
        let policy = EdgeBrowserCapturePolicy {
            binding,
            scope: match self.scope {
                EdgeBrowserWireScope::Location => BrowserCaptureScope::Location,
                EdgeBrowserWireScope::VisibleText => BrowserCaptureScope::VisibleText,
            },
            authority_epoch: self.authority_epoch,
            maximum_payload_bytes: self.maximum_payload_bytes,
            minimum_interval: Duration::from_millis(self.minimum_interval_ms),
        };
        policy.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeBrowserSourceState {
    Paused,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeBrowserSourcePauseReason {
    PausedBackground,
    PausedProtected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBrowserSourceStatus {
    pub protocol_version: u16,
    kind: EdgeBrowserSourceStatusKind,
    pub authority_epoch: u64,
    pub selection_id: Zeroizing<String>,
    pub state: EdgeBrowserSourceState,
    pub reason: EdgeBrowserSourcePauseReason,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum EdgeBrowserSourceStatusKind {
    SourceStatus,
}

impl fmt::Debug for EdgeBrowserSourceStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EdgeBrowserSourceStatus")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl EdgeBrowserSourceStatus {
    pub fn validate(&self, policy: &EdgeBrowserCapturePolicy) -> Result<(), BrowserIngressError> {
        if self.protocol_version != 1
            || self.kind != EdgeBrowserSourceStatusKind::SourceStatus
            || self.authority_epoch != policy.authority_epoch
            || self.state != EdgeBrowserSourceState::Paused
        {
            return Err(malformed());
        }
        compare_hex(
            &self.selection_id,
            &policy.binding.selection_id,
            BrowserIngressErrorKind::WrongSelection,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserIngressErrorKind {
    InvalidConfiguration,
    Malformed,
    Oversize,
    WrongProfile,
    WrongBrowserSession,
    WrongSelection,
    WrongTab,
    WrongWindow,
    BackgroundSurface,
    PrivateSurface,
    ProtectedSurface,
    WrongSite,
    WrongOrigin,
    GranularityExceeded,
    Replay,
    Stale,
    Cancelled,
}

/// Content-free browser-ingress failure suitable for capability health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserIngressError {
    pub kind: BrowserIngressErrorKind,
    pub summary: &'static str,
}

impl std::error::Error for BrowserIngressError {}

impl fmt::Display for BrowserIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.summary)
    }
}

/// Direct-user browser selection before it is converted to a path-free binding.
///
/// Debug output is redacted because origin and site are transient private input.
pub struct EdgeBrowserSelection {
    profile_binding_sha256: [u8; 32],
    browser_session_id: [u8; 16],
    selection_id: [u8; 16],
    tab_id: u32,
    window_id: u32,
    site: Zeroizing<String>,
    origin: Zeroizing<String>,
    granularity: BrowserLocationGranularity,
}

impl fmt::Debug for EdgeBrowserSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EdgeBrowserSelection")
            .field("tab_bound", &true)
            .field("window_bound", &true)
            .field("site_bytes", &self.site.len())
            .field("origin_bytes", &self.origin.len())
            .field("granularity", &self.granularity)
            .finish_non_exhaustive()
    }
}

impl EdgeBrowserSelection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_binding_sha256: [u8; 32],
        browser_session_id: [u8; 16],
        selection_id: [u8; 16],
        tab_id: u32,
        window_id: u32,
        site: impl Into<String>,
        origin: impl Into<String>,
        granularity: BrowserLocationGranularity,
    ) -> Result<Self, BrowserIngressError> {
        let raw_site = Zeroizing::new(site.into());
        let raw_origin = Zeroizing::new(origin.into());
        let site = Zeroizing::new(canonical_site(&raw_site)?);
        let origin = Zeroizing::new(canonical_origin(&raw_origin)?);
        let origin_url = Url::parse(&origin).map_err(|_| invalid_configuration())?;
        if profile_binding_sha256.iter().all(|byte| *byte == 0)
            || browser_session_id.iter().all(|byte| *byte == 0)
            || selection_id.iter().all(|byte| *byte == 0)
            || tab_id == 0
            || window_id == 0
            || origin_url.host_str() != Some(site.as_str())
        {
            return Err(invalid_configuration());
        }
        Ok(Self {
            profile_binding_sha256,
            browser_session_id,
            selection_id,
            tab_id,
            window_id,
            site,
            origin,
            granularity,
        })
    }
}

/// Opaque durable identity for one explicitly selected Edge profile/tab/site.
///
/// It contains only digests and browser-session identifiers. It cannot reveal a
/// URL, profile name, page title, query, fragment, or content if persisted as a
/// `ResourceBinding.opaque_reference`.
#[derive(Clone, Eq, PartialEq)]
pub struct WindowsBrowserSurfaceBinding {
    profile_binding_sha256: [u8; 32],
    browser_session_id: [u8; 16],
    selection_id: [u8; 16],
    tab_id: u32,
    window_id: u32,
    site_sha256: [u8; 32],
    origin_sha256: [u8; 32],
    granularity: BrowserLocationGranularity,
}

impl fmt::Debug for WindowsBrowserSurfaceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsBrowserSurfaceBinding")
            .field("tab_bound", &true)
            .field("window_bound", &true)
            .field("granularity", &self.granularity)
            .finish_non_exhaustive()
    }
}

impl WindowsBrowserSurfaceBinding {
    pub fn from_selection(selection: &EdgeBrowserSelection) -> Self {
        Self {
            profile_binding_sha256: selection.profile_binding_sha256,
            browser_session_id: selection.browser_session_id,
            selection_id: selection.selection_id,
            tab_id: selection.tab_id,
            window_id: selection.window_id,
            site_sha256: sha256(selection.site.as_bytes()),
            origin_sha256: sha256(selection.origin.as_bytes()),
            granularity: selection.granularity,
        }
    }

    pub fn parse(value: &str) -> Result<Self, BrowserIngressError> {
        if value.is_empty() || value.len() > MAXIMUM_BINDING_BYTES {
            return Err(malformed());
        }
        let components: Vec<_> = value.split(':').collect();
        let [
            "winbrowser",
            "v1",
            "edge-stable",
            profile,
            browser_session,
            selection,
            tab,
            window,
            site,
            origin,
            flags,
        ] = components.as_slice()
        else {
            return Err(malformed());
        };
        let binding = Self {
            profile_binding_sha256: decode_fixed(profile)?,
            browser_session_id: decode_fixed(browser_session)?,
            selection_id: decode_fixed(selection)?,
            tab_id: decode_u32(tab)?,
            window_id: decode_u32(window)?,
            site_sha256: decode_fixed(site)?,
            origin_sha256: decode_fixed(origin)?,
            granularity: decode_granularity(flags)?,
        };
        binding.validate()?;
        if binding.to_string() != value {
            return Err(malformed());
        }
        Ok(binding)
    }

    pub const fn granularity(&self) -> BrowserLocationGranularity {
        self.granularity
    }

    fn validate(&self) -> Result<(), BrowserIngressError> {
        if self.profile_binding_sha256.iter().all(|byte| *byte == 0)
            || self.browser_session_id.iter().all(|byte| *byte == 0)
            || self.selection_id.iter().all(|byte| *byte == 0)
            || self.tab_id == 0
            || self.window_id == 0
            || self.site_sha256.iter().all(|byte| *byte == 0)
            || self.origin_sha256.iter().all(|byte| *byte == 0)
        {
            return Err(malformed());
        }
        Ok(())
    }
}

impl fmt::Display for WindowsBrowserSurfaceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{BINDING_PREFIX}:{}:{}:{}:{:08x}:{:08x}:{}:{}:{:02x}",
            encode_bytes(&self.profile_binding_sha256),
            encode_bytes(&self.browser_session_id),
            encode_bytes(&self.selection_id),
            self.tab_id,
            self.window_id,
            encode_bytes(&self.site_sha256),
            encode_bytes(&self.origin_sha256),
            encode_granularity(self.granularity),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeBrowserCapturePolicy {
    pub binding: WindowsBrowserSurfaceBinding,
    pub scope: BrowserCaptureScope,
    pub authority_epoch: u64,
    pub maximum_payload_bytes: usize,
    pub minimum_interval: Duration,
}

impl EdgeBrowserCapturePolicy {
    pub fn validate(&self) -> Result<(), BrowserIngressError> {
        self.binding.validate()?;
        if self.authority_epoch == 0
            || self.maximum_payload_bytes == 0
            || self.maximum_payload_bytes > MAXIMUM_OUTPUT_BYTES
            || self.minimum_interval < Duration::from_secs(1)
        {
            return Err(invalid_configuration());
        }
        if self.scope == BrowserCaptureScope::Location {
            let granularity = self.binding.granularity;
            if !granularity.origin
                && !granularity.path
                && !granularity.query
                && !granularity.fragment
            {
                return Err(invalid_configuration());
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserObservationEnvelope {
    pub protocol_version: u16,
    pub authority_epoch: u64,
    pub sequence: u64,
    pub profile_binding_sha256: Zeroizing<String>,
    pub browser_session_id: Zeroizing<String>,
    pub selection_id: Zeroizing<String>,
    pub tab_id: u32,
    pub window_id: u32,
    pub active: bool,
    pub window_focused: bool,
    pub incognito: bool,
    pub top_frame: bool,
    pub page_kind: BrowserPageKind,
    pub site_sha256: Zeroizing<String>,
    pub origin_sha256: Zeroizing<String>,
    pub location: Option<BrowserLocationFields>,
    pub visible_text: Option<Zeroizing<String>>,
    pub observed_at_unix_ms: i64,
}

impl fmt::Debug for BrowserObservationEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserObservationEnvelope")
            .field("protocol_version", &self.protocol_version)
            .field("sequence", &self.sequence)
            .field("has_location", &self.location.is_some())
            .field(
                "visible_text_bytes",
                &self.visible_text.as_ref().map(|value| value.len()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserPageKind {
    StandardWebPage,
    BrowserHistory,
    ProtectedBrowserPage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLocationFields {
    pub origin: Option<Zeroizing<String>>,
    pub path: Option<Zeroizing<String>>,
    pub query: Option<Zeroizing<String>>,
    pub fragment: Option<Zeroizing<String>>,
}

impl fmt::Debug for BrowserLocationFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserLocationFields")
            .field(
                "origin_bytes",
                &self.origin.as_ref().map(|value| value.len()),
            )
            .field("path_bytes", &self.path.as_ref().map(|value| value.len()))
            .field("query_bytes", &self.query.as_ref().map(|value| value.len()))
            .field(
                "fragment_bytes",
                &self.fragment.as_ref().map(|value| value.len()),
            )
            .finish()
    }
}

pub struct BrowserObservationPacket {
    pub sequence: u64,
    pub observed_at_unix_ms: i64,
    pub origin: Option<SensitiveText>,
    pub relative_location: Option<SensitiveText>,
    pub query_included: bool,
    pub fragment_included: bool,
    pub visible_text: Option<SensitiveText>,
}

impl fmt::Debug for BrowserObservationPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserObservationPacket")
            .field("sequence", &self.sequence)
            .field("has_origin", &self.origin.is_some())
            .field("has_relative_location", &self.relative_location.is_some())
            .field("query_included", &self.query_included)
            .field("fragment_included", &self.fragment_included)
            .field(
                "visible_text_bytes",
                &self.visible_text.as_ref().map(SensitiveText::len),
            )
            .finish()
    }
}

pub enum BrowserValidationOutcome {
    Emit(BrowserObservationPacket),
    Coalesced,
}

impl fmt::Debug for BrowserValidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emit(packet) => formatter.debug_tuple("Emit").field(packet).finish(),
            Self::Coalesced => formatter.write_str("Coalesced"),
        }
    }
}

pub struct BrowserObservationValidator {
    policy: EdgeBrowserCapturePolicy,
    cancelled: Option<BrowserCaptureCancellation>,
    last_sequence: Option<u64>,
    last_emitted_at_unix_ms: Option<i64>,
    pending: Option<BrowserObservationPacket>,
}

impl BrowserObservationValidator {
    pub fn new(policy: EdgeBrowserCapturePolicy) -> Result<Self, BrowserIngressError> {
        policy.validate()?;
        Ok(Self {
            policy,
            cancelled: None,
            last_sequence: None,
            last_emitted_at_unix_ms: None,
            pending: None,
        })
    }

    pub fn cancel(&mut self, reason: BrowserCaptureCancellation) {
        self.cancelled = Some(reason);
        self.pending = None;
    }

    pub fn ingest(
        &mut self,
        envelope: BrowserObservationEnvelope,
        received_at_unix_ms: i64,
    ) -> Result<BrowserValidationOutcome, BrowserIngressError> {
        if self.cancelled.is_some() {
            return Err(cancelled());
        }
        self.validate_boundary(&envelope, received_at_unix_ms)?;
        let packet = self.normalize(envelope)?;
        self.last_sequence = Some(packet.sequence);
        let minimum_interval = i64::try_from(self.policy.minimum_interval.as_millis())
            .map_err(|_| invalid_configuration())?;
        let should_coalesce = self
            .last_emitted_at_unix_ms
            .is_some_and(|last| received_at_unix_ms.saturating_sub(last) < minimum_interval);
        if should_coalesce {
            self.pending = Some(packet);
            return Ok(BrowserValidationOutcome::Coalesced);
        }
        self.last_emitted_at_unix_ms = Some(received_at_unix_ms);
        Ok(BrowserValidationOutcome::Emit(packet))
    }

    pub fn flush_coalesced(
        &mut self,
        received_at_unix_ms: i64,
    ) -> Result<Option<BrowserObservationPacket>, BrowserIngressError> {
        if self.cancelled.is_some() {
            self.pending = None;
            return Err(cancelled());
        }
        let minimum_interval = i64::try_from(self.policy.minimum_interval.as_millis())
            .map_err(|_| invalid_configuration())?;
        if self
            .last_emitted_at_unix_ms
            .is_some_and(|last| received_at_unix_ms.saturating_sub(last) < minimum_interval)
        {
            return Ok(None);
        }
        let packet = self.pending.take();
        if packet.is_some() {
            self.last_emitted_at_unix_ms = Some(received_at_unix_ms);
        }
        Ok(packet)
    }

    fn validate_boundary(
        &self,
        envelope: &BrowserObservationEnvelope,
        received_at_unix_ms: i64,
    ) -> Result<(), BrowserIngressError> {
        if envelope.protocol_version != 1 || envelope.sequence == 0 {
            return Err(malformed());
        }
        if envelope.authority_epoch != self.policy.authority_epoch {
            return Err(error(BrowserIngressErrorKind::WrongSelection));
        }
        if self
            .last_sequence
            .is_some_and(|sequence| envelope.sequence <= sequence)
        {
            return Err(error(BrowserIngressErrorKind::Replay));
        }
        if envelope.observed_at_unix_ms
            > received_at_unix_ms.saturating_add(MAXIMUM_FUTURE_SKEW_MILLISECONDS)
            || received_at_unix_ms.saturating_sub(envelope.observed_at_unix_ms)
                > MAXIMUM_STALE_MILLISECONDS
        {
            return Err(error(BrowserIngressErrorKind::Stale));
        }
        let binding = &self.policy.binding;
        compare_hex(
            &envelope.profile_binding_sha256,
            &binding.profile_binding_sha256,
            BrowserIngressErrorKind::WrongProfile,
        )?;
        compare_hex(
            &envelope.browser_session_id,
            &binding.browser_session_id,
            BrowserIngressErrorKind::WrongBrowserSession,
        )?;
        compare_hex(
            &envelope.selection_id,
            &binding.selection_id,
            BrowserIngressErrorKind::WrongSelection,
        )?;
        if envelope.tab_id != binding.tab_id {
            return Err(error(BrowserIngressErrorKind::WrongTab));
        }
        if envelope.window_id != binding.window_id {
            return Err(error(BrowserIngressErrorKind::WrongWindow));
        }
        if !envelope.active || !envelope.window_focused || !envelope.top_frame {
            return Err(error(BrowserIngressErrorKind::BackgroundSurface));
        }
        if envelope.incognito {
            return Err(error(BrowserIngressErrorKind::PrivateSurface));
        }
        if envelope.page_kind != BrowserPageKind::StandardWebPage {
            return Err(error(BrowserIngressErrorKind::ProtectedSurface));
        }
        compare_hex(
            &envelope.site_sha256,
            &binding.site_sha256,
            BrowserIngressErrorKind::WrongSite,
        )?;
        compare_hex(
            &envelope.origin_sha256,
            &binding.origin_sha256,
            BrowserIngressErrorKind::WrongOrigin,
        )?;
        Ok(())
    }

    fn normalize(
        &self,
        envelope: BrowserObservationEnvelope,
    ) -> Result<BrowserObservationPacket, BrowserIngressError> {
        match self.policy.scope {
            BrowserCaptureScope::Location => self.normalize_location(envelope),
            BrowserCaptureScope::VisibleText => self.normalize_visible_text(envelope),
        }
    }

    fn normalize_location(
        &self,
        mut envelope: BrowserObservationEnvelope,
    ) -> Result<BrowserObservationPacket, BrowserIngressError> {
        if envelope.visible_text.is_some() {
            return Err(error(BrowserIngressErrorKind::GranularityExceeded));
        }
        let mut fields = envelope.location.take().ok_or_else(malformed)?;
        let allowed = self.policy.binding.granularity;
        enforce_component_permission(fields.origin.as_deref(), allowed.origin)?;
        enforce_component_permission(fields.path.as_deref(), allowed.path)?;
        enforce_component_permission(fields.query.as_deref(), allowed.query)?;
        enforce_component_permission(fields.fragment.as_deref(), allowed.fragment)?;

        let query_included = fields.query.is_some();
        let fragment_included = fields.fragment.is_some();
        let origin = match fields.origin.take() {
            Some(mut origin) => {
                let canonical = Zeroizing::new(canonical_origin(&origin)?);
                if canonical.as_str() != origin.as_str() {
                    return Err(malformed());
                }
                if sha256(canonical.as_bytes()) != self.policy.binding.origin_sha256 {
                    return Err(error(BrowserIngressErrorKind::WrongOrigin));
                }
                Some(SensitiveText::new(std::mem::take(&mut *origin)))
            }
            None => None,
        };
        let mut relative = Zeroizing::new(String::new());
        if let Some(path) = fields.path.take() {
            validate_location_component(&path)?;
            if !path.starts_with('/') {
                return Err(malformed());
            }
            relative.push_str(&path);
        }
        if let Some(query) = fields.query.take() {
            validate_location_component(&query)?;
            if query.starts_with('?') {
                return Err(malformed());
            }
            relative.push('?');
            relative.push_str(&query);
        }
        if let Some(fragment) = fields.fragment.take() {
            validate_location_component(&fragment)?;
            if fragment.starts_with('#') {
                return Err(malformed());
            }
            relative.push('#');
            relative.push_str(&fragment);
        }
        let output_bytes = origin.as_ref().map_or(0, SensitiveText::len) + relative.len();
        if output_bytes == 0 || output_bytes > self.policy.maximum_payload_bytes {
            return Err(error(BrowserIngressErrorKind::Oversize));
        }
        Ok(BrowserObservationPacket {
            sequence: envelope.sequence,
            observed_at_unix_ms: envelope.observed_at_unix_ms,
            origin,
            relative_location: (!relative.is_empty())
                .then(|| SensitiveText::new(std::mem::take(&mut *relative))),
            query_included,
            fragment_included,
            visible_text: None,
        })
    }

    fn normalize_visible_text(
        &self,
        mut envelope: BrowserObservationEnvelope,
    ) -> Result<BrowserObservationPacket, BrowserIngressError> {
        if envelope.location.is_some() {
            return Err(error(BrowserIngressErrorKind::GranularityExceeded));
        }
        let visible_text = envelope.visible_text.take().ok_or_else(malformed)?;
        if visible_text.len() > MAXIMUM_VISIBLE_TEXT_INPUT_BYTES {
            return Err(error(BrowserIngressErrorKind::Oversize));
        }
        let mut redacted = Zeroizing::new(redact_and_bound(
            &visible_text,
            self.policy.maximum_payload_bytes,
        ));
        if redacted.is_empty() {
            return Err(malformed());
        }
        Ok(BrowserObservationPacket {
            sequence: envelope.sequence,
            observed_at_unix_ms: envelope.observed_at_unix_ms,
            origin: None,
            relative_location: None,
            query_included: false,
            fragment_included: false,
            visible_text: Some(SensitiveText::new(std::mem::take(&mut *redacted))),
        })
    }
}

fn canonical_site(value: &str) -> Result<String, BrowserIngressError> {
    if value.is_empty()
        || value.len() > 253
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('/')
        || value.contains(char::from(92))
        || value.contains(['@', ':'])
    {
        return Err(invalid_configuration());
    }
    let parse_value = Zeroizing::new(format!("https://{value}/"));
    let parsed = Url::parse(&parse_value).map_err(|_| invalid_configuration())?;
    let host = parsed.host_str().ok_or_else(invalid_configuration)?;
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_configuration());
    }
    Ok(host.to_owned())
}

fn valid_extension_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

fn valid_extension_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && (1..=4).contains(&value.split('.').count())
        && value.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 9
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component == "0" || !component.starts_with('0'))
        })
}

fn canonical_origin(value: &str) -> Result<String, BrowserIngressError> {
    if value.is_empty()
        || value.len() > MAXIMUM_LOCATION_COMPONENT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_configuration());
    }
    let parsed = Url::parse(value).map_err(|_| invalid_configuration())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(error(BrowserIngressErrorKind::ProtectedSurface));
    }
    Ok(parsed.origin().ascii_serialization())
}

fn validate_location_component(value: &str) -> Result<(), BrowserIngressError> {
    if value.len() > MAXIMUM_LOCATION_COMPONENT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(malformed());
    }
    Ok(())
}

fn enforce_component_permission(
    component: Option<&String>,
    allowed: bool,
) -> Result<(), BrowserIngressError> {
    if component.is_some() && !allowed {
        return Err(error(BrowserIngressErrorKind::GranularityExceeded));
    }
    Ok(())
}

fn redact_and_bound(value: &str, maximum_bytes: usize) -> String {
    let normalized = Zeroizing::new(
        value
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>(),
    );
    let mut output = String::new();
    let mut redact_next = false;
    for token in normalized.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        let sensitive_label = [
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "token",
        ]
        .iter()
        .any(|label| {
            lower.trim_matches(|value: char| !value.is_ascii_alphanumeric() && value != '_')
                == *label
        });
        let inline_sensitive = [
            "password=",
            "password:",
            "secret=",
            "secret:",
            "api_key=",
            "token=",
        ]
        .iter()
        .any(|prefix| lower.starts_with(prefix));
        let replacement = if redact_next || inline_sensitive {
            "[redacted]"
        } else if token.contains('@') {
            "[redacted-email]"
        } else if token.len() >= 32 && token.bytes().filter(|byte| *byte == b'.').count() == 2 {
            "[redacted-token]"
        } else {
            token
        };
        let separator = usize::from(!output.is_empty());
        if output.len() + separator + replacement.len() > maximum_bytes {
            break;
        }
        if separator == 1 {
            output.push(' ');
        }
        output.push_str(replacement);
        redact_next = sensitive_label;
    }
    output
}

fn compare_hex<const LENGTH: usize>(
    supplied: &str,
    expected: &[u8; LENGTH],
    kind: BrowserIngressErrorKind,
) -> Result<(), BrowserIngressError> {
    let supplied: [u8; LENGTH] = decode_fixed(supplied).map_err(|_| error(kind))?;
    let difference = supplied
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        });
    if difference == 0 {
        Ok(())
    } else {
        Err(error(kind))
    }
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn encode_granularity(value: BrowserLocationGranularity) -> u8 {
    u8::from(value.origin)
        | (u8::from(value.path) << 1)
        | (u8::from(value.query) << 2)
        | (u8::from(value.fragment) << 3)
}

fn decode_granularity(value: &str) -> Result<BrowserLocationGranularity, BrowserIngressError> {
    if value.len() != 2 || !value.bytes().all(is_lower_hex) {
        return Err(malformed());
    }
    let flags = u8::from_str_radix(value, 16).map_err(|_| malformed())?;
    if flags & !0x0f != 0 {
        return Err(malformed());
    }
    Ok(BrowserLocationGranularity {
        origin: flags & 1 != 0,
        path: flags & 2 != 0,
        query: flags & 4 != 0,
        fragment: flags & 8 != 0,
    })
}

fn encode_bytes(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_fixed<const LENGTH: usize>(value: &str) -> Result<[u8; LENGTH], BrowserIngressError> {
    if value.len() != LENGTH * 2 || !value.bytes().all(is_lower_hex) {
        return Err(malformed());
    }
    let mut decoded = [0_u8; LENGTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn decode_u32(value: &str) -> Result<u32, BrowserIngressError> {
    if value.len() != 8 || !value.bytes().all(is_lower_hex) {
        return Err(malformed());
    }
    u32::from_str_radix(value, 16).map_err(|_| malformed())
}

fn decode_nibble(value: u8) -> Result<u8, BrowserIngressError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(malformed()),
    }
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

const fn error(kind: BrowserIngressErrorKind) -> BrowserIngressError {
    BrowserIngressError {
        kind,
        summary: "The Edge browser observation was rejected at its selected boundary.",
    }
}

const fn invalid_configuration() -> BrowserIngressError {
    BrowserIngressError {
        kind: BrowserIngressErrorKind::InvalidConfiguration,
        summary: "The Edge browser observation configuration is invalid.",
    }
}

const fn malformed() -> BrowserIngressError {
    error(BrowserIngressErrorKind::Malformed)
}

const fn cancelled() -> BrowserIngressError {
    error(BrowserIngressErrorKind::Cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn granularity() -> BrowserLocationGranularity {
        BrowserLocationGranularity {
            origin: true,
            path: true,
            query: false,
            fragment: false,
        }
    }

    fn binding() -> WindowsBrowserSurfaceBinding {
        WindowsBrowserSurfaceBinding::from_selection(
            &EdgeBrowserSelection::new(
                [0x11; 32],
                [0x22; 16],
                [0x33; 16],
                41,
                7,
                "atlas.example",
                "https://atlas.example",
                granularity(),
            )
            .unwrap(),
        )
    }

    fn location_policy() -> EdgeBrowserCapturePolicy {
        EdgeBrowserCapturePolicy {
            binding: binding(),
            scope: BrowserCaptureScope::Location,
            authority_epoch: 9,
            maximum_payload_bytes: 2 * 1024,
            minimum_interval: Duration::from_secs(5),
        }
    }

    fn envelope(sequence: u64) -> BrowserObservationEnvelope {
        BrowserObservationEnvelope {
            protocol_version: 1,
            authority_epoch: 9,
            sequence,
            profile_binding_sha256: encode_bytes(&[0x11; 32]).into(),
            browser_session_id: encode_bytes(&[0x22; 16]).into(),
            selection_id: encode_bytes(&[0x33; 16]).into(),
            tab_id: 41,
            window_id: 7,
            active: true,
            window_focused: true,
            incognito: false,
            top_frame: true,
            page_kind: BrowserPageKind::StandardWebPage,
            site_sha256: encode_bytes(&sha256(b"atlas.example")).into(),
            origin_sha256: encode_bytes(&sha256(b"https://atlas.example")).into(),
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

    #[test]
    fn binding_round_trips_without_profile_site_or_origin_content() {
        let binding = binding();
        let encoded = binding.to_string();
        assert_eq!(
            WindowsBrowserSurfaceBinding::parse(&encoded).unwrap(),
            binding
        );
        assert!(!encoded.contains("atlas"));
        assert!(!encoded.contains("https"));
        assert!(encoded.len() <= MAXIMUM_BINDING_BYTES);
    }

    fn selection_offer_json() -> serde_json::Value {
        serde_json::json!({
            "protocol_version": 1,
            "kind": "selection_offer",
            "extension_id": "abcdefghijklmnopabcdefghijklmnop",
            "extension_version": "0.1.0",
            "profile_binding_sha256": "11".repeat(32),
            "browser_session_id": "22".repeat(16),
            "selection_id": "33".repeat(16),
            "tab_id": 41,
            "window_id": 7,
            "active": true,
            "incognito": false,
            "page_kind": "standard_web_page",
            "site": "atlas.example",
            "origin": "https://atlas.example",
            "site_sha256": encode_bytes(&sha256(b"atlas.example")),
            "origin_sha256": encode_bytes(&sha256(b"https://atlas.example")),
        })
    }

    #[test]
    fn selection_offer_requires_exact_release_profile_tab_site_and_origin() {
        let offer: EdgeBrowserSelectionOffer =
            serde_json::from_value(selection_offer_json()).unwrap();
        assert_eq!(
            offer
                .into_binding("abcdefghijklmnopabcdefghijklmnop", "0.1.0", granularity(),)
                .unwrap(),
            binding()
        );

        for (field, replacement, expected_kind) in [
            (
                "profile_binding_sha256",
                serde_json::json!("90".repeat(31)),
                BrowserIngressErrorKind::Malformed,
            ),
            (
                "tab_id",
                serde_json::json!(0),
                BrowserIngressErrorKind::InvalidConfiguration,
            ),
            (
                "site_sha256",
                serde_json::json!("91".repeat(32)),
                BrowserIngressErrorKind::WrongSite,
            ),
            (
                "origin_sha256",
                serde_json::json!("92".repeat(32)),
                BrowserIngressErrorKind::WrongOrigin,
            ),
        ] {
            let mut value = selection_offer_json();
            value[field] = replacement;
            let offer: EdgeBrowserSelectionOffer = serde_json::from_value(value).unwrap();
            let failure = offer
                .into_binding("abcdefghijklmnopabcdefghijklmnop", "0.1.0", granularity())
                .unwrap_err();
            assert_eq!(failure.kind, expected_kind);
        }

        let offer: EdgeBrowserSelectionOffer =
            serde_json::from_value(selection_offer_json()).unwrap();
        assert_eq!(
            offer
                .into_binding("abcdefghijklmnopabcdefghijklmnop", "0.1.1", granularity(),)
                .unwrap_err()
                .kind,
            BrowserIngressErrorKind::Malformed
        );
    }

    #[test]
    fn capture_plan_is_bounded_content_free_and_round_trips_strictly() {
        let plan = EdgeBrowserCapturePlan::from_policy(
            &location_policy(),
            "abcdefghijklmnopabcdefghijklmnop",
            "0.1.0",
        )
        .unwrap();
        let encoded = serde_json::to_vec(&plan).unwrap();
        assert!(encoded.len() <= EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES);
        let text = String::from_utf8(encoded.clone()).unwrap();
        assert!(!text.contains("atlas.example"));
        assert!(!text.contains("/research"));
        let decoded: EdgeBrowserCapturePlan = serde_json::from_slice(&encoded).unwrap();
        decoded
            .validate_for_release("abcdefghijklmnopabcdefghijklmnop", "0.1.0")
            .unwrap();

        let mut unknown = serde_json::to_value(&plan).unwrap();
        unknown["private_payload"] = serde_json::json!("synthetic-secret");
        assert!(serde_json::from_value::<EdgeBrowserCapturePlan>(unknown).is_err());
    }

    #[test]
    fn source_status_is_content_free_and_bound_to_selection_epoch() {
        let status: EdgeBrowserSourceStatus = serde_json::from_value(serde_json::json!({
            "protocol_version": 1,
            "kind": "source_status",
            "authority_epoch": 9,
            "selection_id": "33".repeat(16),
            "state": "paused",
            "reason": "paused_background",
        }))
        .unwrap();
        status.validate(&location_policy()).unwrap();

        let wrong: EdgeBrowserSourceStatus = serde_json::from_value(serde_json::json!({
            "protocol_version": 1,
            "kind": "source_status",
            "authority_epoch": 10,
            "selection_id": "33".repeat(16),
            "state": "paused",
            "reason": "paused_protected",
        }))
        .unwrap();
        assert_eq!(
            wrong.validate(&location_policy()).unwrap_err().kind,
            BrowserIngressErrorKind::Malformed
        );
    }

    #[test]
    fn exact_selected_location_is_minimized_and_coalesced() {
        let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
        let BrowserValidationOutcome::Emit(first) = validator.ingest(envelope(1), NOW).unwrap()
        else {
            panic!("first observation must emit");
        };
        assert_eq!(first.origin.unwrap().expose(), "https://atlas.example");
        assert_eq!(first.relative_location.unwrap().expose(), "/research");
        assert!(!first.query_included);
        assert!(!first.fragment_included);

        assert!(matches!(
            validator.ingest(envelope(2), NOW + 1_000).unwrap(),
            BrowserValidationOutcome::Coalesced
        ));
        assert!(validator.flush_coalesced(NOW + 4_999).unwrap().is_none());
        assert_eq!(
            validator
                .flush_coalesced(NOW + 5_000)
                .unwrap()
                .unwrap()
                .sequence,
            2
        );
    }

    #[test]
    fn wrong_profile_site_tab_origin_and_replay_fail_closed() {
        type Mutator = fn(&mut BrowserObservationEnvelope);
        let cases: &[(Mutator, BrowserIngressErrorKind)] = &[
            (
                |value| value.profile_binding_sha256 = encode_bytes(&[0x91; 32]).into(),
                BrowserIngressErrorKind::WrongProfile,
            ),
            (
                |value| value.site_sha256 = encode_bytes(&[0x92; 32]).into(),
                BrowserIngressErrorKind::WrongSite,
            ),
            (|value| value.tab_id = 99, BrowserIngressErrorKind::WrongTab),
            (
                |value| value.origin_sha256 = encode_bytes(&[0x93; 32]).into(),
                BrowserIngressErrorKind::WrongOrigin,
            ),
        ];
        for (mutator, kind) in cases {
            let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
            let mut value = envelope(1);
            mutator(&mut value);
            assert_eq!(validator.ingest(value, NOW).unwrap_err().kind, *kind);
        }

        let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
        validator.ingest(envelope(2), NOW).unwrap();
        assert_eq!(
            validator.ingest(envelope(2), NOW).unwrap_err().kind,
            BrowserIngressErrorKind::Replay
        );
    }

    #[test]
    fn background_history_private_and_protected_pages_are_rejected() {
        let mut background = envelope(1);
        background.active = false;
        let mut history = envelope(1);
        history.page_kind = BrowserPageKind::BrowserHistory;
        let mut private = envelope(1);
        private.incognito = true;
        let mut protected = envelope(1);
        protected.page_kind = BrowserPageKind::ProtectedBrowserPage;

        for (value, kind) in [
            (background, BrowserIngressErrorKind::BackgroundSurface),
            (history, BrowserIngressErrorKind::ProtectedSurface),
            (private, BrowserIngressErrorKind::PrivateSurface),
            (protected, BrowserIngressErrorKind::ProtectedSurface),
        ] {
            let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
            assert_eq!(validator.ingest(value, NOW).unwrap_err().kind, kind);
        }
        assert_eq!(
            EdgeBrowserSelection::new(
                [1; 32],
                [2; 16],
                [3; 16],
                1,
                1,
                "settings",
                "edge://settings",
                granularity(),
            )
            .unwrap_err()
            .kind,
            BrowserIngressErrorKind::ProtectedSurface
        );
    }

    #[test]
    fn query_fragment_and_text_cannot_ride_a_narrow_location_grant() {
        let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
        let mut query = envelope(1);
        query.location.as_mut().unwrap().query = Some("private=1".to_owned().into());
        assert_eq!(
            validator.ingest(query, NOW).unwrap_err().kind,
            BrowserIngressErrorKind::GranularityExceeded
        );

        let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
        let mut text = envelope(1);
        text.visible_text = Some("unapproved text".to_owned().into());
        assert_eq!(
            validator.ingest(text, NOW).unwrap_err().kind,
            BrowserIngressErrorKind::GranularityExceeded
        );
    }

    #[test]
    fn visible_text_is_independently_allowed_redacted_bounded_and_not_debuggable() {
        let policy = EdgeBrowserCapturePolicy {
            binding: binding(),
            scope: BrowserCaptureScope::VisibleText,
            authority_epoch: 9,
            maximum_payload_bytes: 96,
            minimum_interval: Duration::from_secs(5),
        };
        let mut value = envelope(1);
        value.location = None;
        value.visible_text = Some(
            "Atlas analyst@example.test password: synthetic-secret recommendation "
                .repeat(8)
                .into(),
        );
        let envelope_debug = format!("{value:?}");
        assert!(!envelope_debug.contains("synthetic-secret"));

        let mut validator = BrowserObservationValidator::new(policy).unwrap();
        let BrowserValidationOutcome::Emit(packet) = validator.ingest(value, NOW).unwrap() else {
            panic!("first observation must emit");
        };
        let text = packet.visible_text.as_ref().unwrap();
        assert!(text.len() <= 96);
        assert!(!text.expose().contains("synthetic-secret"));
        assert!(!text.expose().contains("analyst@example.test"));
        assert!(!format!("{packet:?}").contains("Atlas"));
    }

    #[test]
    fn lock_and_revocation_destroy_pending_and_reject_late_values() {
        for reason in [
            BrowserCaptureCancellation::Locked,
            BrowserCaptureCancellation::Revoked,
        ] {
            let mut validator = BrowserObservationValidator::new(location_policy()).unwrap();
            validator.ingest(envelope(1), NOW).unwrap();
            validator.ingest(envelope(2), NOW + 1_000).unwrap();
            validator.cancel(reason);
            assert_eq!(
                validator.flush_coalesced(NOW + 5_000).unwrap_err().kind,
                BrowserIngressErrorKind::Cancelled
            );
            assert_eq!(
                validator.ingest(envelope(3), NOW + 5_000).unwrap_err().kind,
                BrowserIngressErrorKind::Cancelled
            );
        }
    }

    #[test]
    fn malformed_oversize_stale_and_noncanonical_inputs_are_rejected() {
        let oversize_binding = "x".repeat(MAXIMUM_BINDING_BYTES + 1);
        for value in [
            "",
            "winbrowser:v2:edge-stable:00",
            "winbrowser:v1:edge-stable:00:00:00:00000000:00000000:00:00:00",
            &oversize_binding,
        ] {
            assert!(WindowsBrowserSurfaceBinding::parse(value).is_err());
        }

        let mut stale = envelope(1);
        stale.observed_at_unix_ms = NOW - MAXIMUM_STALE_MILLISECONDS - 1;
        assert_eq!(
            BrowserObservationValidator::new(location_policy())
                .unwrap()
                .ingest(stale, NOW)
                .unwrap_err()
                .kind,
            BrowserIngressErrorKind::Stale
        );

        let policy = EdgeBrowserCapturePolicy {
            binding: binding(),
            scope: BrowserCaptureScope::VisibleText,
            authority_epoch: 9,
            maximum_payload_bytes: 1024,
            minimum_interval: Duration::from_secs(5),
        };
        let mut oversize = envelope(1);
        oversize.location = None;
        oversize.visible_text = Some("x".repeat(MAXIMUM_VISIBLE_TEXT_INPUT_BYTES + 1).into());
        assert_eq!(
            BrowserObservationValidator::new(policy)
                .unwrap()
                .ingest(oversize, NOW)
                .unwrap_err()
                .kind,
            BrowserIngressErrorKind::Oversize
        );
    }
}
