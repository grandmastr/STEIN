//! Windows-native adapters for CORE.
//!
//! Native handles and Windows SDK types stay in this crate. Public APIs expose
//! only CORE types and small, content-free status values.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod application_binding;
mod browser;
mod browser_ingress;
mod credential;
#[cfg(windows)]
mod edge_launch;
#[cfg(windows)]
mod foreground;
#[cfg(any(windows, test))]
mod native_surface;
#[cfg(any(windows, test))]
mod notification;
#[cfg(windows)]
mod observation;
mod presence;
#[cfg(windows)]
mod selected_resource;
#[cfg(windows)]
mod selected_resource_binding;
#[cfg(windows)]
mod uia;
#[cfg(windows)]
mod uia_binding;

pub use application_binding::{
    ApplicationBindingError, WindowsApplicationBinding, WindowsPackagedApplicationIdentity,
    WindowsUnpackagedApplicationIdentity,
};
pub use browser::{
    BrowserCaptureCancellation, BrowserCaptureScope, BrowserIngressError, BrowserIngressErrorKind,
    BrowserLocationFields, BrowserObservationEnvelope, BrowserObservationPacket,
    BrowserObservationValidator, BrowserPageKind, BrowserValidationOutcome,
    EDGE_BROWSER_EXTRACTION_VERSION, EDGE_BROWSER_MAXIMUM_NATIVE_MESSAGE_BYTES,
    EDGE_BROWSER_REDACTION_VERSION, EDGE_NATIVE_HOST_NAME, EdgeBrowserCapturePolicy,
    EdgeBrowserSelection, WindowsBrowserSurfaceBinding,
};
pub use browser_ingress::{
    AuthorizedBrowserObservation, BrowserAuthoritySnapshotPort, BrowserObservationProducerIngress,
    BrowserProducerAuthorityReference, BrowserProducerConnectionAuthority,
    BrowserProducerIngressError, BrowserProducerIngressErrorKind, CurrentBrowserProducerAuthority,
    EDGE_BROWSER_PRODUCER_APPLICATION_ID, EDGE_BROWSER_PRODUCER_PIPE,
    EDGE_BROWSER_PRODUCER_SOURCE_ID, EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON,
    admit_release_managed_edge_producer,
};
pub use credential::{MODEL_ROUTE_TARGET_PREFIX, WindowsCredentialSecretStore};
#[cfg(windows)]
pub use edge_launch::{
    EdgeLaunchError, EdgeLaunchErrorKind, EdgeNativeHostLaunchPolicy, VerifiedEdgeNativeHostLaunch,
    verify_current_edge_native_host_launch,
};
pub use presence::{PresenceEvent, PresenceSignal, PresenceTracker, PresenceUpdateSource};

#[cfg(windows)]
pub use presence::{PresenceMonitorError, WindowsPresenceMonitor};

#[cfg(windows)]
pub use native_surface::{WindowsNativeSurface, WindowsNativeSurfaceError};
#[cfg(windows)]
pub use notification::{
    WindowsNotificationConfig, WindowsNotificationError, WindowsNotificationPort,
    WindowsToastRegistrationHealth,
};
#[cfg(windows)]
pub use observation::WindowsObservationPort;
#[cfg(windows)]
pub use selected_resource_binding::{
    SelectedResourceBindingError, WindowsDocumentFormat, WindowsSelectedResourceBinding,
};
