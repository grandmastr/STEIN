use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    ChannelAcknowledgement, DeliveryChannelStatus, EmergencyCommandAcknowledgement,
    EmergencyCommandEnvelope, NativeCaptureStatus, NativeStatusAcknowledgement, NativeStatusError,
    NativeStatusHeartbeat, NotificationDelivery, NotificationPortError, PortFuture, ResourceKind,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreConfig {
    pub event_buffer_capacity: usize,
    pub maximum_goal_count: usize,
    pub maximum_delay_echo: Duration,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            event_buffer_capacity: 256,
            maximum_goal_count: 1_000,
            maximum_delay_echo: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub summary: &'static str,
}

pub trait ConfigProvider: Send + Sync {
    fn load(&self) -> Result<CoreConfig, ConfigError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformPortAvailability {
    Available,
    Unavailable { reason: &'static str },
}

impl PlatformPortAvailability {
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    pub const fn detail(self) -> &'static str {
        match self {
            Self::Available => "The platform capability is available.",
            Self::Unavailable { reason } => reason,
        }
    }
}

pub trait NotificationPort: Send + Sync {
    fn availability(&self) -> PlatformPortAvailability;

    fn deliver<'a>(
        &'a self,
        _delivery: &'a NotificationDelivery,
        _cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<ChannelAcknowledgement, NotificationPortError>> {
        Box::pin(async {
            Err(NotificationPortError {
                summary: "Native notification delivery is unavailable.",
                retryable: true,
            })
        })
    }

    fn status<'a>(&'a self) -> PortFuture<'a, DeliveryChannelStatus> {
        Box::pin(async {
            DeliveryChannelStatus {
                channel_id: "native_notification".to_owned(),
                health: crate::DeliveryChannelHealth::Unavailable,
                detail: "Native notification delivery is unavailable.",
                observed_at: time::OffsetDateTime::now_utc(),
            }
        })
    }
}

pub trait NativeStatusPort: Send + Sync {
    fn availability(&self) -> PlatformPortAvailability;

    fn publish<'a>(
        &'a self,
        _status: &'a NativeCaptureStatus,
    ) -> PortFuture<'a, Result<NativeStatusAcknowledgement, NativeStatusError>> {
        Box::pin(async {
            Err(NativeStatusError {
                summary: "Native background status is unavailable.",
                retryable: true,
            })
        })
    }

    fn clear<'a>(
        &'a self,
        _session_id: crate::FocusSessionId,
        _revision: u64,
    ) -> PortFuture<'a, Result<NativeStatusAcknowledgement, NativeStatusError>> {
        Box::pin(async {
            Err(NativeStatusError {
                summary: "Native background status is unavailable.",
                retryable: true,
            })
        })
    }

    /// Waits for the next adapter-originated heartbeat for `session_id`.
    ///
    /// Implementations must route concurrent sessions independently and return
    /// an error as soon as the native registration or message loop is lost.
    /// CORE validates the returned session and status revision and owns the
    /// heartbeat deadline; this is deliberately not an availability poll.
    fn next_heartbeat<'a>(
        &'a self,
        _session_id: crate::FocusSessionId,
    ) -> PortFuture<'a, Result<NativeStatusHeartbeat, NativeStatusError>> {
        Box::pin(async {
            Err(NativeStatusError {
                summary: "Native background status heartbeat is unavailable.",
                retryable: true,
            })
        })
    }
}

pub trait EmergencyControlPort: Send + Sync {
    fn availability(&self) -> PlatformPortAvailability;

    fn next_command<'a>(
        &'a self,
    ) -> PortFuture<'a, Result<EmergencyCommandEnvelope, &'static str>> {
        Box::pin(async { Err("Independent emergency control is unavailable.") })
    }

    fn acknowledge<'a>(
        &'a self,
        _acknowledgement: EmergencyCommandAcknowledgement,
    ) -> PortFuture<'a, Result<EmergencyCommandAcknowledgement, &'static str>> {
        Box::pin(async { Err("Independent emergency control is unavailable.") })
    }
}

/// Platform-owned identity for a native selection. It is deliberately neither
/// serializable nor debuggable so handles, paths, URLs, and registry keys do
/// not cross protocol or telemetry boundaries.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeResourceBinding(String);

impl NativeResourceBinding {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for NativeResourceBinding {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A completed native picker result. CORE supplies durable identity and time;
/// the platform adapter supplies only native binding and privacy-safe label.
pub struct NativeSelectedResource {
    pub kind: ResourceKind,
    pub binding: NativeResourceBinding,
    pub safe_display_label: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceSelectionErrorKind {
    Cancelled,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSelectionError {
    pub kind: ResourceSelectionErrorKind,
    pub summary: &'static str,
    pub retryable: bool,
}

pub trait ResourceSelectionPort: Send + Sync {
    fn availability(&self) -> PlatformPortAvailability;

    fn select<'a>(
        &'a self,
        _kind: ResourceKind,
        _cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<Option<NativeSelectedResource>, ResourceSelectionError>> {
        Box::pin(async {
            Err(ResourceSelectionError {
                kind: ResourceSelectionErrorKind::Unavailable,
                summary: "Native resource selection is unavailable.",
                retryable: true,
            })
        })
    }

    fn release<'a>(
        &'a self,
        _binding: NativeResourceBinding,
        _cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<(), ResourceSelectionError>> {
        Box::pin(async {
            Err(ResourceSelectionError {
                kind: ResourceSelectionErrorKind::Unavailable,
                summary: "Native resource cleanup is unavailable.",
                retryable: true,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableNotificationPort;

impl NotificationPort for UnavailableNotificationPort {
    fn availability(&self) -> PlatformPortAvailability {
        PlatformPortAvailability::Unavailable {
            reason: "Native notification delivery is not implemented in Phase 1.",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableNativeStatusPort;

impl NativeStatusPort for UnavailableNativeStatusPort {
    fn availability(&self) -> PlatformPortAvailability {
        PlatformPortAvailability::Unavailable {
            reason: "Native background status is not implemented in Phase 1.",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableEmergencyControlPort;

impl EmergencyControlPort for UnavailableEmergencyControlPort {
    fn availability(&self) -> PlatformPortAvailability {
        PlatformPortAvailability::Unavailable {
            reason: "Independent emergency control is not implemented in Phase 1.",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableResourceSelectionPort;

impl ResourceSelectionPort for UnavailableResourceSelectionPort {
    fn availability(&self) -> PlatformPortAvailability {
        PlatformPortAvailability::Unavailable {
            reason: "Native resource selection is not configured.",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StaticConfigProvider {
    config: CoreConfig,
}

impl StaticConfigProvider {
    pub fn new(config: CoreConfig) -> Self {
        Self { config }
    }
}

impl Default for StaticConfigProvider {
    fn default() -> Self {
        Self::new(CoreConfig::default())
    }
}

impl ConfigProvider for StaticConfigProvider {
    fn load(&self) -> Result<CoreConfig, ConfigError> {
        Ok(self.config.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecretKey(String);

impl SecretKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque durable reference to a platform secret. The name is intentionally
/// non-secret and is safe to persist; the referenced value is not.
pub type SecretRef = SecretKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretPurpose {
    ModelProviderCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretHealthState {
    Healthy,
    Missing,
    Locked,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretStoreHealth {
    pub configured: bool,
    pub state: SecretHealthState,
}

/// A secret intentionally omits `Debug`, `Display`, equality, and serialization.
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretStoreError {
    pub kind: SecretStoreErrorKind,
    pub summary: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStoreErrorKind {
    NotFound,
    InvalidReference,
    ValueTooLarge,
    Unavailable,
    AccessDenied,
    Locked,
    Internal,
}

pub trait SecretStore: Send + Sync {
    fn is_available(&self) -> bool;
    fn health(&self, key: &SecretRef, _purpose: SecretPurpose) -> SecretStoreHealth {
        match self.read(key) {
            Ok(Some(_)) => SecretStoreHealth {
                configured: true,
                state: SecretHealthState::Healthy,
            },
            Ok(None) => SecretStoreHealth {
                configured: false,
                state: SecretHealthState::Missing,
            },
            Err(error) if error.kind == SecretStoreErrorKind::Locked => SecretStoreHealth {
                configured: true,
                state: SecretHealthState::Locked,
            },
            Err(_) => SecretStoreHealth {
                configured: false,
                state: SecretHealthState::Unavailable,
            },
        }
    }
    fn read(&self, key: &SecretKey) -> Result<Option<SecretValue>, SecretStoreError>;

    fn write(&self, _key: &SecretKey, _value: &SecretValue) -> Result<(), SecretStoreError> {
        Err(SecretStoreError {
            kind: SecretStoreErrorKind::Unavailable,
            summary: "The secret store is read-only or unavailable.",
        })
    }

    fn delete(&self, _key: &SecretKey) -> Result<bool, SecretStoreError> {
        Err(SecretStoreError {
            kind: SecretStoreErrorKind::Unavailable,
            summary: "The secret store is read-only or unavailable.",
        })
    }
}

/// Honest Phase 1 fake: it never fabricates secret availability or values.
#[derive(Clone)]
pub struct UnavailableSecretStore {
    reason: &'static str,
}

impl UnavailableSecretStore {
    pub fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl Default for UnavailableSecretStore {
    fn default() -> Self {
        Self::new("No platform secret store is configured.")
    }
}

impl fmt::Debug for UnavailableSecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnavailableSecretStore")
            .field("available", &false)
            .finish()
    }
}

impl SecretStore for UnavailableSecretStore {
    fn is_available(&self) -> bool {
        false
    }

    fn read(&self, _key: &SecretKey) -> Result<Option<SecretValue>, SecretStoreError> {
        Err(SecretStoreError {
            kind: SecretStoreErrorKind::Unavailable,
            summary: self.reason,
        })
    }
}
