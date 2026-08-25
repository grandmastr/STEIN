//! Authenticated local transport for CORE's typed client protocol.
//!
//! Platform APIs are confined to this infrastructure crate. Domain and
//! application crates depend only on `stein-protocol` contracts.

#[cfg(all(feature = "private-client-test-harness", not(debug_assertions)))]
compile_error!(
    "private-client-test-harness is non-production only; release builds must use broker admission"
);

mod client;
mod codec;
mod server;

#[cfg(windows)]
mod windows;

pub use client::{Client, ClientError, ClientSubscription};
pub use codec::{MAX_FRAME_BYTES, read_frame, write_frame};
#[cfg(feature = "private-client-test-harness")]
pub use server::run_private_capability_bound_test_server;
pub use server::{
    PrivateServerIdentity, ServerConfig, ServerError, run_private_server, run_server,
};
pub use stein_core::ClientAssurance;

#[cfg(windows)]
pub(crate) const fn capability_supported(
    capability: stein_protocol::CapabilityId,
    negotiated: stein_protocol::ProtocolVersion,
) -> bool {
    let required = match capability {
        stein_protocol::CapabilityId::GoalUpdate
        | stein_protocol::CapabilityId::ModelRouteApproval
        | stein_protocol::CapabilityId::SessionPermissions
        | stein_protocol::CapabilityId::FocusSessions
        | stein_protocol::CapabilityId::CaptureState
        | stein_protocol::CapabilityId::DeliveryChannels
        | stein_protocol::CapabilityId::InterventionFeedback
        | stein_protocol::CapabilityId::InterventionHistory
        | stein_protocol::CapabilityId::InterventionExplanation => {
            stein_protocol::ProtocolVersion::V1_1
        }
        stein_protocol::CapabilityId::GoalDelete
        | stein_protocol::CapabilityId::SteinIdentity
        | stein_protocol::CapabilityId::UserPreferences
        | stein_protocol::CapabilityId::EffectivePolicy
        | stein_protocol::CapabilityId::SelectedResources => stein_protocol::ProtocolVersion::V1_2,
        stein_protocol::CapabilityId::Snapshot
        | stein_protocol::CapabilityId::RuntimeStatus
        | stein_protocol::CapabilityId::GoalCreate
        | stein_protocol::CapabilityId::DelayEcho
        | stein_protocol::CapabilityId::RuntimeShutdown
        | stein_protocol::CapabilityId::ViewEvents
        | stein_protocol::CapabilityId::RequestCancellation
        | stein_protocol::CapabilityId::DesktopObservation
        | stein_protocol::CapabilityId::ModelReasoning
        | stein_protocol::CapabilityId::DurablePersistence
        | stein_protocol::CapabilityId::NativeNotification
        | stein_protocol::CapabilityId::NativeStatus
        | stein_protocol::CapabilityId::EmergencyControl
        | stein_protocol::CapabilityId::SecretStore => stein_protocol::ProtocolVersion::V1_0,
    };
    negotiated.major == required.major && negotiated.minor >= required.minor
}

#[cfg(windows)]
pub use windows::{current_user_sid, default_pipe_name};

/// A randomized, non-production named-pipe endpoint for the retained private
/// client compatibility harness.
///
/// The endpoint is deliberately distinct from CORE's production pipe. Merely
/// enabling the harness feature therefore cannot upgrade ordinary same-user
/// diagnostic connections to private sessions.
#[cfg(all(feature = "private-client-test-harness", windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateTestEndpoint {
    pipe_name: String,
}

#[cfg(all(feature = "private-client-test-harness", not(windows)))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateTestEndpoint;

#[cfg(all(feature = "private-client-test-harness", windows))]
impl PrivateTestEndpoint {
    pub fn new() -> Result<Self, std::io::Error> {
        let sid = current_user_sid()?;
        let safe_sid: String = sid
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
            .collect();
        Ok(Self {
            pipe_name: format!(
                r"\\.\pipe\stein-core-private-test-{safe_sid}-{}",
                uuid::Uuid::now_v7()
            ),
        })
    }

    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

#[cfg(all(feature = "private-client-test-harness", not(windows)))]
impl PrivateTestEndpoint {
    pub fn new() -> Result<Self, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the private client test harness is implemented on Windows first",
        ))
    }
}

#[cfg(not(windows))]
pub fn default_pipe_name() -> Result<String, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the Phase 1 native transport is implemented on Windows first",
    ))
}
