use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! protocol_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a time-ordered identifier for a new CORE protocol object.
            #[must_use]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.into_uuid()
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

protocol_id!(ActorId);
protocol_id!(AuthorityId);
protocol_id!(CancellationId);
protocol_id!(ClientInstanceId);
protocol_id!(CorrelationId);
protocol_id!(DaemonInstanceId);
protocol_id!(DeliveryChannelId);
protocol_id!(DeviceId);
protocol_id!(FocusSessionId);
protocol_id!(GoalId);
protocol_id!(IdempotencyKey);
protocol_id!(InterventionId);
protocol_id!(MessageId);
protocol_id!(ModelRouteApprovalId);
protocol_id!(ObservationSourceId);
protocol_id!(PermissionGrantId);
protocol_id!(PolicyDecisionId);
protocol_id!(RequestId);
protocol_id!(SelectedResourceId);
protocol_id!(SnapshotId);
protocol_id!(TraceId);
