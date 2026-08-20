use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Authenticated actor resolved by the transport boundary.
///
/// This value must never be populated from an actor claimed inside an untrusted
/// request payload.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ActorId(Uuid);

impl ActorId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl From<stein_protocol::ActorId> for ActorId {
    fn from(value: stein_protocol::ActorId) -> Self {
        Self(value.into_uuid())
    }
}

impl From<ActorId> for stein_protocol::ActorId {
    fn from(value: ActorId) -> Self {
        Self::from_uuid(value.as_uuid())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GoalId(Uuid);

impl GoalId {
    pub(crate) fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for GoalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<stein_protocol::GoalId> for GoalId {
    fn from(value: stein_protocol::GoalId) -> Self {
        Self(value.into_uuid())
    }
}

impl From<GoalId> for stein_protocol::GoalId {
    fn from(value: GoalId) -> Self {
        Self::from_uuid(value.as_uuid())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub const INITIAL: Self = Self(1);

    pub fn new(value: u64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("revision space exhausted"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalState {
    Active,
    Completed,
    Abandoned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Goal {
    pub id: GoalId,
    pub owner: ActorId,
    pub title: String,
    pub success_statement: String,
    pub deadline: Option<OffsetDateTime>,
    pub state: GoalState,
    pub revision: Revision,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(Uuid);

impl IdempotencyKey {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl From<stein_protocol::IdempotencyKey> for IdempotencyKey {
    fn from(value: stein_protocol::IdempotencyKey) -> Self {
        Self(value.into_uuid())
    }
}

impl From<IdempotencyKey> for stein_protocol::IdempotencyKey {
    fn from(value: IdempotencyKey) -> Self {
        Self::from_uuid(value.as_uuid())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateGoal {
    pub actor: ActorId,
    pub idempotency_key: IdempotencyKey,
    pub title: String,
    pub success_statement: String,
    pub deadline: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GoalPatch {
    pub title: Option<String>,
    pub success_statement: Option<String>,
    /// `None` leaves the deadline unchanged. `Some(None)` clears it.
    pub deadline: Option<Option<OffsetDateTime>>,
}

impl GoalPatch {
    pub fn is_empty(&self) -> bool {
        self.title.is_none() && self.success_statement.is_none() && self.deadline.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateGoal {
    pub actor: ActorId,
    pub id: GoalId,
    pub expected_revision: Revision,
    pub patch: GoalPatch,
}
