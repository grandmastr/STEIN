use serde::{Deserialize, Serialize};

use crate::{
    ActorId, AuthorityId, CancellationId, CorrelationId, IdempotencyKey, MessageId, TraceId,
    UtcTimestamp,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    LocalOsUser,
    Client,
    CoreDaemon,
    System,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    DesktopClient,
    CoreCli,
    CoreDaemon,
    CoreApplication,
    TestFixture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActorReference {
    pub actor_id: ActorId,
    pub kind: ActorKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorityReference {
    pub authority_id: AuthorityId,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityClass {
    Public,
    Operational,
    Personal,
    Sensitive,
    Restricted,
    HighlySensitive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    TransientProcessing,
    Ephemeral,
    Runtime,
    DurableUntilExpiry,
    DurableUntilDeleted,
    BoundedAudit,
    Operational,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestMetadata {
    pub message_id: MessageId,
    pub schema_version: u16,
    pub issued_at: UtcTimestamp,
    pub correlation_id: CorrelationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<MessageId>,
    pub origin: Component,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority: Vec<AuthorityReference>,
    pub sensitivity: SensitivityClass,
    pub retention: RetentionClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<IdempotencyKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_id: Option<CancellationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
}

impl RequestMetadata {
    #[must_use]
    pub fn new(
        origin: Component,
        sensitivity: SensitivityClass,
        retention: RetentionClass,
    ) -> Self {
        Self {
            message_id: MessageId::new_v7(),
            schema_version: crate::SCHEMA_VERSION_V1,
            issued_at: UtcTimestamp::now(),
            correlation_id: CorrelationId::new_v7(),
            causation_id: None,
            origin,
            authority: Vec::new(),
            sensitivity,
            retention,
            idempotency_key: None,
            deadline_at: None,
            cancellation_id: None,
            trace_context: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResponseMetadata {
    pub message_id: MessageId,
    pub schema_version: u16,
    pub issued_at: UtcTimestamp,
    pub correlation_id: CorrelationId,
    pub causation_id: MessageId,
    pub actor: ActorReference,
    pub origin: Component,
    pub sensitivity: SensitivityClass,
    pub retention: RetentionClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
}

impl ResponseMetadata {
    #[must_use]
    pub fn for_request(request: &RequestMetadata, actor: ActorReference) -> Self {
        Self {
            message_id: MessageId::new_v7(),
            schema_version: crate::SCHEMA_VERSION_V1,
            issued_at: UtcTimestamp::now(),
            correlation_id: request.correlation_id,
            causation_id: request.message_id,
            actor,
            origin: Component::CoreDaemon,
            sensitivity: request.sensitivity,
            retention: request.retention,
            trace_context: request.trace_context,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventMetadata {
    pub message_id: MessageId,
    pub schema_version: u16,
    pub occurred_at: UtcTimestamp,
    pub correlation_id: CorrelationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<MessageId>,
    pub actor: ActorReference,
    pub origin: Component,
    pub sensitivity: SensitivityClass,
    pub retention: RetentionClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
}

impl EventMetadata {
    #[must_use]
    pub fn caused_by(request: &RequestMetadata, actor: ActorReference) -> Self {
        Self {
            message_id: MessageId::new_v7(),
            schema_version: crate::SCHEMA_VERSION_V1,
            occurred_at: UtcTimestamp::now(),
            correlation_id: request.correlation_id,
            causation_id: Some(request.message_id),
            actor,
            origin: Component::CoreApplication,
            sensitivity: request.sensitivity,
            retention: request.retention,
            trace_context: request.trace_context,
        }
    }
}
