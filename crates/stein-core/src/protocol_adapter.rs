use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::view_publication::EventContext;
use crate::{
    ApplicationError, ClientSnapshot, CoreApplication, CoreEvent, DelayEcho, ErrorCode, Goal,
    GoalState, RuntimeHealth, RuntimeStatus,
};
use stein_protocol as wire;

/// A privacy-filtered view event paired with the daemon-instance cursor that
/// the IPC adapter will place in its event envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolEvent {
    pub message_id: wire::MessageId,
    pub occurred_at: wire::UtcTimestamp,
    pub actor: wire::ActorReference,
    pub correlation_id: wire::CorrelationId,
    pub causation_id: Option<wire::MessageId>,
    pub sensitivity: wire::SensitivityClass,
    pub retention: wire::RetentionClass,
    pub cursor: wire::EventCursor,
    pub event: wire::ViewEvent,
}

/// An atomic protocol snapshot and its already-registered event subscription.
pub struct ProtocolSubscription {
    pub snapshot: wire::ClientSnapshot,
    inner: crate::Subscription,
    active_connections: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolRequestContext {
    pub actor: wire::ActorId,
    pub client_id: wire::ClientInstanceId,
    pub assurance: crate::ClientAssurance,
    pub negotiated_version: wire::ProtocolVersion,
}

impl ProtocolSubscription {
    pub async fn receive(&mut self) -> Result<ProtocolEvent, crate::EventStreamError> {
        let event = self.inner.receive().await?;
        let actor_kind = match event.actor_kind {
            crate::CoreEventActorKind::LocalOsUser => wire::ActorKind::LocalOsUser,
            crate::CoreEventActorKind::CoreDaemon => wire::ActorKind::CoreDaemon,
            crate::CoreEventActorKind::System => wire::ActorKind::System,
        };
        let view_event = event_to_wire(event.event, self.active_connections);
        let event_kind = view_event.kind();
        Ok(ProtocolEvent {
            message_id: wire::MessageId::from_uuid(event.event_id),
            occurred_at: wire::UtcTimestamp::from_datetime(event.occurred_at),
            actor: wire::ActorReference {
                actor_id: event.actor.into(),
                kind: actor_kind,
            },
            correlation_id: wire::CorrelationId::from_uuid(event.correlation_id),
            causation_id: event.causation_id.map(wire::MessageId::from_uuid),
            sensitivity: event_kind.sensitivity(),
            retention: event_kind.retention(),
            cursor: cursor(self.inner.snapshot.runtime.daemon_instance_id, event.cursor),
            event: view_event,
        })
    }
}

impl CoreApplication {
    /// Atomically creates the first client snapshot and registers for every
    /// later view event. This is the application-side half of session opening.
    pub fn open_protocol_subscription(
        &self,
        actor: wire::ActorId,
        active_connections: u32,
    ) -> Result<ProtocolSubscription, ApplicationError> {
        let owner: crate::ActorId = actor.into();
        self.second_mind()
            .stein_identity(crate::ClientAssurance::PrivateCapabilityBound, owner)
            .map_err(crate::application::second_mind_error_to_application)?;
        self.second_mind()
            .user_preferences(crate::ClientAssurance::PrivateCapabilityBound, owner)
            .map_err(crate::application::second_mind_error_to_application)?;
        self.second_mind()
            .current_device(crate::ClientAssurance::PrivateCapabilityBound, owner)
            .map_err(crate::application::second_mind_error_to_application)?;
        let (inner, snapshot) = self.open_subscription_with(&owner, |base, owner_state| {
            Ok(snapshot_to_wire(
                base,
                active_connections,
                Some(phase2_snapshot_to_wire(
                    self.second_mind(),
                    owner,
                    owner_state,
                )),
            ))
        })?;
        Ok(ProtocolSubscription {
            snapshot,
            inner,
            active_connections,
        })
    }

    /// Executes one typed request after transport authentication. The actor is
    /// supplied by the local transport and never read from the request body.
    pub async fn handle_protocol_request(
        &self,
        actor: wire::ActorId,
        request: &wire::RequestEnvelope,
        active_connections: u32,
        cancellation: CancellationToken,
    ) -> Result<wire::ResponseBody, wire::PublicError> {
        self.handle_protocol_request_with_context(
            ProtocolRequestContext {
                actor,
                client_id: wire::ClientInstanceId::from_uuid(actor.into_uuid()),
                assurance: crate::ClientAssurance::PrivateCapabilityBound,
                negotiated_version: wire::ProtocolVersion::CURRENT,
            },
            request,
            active_connections,
            cancellation,
        )
        .await
    }

    pub async fn handle_protocol_request_with_context(
        &self,
        context: ProtocolRequestContext,
        request: &wire::RequestEnvelope,
        active_connections: u32,
        cancellation: CancellationToken,
    ) -> Result<wire::ResponseBody, wire::PublicError> {
        let actor = context.actor;
        if request.metadata.schema_version != wire::SCHEMA_VERSION_V1 {
            return Err(unsupported_schema(request));
        }
        let required_version = request.body.minimum_protocol_version();
        if required_version.major != context.negotiated_version.major
            || required_version.minor > context.negotiated_version.minor
        {
            return Err(wire::PublicError {
                code: wire::ErrorCode::IncompatibleProtocol,
                category: wire::ErrorCategory::IncompatibleVersion,
                summary: "The request requires a newer negotiated protocol version.".to_owned(),
                retryable: false,
                correlation_id: request.metadata.correlation_id,
                details: Some(wire::ErrorDetails::Compatibility(
                    wire::CompatibilityErrorDetails {
                        client_support: wire::ProtocolSupport::exact(context.negotiated_version),
                        server_support: wire::ProtocolSupport::V1,
                    },
                )),
            });
        }
        if !matches!(
            context.assurance,
            crate::ClientAssurance::PrivateCapabilityBound
        ) && !matches!(
            request.body,
            wire::RequestBody::GetRuntimeStatus(_) | wire::RequestBody::GetCapabilityHealth(_)
        ) {
            return Err(wire::PublicError {
                code: wire::ErrorCode::PermissionDenied,
                category: wire::ErrorCategory::PermissionDenied,
                summary: "This connection is not admitted for private protocol operations."
                    .to_owned(),
                retryable: false,
                correlation_id: request.metadata.correlation_id,
                details: None,
            });
        }
        if request
            .metadata
            .deadline_at
            .is_some_and(|deadline| deadline.as_datetime() <= time::OffsetDateTime::now_utc())
        {
            return Err(error_to_wire(
                ApplicationError {
                    code: ErrorCode::DeadlineExceeded,
                    summary: "The request deadline elapsed.",
                    retryable: true,
                    field_violations: Vec::new(),
                    current_revision: None,
                },
                request.metadata.correlation_id,
            ));
        }

        let result: Result<wire::ResponseBody, ApplicationError> = async {
            match &request.body {
                wire::RequestBody::CreateGoal(input) => {
                    let key = request.metadata.idempotency_key.ok_or_else(|| {
                        invalid_application("CreateGoal requires an idempotency key.")
                    })?;
                    self.create_goal_with_context(
                        crate::CreateGoal {
                            actor: actor.into(),
                            idempotency_key: key.into(),
                            title: input.title.clone(),
                            success_statement: input.success_statement.clone(),
                            deadline: input.deadline.map(|value| value.as_datetime()),
                        },
                        EventContext {
                            actor: actor.into(),
                            actor_kind: crate::CoreEventActorKind::LocalOsUser,
                            correlation_id: request.metadata.correlation_id.into_uuid(),
                            causation_id: Some(request.metadata.message_id.into_uuid()),
                        },
                    )
                    .map(|goal| {
                        wire::ResponseBody::CreateGoal(wire::CreateGoalResponse {
                            goal: goal_to_wire(&goal),
                        })
                    })
                }
                wire::RequestBody::UpdateGoal(input) => {
                    let expected_revision = crate::Revision::new(input.expected_revision)
                        .ok_or_else(|| invalid_application("The expected revision is invalid."))?;
                    self.update_goal(crate::UpdateGoal {
                        actor: actor.into(),
                        id: input.goal_id.into(),
                        expected_revision,
                        patch: crate::GoalPatch {
                            title: input.patch.title.clone(),
                            success_statement: input.patch.success_statement.clone(),
                            deadline: input.patch.deadline.as_ref().map(
                                |deadline| match deadline {
                                    wire::GoalDeadlinePatch::Clear => None,
                                    wire::GoalDeadlinePatch::Set { deadline } => {
                                        Some(deadline.as_datetime())
                                    }
                                },
                            ),
                        },
                    })
                    .map(|goal| {
                        wire::ResponseBody::UpdateGoal(Box::new(wire::UpdateGoalResponse {
                            goal: goal_to_wire(&goal),
                        }))
                    })
                }
                wire::RequestBody::CompleteGoal(input) => self
                    .set_goal_state_with_context(
                        actor.into(),
                        input.goal_id.into(),
                        input.expected_revision,
                        GoalState::Completed,
                        event_context(request, actor),
                    )
                    .await
                    .map(|goal| {
                        wire::ResponseBody::CompleteGoal(Box::new(wire::CompleteGoalResponse {
                            goal: goal_to_wire(&goal),
                        }))
                    }),
                wire::RequestBody::AbandonGoal(input) => {
                    if input.reason.as_ref().is_some_and(|reason| {
                        reason.trim().is_empty() || reason.chars().count() > 240
                    }) {
                        Err(invalid_application("The abandonment reason is invalid."))
                    } else {
                        self.set_goal_state_with_context(
                            actor.into(),
                            input.goal_id.into(),
                            input.expected_revision,
                            GoalState::Abandoned,
                            event_context(request, actor),
                        )
                        .await
                        .map(|goal| {
                            wire::ResponseBody::AbandonGoal(Box::new(wire::AbandonGoalResponse {
                                goal: goal_to_wire(&goal),
                            }))
                        })
                    }
                }
                wire::RequestBody::ApproveModelRoute(input) => {
                    let idempotency = crate::IdempotencyContext {
                        key: require_idempotency(request)?,
                        request_digest: stable_request_digest(input)?,
                    };
                    let categories: std::collections::BTreeSet<_> = input
                        .allowed_data_categories
                        .iter()
                        .copied()
                        .map(data_category_from_wire)
                        .collect();
                    if categories.len() != input.allowed_data_categories.len() {
                        Err(invalid_application(
                            "Model route data categories must be unique.",
                        ))
                    } else {
                        let now = time::OffsetDateTime::now_utc();
                        let approval_id = crate::ModelRouteApprovalId::new_v7();
                        let route = crate::ModelRouteApproval {
                            id: approval_id,
                            revision: 1,
                            owner: actor.into(),
                            authenticated_client: crate::ClientId::from_uuid(
                                context.client_id.into_uuid(),
                            ),
                            provider: input.route.provider_id.clone(),
                            account_profile: input.account_profile.clone(),
                            model: input.route.route_id.clone(),
                            secret_ref: crate::ModelRouteApproval::approval_scoped_secret_ref(
                                approval_id,
                            ),
                            placement: model_placement_from_wire(input.route.placement),
                            allowed_categories: categories,
                            handling: crate::ModelHandlingProfile {
                                profile_id: input.handling.profile_version.clone(),
                                retention: provider_retention_from_wire(&input.handling.retention),
                                training_use: provider_training_from_wire(
                                    input.handling.training_use,
                                ),
                                data_residency: input.handling.data_residency.clone(),
                                core_persists_prompt_or_response: false,
                                tools_enabled: false,
                            },
                            purpose: input.purpose.clone(),
                            maximum_input_tokens: input.maximum_request_tokens,
                            maximum_output_tokens: 512,
                            fallback: input.fallback.as_ref().map(model_route_reference_from_wire),
                            fallback_allowed: input.fallback.is_some(),
                            effective_at: now,
                            expires_at: input.expires_at.map(|value| value.as_datetime()),
                            revoked_at: None,
                            disclosure_version: input.disclosure_version.clone(),
                        };
                        self.second_mind()
                            .approve_model_route(context.assurance, idempotency, route)
                            .map_err(crate::application::second_mind_error_to_application)
                            .map(|approval| {
                                wire::ResponseBody::ApproveModelRoute(Box::new(
                                    wire::ApproveModelRouteResponse {
                                        approval: model_route_to_wire(&approval, now),
                                    },
                                ))
                            })
                    }
                }
                wire::RequestBody::GrantSessionPermission(input) => {
                    let idempotency = crate::IdempotencyContext {
                        key: require_idempotency(request)?,
                        request_digest: stable_request_digest(input)?,
                    };
                    let now = time::OffsetDateTime::now_utc();
                    let device_id = if context.negotiated_version.minor
                        >= wire::ProtocolVersion::V1_2.minor
                    {
                        self.second_mind()
                            .current_device(context.assurance, actor.into())
                            .map_err(crate::application::second_mind_error_to_application)?
                            .device_id
                    } else {
                        crate::DeviceId::from_uuid(
                            input
                                .device_id
                                .ok_or_else(|| {
                                    invalid_application("Protocol 1.1 requires a device identity.")
                                })?
                                .into_uuid(),
                        )
                    };
                    self.second_mind()
                        .grant_permission(
                            context.assurance,
                            crate::GrantPermission {
                                idempotency,
                                owner: actor.into(),
                                goal_id: input.goal_id.into(),
                                client_id: crate::ClientId::from_uuid(
                                    context.client_id.into_uuid(),
                                ),
                                device_id,
                                scope: permission_scope_from_wire(input.scope),
                                selected_resource_id: input
                                    .selected_resource_id
                                    .map(|id| crate::ResourceId::from_uuid(id.into_uuid())),
                                purpose: input.purpose.clone(),
                                client_disconnect_allowed: input
                                    .continuity
                                    .while_client_disconnected,
                                daemon_restart_allowed: input.continuity.after_daemon_restart,
                                effective_at: now,
                                expires_at: input.expires_at.as_datetime(),
                                consent_copy_version: input.consent_copy_version.clone(),
                            },
                        )
                        .map_err(crate::application::second_mind_error_to_application)
                        .map(|permission| {
                            wire::ResponseBody::GrantSessionPermission(Box::new(
                                wire::GrantSessionPermissionResponse {
                                    permission: grant_to_wire(&permission, now),
                                },
                            ))
                        })
                }
                wire::RequestBody::RevokePermission(input) => match input.target {
                    wire::PermissionReference::SessionGrant {
                        permission_grant_id,
                    } => self
                        .second_mind()
                        .revoke_permission(
                            context.assurance,
                            actor.into(),
                            crate::PermissionGrantId::from_uuid(permission_grant_id.into_uuid()),
                            input.expected_revision,
                            input.reason.clone(),
                        )
                        .await
                        .map_err(crate::application::second_mind_error_to_application)
                        .map(|permission| {
                            wire::ResponseBody::RevokePermission(Box::new(
                                wire::RevokePermissionResponse {
                                    permission: wire::PermissionRecordView::SessionGrant(
                                        grant_to_wire(&permission, time::OffsetDateTime::now_utc()),
                                    ),
                                },
                            ))
                        }),
                    wire::PermissionReference::ModelRouteApproval {
                        model_route_approval_id,
                    } => self
                        .second_mind()
                        .revoke_model_route(
                            context.assurance,
                            actor.into(),
                            crate::ModelRouteApprovalId::from_uuid(
                                model_route_approval_id.into_uuid(),
                            ),
                            input.expected_revision,
                            input.reason.clone(),
                        )
                        .await
                        .map_err(crate::application::second_mind_error_to_application)
                        .map(|approval| {
                            wire::ResponseBody::RevokePermission(Box::new(
                                wire::RevokePermissionResponse {
                                    permission: wire::PermissionRecordView::ModelRouteApproval(
                                        model_route_to_wire(
                                            &approval,
                                            time::OffsetDateTime::now_utc(),
                                        ),
                                    ),
                                },
                            ))
                        }),
                },
                wire::RequestBody::StartFocusSession(input) => {
                    let idempotency = crate::IdempotencyContext {
                        key: require_idempotency(request)?,
                        request_digest: stable_request_digest(input)?,
                    };
                    let owner: crate::ActorId = actor.into();
                    let state = self
                        .second_mind()
                        .owner_state_snapshot(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    let selected_ids: std::collections::BTreeSet<_> = input
                        .selected_resource_ids
                        .iter()
                        .map(|id| crate::ResourceId::from_uuid(id.into_uuid()))
                        .collect();
                    let grant_ids: std::collections::BTreeSet<_> = input
                        .permission_grant_ids
                        .iter()
                        .map(|id| crate::PermissionGrantId::from_uuid(id.into_uuid()))
                        .collect();
                    if selected_ids.len() != input.selected_resource_ids.len()
                        || grant_ids.len() != input.permission_grant_ids.len()
                    {
                        Err(invalid_application(
                            "Focus-session resource and permission identifiers must be unique.",
                        ))
                    } else {
                        let selected_grants: Vec<_> = state
                            .grants
                            .iter()
                            .filter(|grant| grant_ids.contains(&grant.id))
                            .collect();
                        let client_disconnect_allowed = selected_grants
                            .iter()
                            .all(|grant| grant.client_disconnect_allowed);
                        let daemon_restart_allowed = selected_grants
                            .iter()
                            .all(|grant| grant.daemon_restart_allowed);
                        let starting = self
                            .second_mind()
                            .request_focus_session(
                                context.assurance,
                                crate::StartFocusSession {
                                    idempotency,
                                    owner,
                                    session_id: crate::FocusSessionId::new_v7(),
                                    goal_id: input.goal_id.into(),
                                    expected_goal_revision: input.goal_revision,
                                    selected_resource_ids: selected_ids,
                                    grant_ids,
                                    model_route_approval_id: crate::ModelRouteApprovalId::from_uuid(
                                        input.model_route_approval_id.into_uuid(),
                                    ),
                                    client_disconnect_allowed,
                                    daemon_restart_allowed,
                                },
                            )
                            .map_err(crate::application::second_mind_error_to_application)?;
                        let runtime = self.second_mind().clone();
                        let starting_for_activation = starting.clone();
                        let activation_owner = starting.owner;
                        let activation_session_id = starting.id;
                        tokio::spawn(async move {
                            let activation_runtime = runtime.clone();
                            let activation = tokio::spawn(async move {
                                activation_runtime
                                    .activate_focus_session(
                                        crate::ClientAssurance::PrivateCapabilityBound,
                                        starting_for_activation.owner,
                                        starting_for_activation.id,
                                        starting_for_activation.revision,
                                    )
                                    .await
                            });
                            match activation.await {
                                Ok(Ok(_)) => {}
                                Ok(Err(_)) => {
                                    let _ = runtime
                                        .fail_detached_focus_activation(
                                            activation_owner,
                                            activation_session_id,
                                            false,
                                            "detached_activation_failed",
                                        )
                                        .await;
                                }
                                Err(_) => {
                                    let _ = runtime
                                        .fail_detached_focus_activation(
                                            activation_owner,
                                            activation_session_id,
                                            true,
                                            "detached_activation_panicked",
                                        )
                                        .await;
                                }
                            }
                        });
                        Ok(wire::ResponseBody::StartFocusSession(Box::new(
                            wire::StartFocusSessionResponse {
                                focus_session: focus_session_to_wire(&starting),
                            },
                        )))
                    }
                }
                wire::RequestBody::SetInterventionsMuted(input) => self
                    .second_mind()
                    .set_interventions_muted(
                        context.assurance,
                        actor.into(),
                        crate::FocusSessionId::from_uuid(input.focus_session_id.into_uuid()),
                        input.expected_revision,
                        input.muted,
                    )
                    .await
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|focus_session| {
                        wire::ResponseBody::SetInterventionsMuted(Box::new(
                            wire::SetInterventionsMutedResponse {
                                focus_session: focus_session_to_wire(&focus_session),
                            },
                        ))
                    }),
                wire::RequestBody::EndFocusSession(input) => {
                    let owner: crate::ActorId = actor.into();
                    let stopping = self
                        .second_mind()
                        .end_focus_session(
                            context.assurance,
                            owner,
                            crate::FocusSessionId::from_uuid(input.focus_session_id.into_uuid()),
                            input.expected_revision,
                            end_reason_from_wire(input.reason),
                        )
                        .map_err(crate::application::second_mind_error_to_application)?;
                    let runtime = self.second_mind().clone();
                    let stopping_for_cleanup = stopping.clone();
                    tokio::spawn(async move {
                        let _ = runtime
                            .finish_end_focus_session(
                                owner,
                                stopping_for_cleanup.id,
                                stopping_for_cleanup.revision,
                            )
                            .await;
                    });
                    Ok(wire::ResponseBody::EndFocusSession(Box::new(
                        wire::EndFocusSessionResponse {
                            focus_session: focus_session_to_wire(&stopping),
                        },
                    )))
                }
                wire::RequestBody::RecordInterventionFeedback(input) => {
                    let (outcome, correction, correction_applied) = match &input.feedback {
                        wire::InterventionFeedback::Accepted => {
                            (crate::InterventionOutcome::Accepted, None, false)
                        }
                        wire::InterventionFeedback::Dismissed => {
                            (crate::InterventionOutcome::Dismissed, None, false)
                        }
                        wire::InterventionFeedback::Corrected { correction, .. } => (
                            crate::InterventionOutcome::Corrected,
                            Some(crate::SensitiveText::new(correction.clone())),
                            true,
                        ),
                    };
                    self.second_mind()
                        .record_feedback(
                            context.assurance,
                            actor.into(),
                            crate::InterventionId::from_uuid(input.intervention_id.into_uuid()),
                            input.expected_revision,
                            outcome,
                            correction,
                        )
                        .map_err(crate::application::second_mind_error_to_application)
                        .map(|intervention| {
                            wire::ResponseBody::RecordInterventionFeedback(Box::new(
                                wire::RecordInterventionFeedbackResponse {
                                    intervention: intervention_to_wire(&intervention),
                                    outcome: intervention_outcome_to_wire(intervention.outcome),
                                    context_correction_applied: correction_applied,
                                },
                            ))
                        })
                }
                wire::RequestBody::GetSnapshot(_) => {
                    let owner: crate::ActorId = actor.into();
                    self.second_mind()
                        .stein_identity(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    self.second_mind()
                        .user_preferences(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    self.second_mind()
                        .current_device(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    self.open_subscription_with(&owner, |base, owner_state| {
                        Ok(wire::ResponseBody::GetSnapshot(wire::GetSnapshotResponse {
                            snapshot: snapshot_to_wire(
                                base,
                                active_connections,
                                Some(phase2_snapshot_to_wire(
                                    self.second_mind(),
                                    owner,
                                    owner_state,
                                )),
                            ),
                        }))
                    })
                    .map(|(_discarded, response)| response)
                }
                wire::RequestBody::GetRuntimeStatus(_) => Ok(wire::ResponseBody::GetRuntimeStatus(
                    wire::GetRuntimeStatusResponse {
                        runtime: runtime_to_wire(&self.runtime_status(), active_connections),
                        capabilities: capabilities_to_wire(&self.capability_health()),
                    },
                )),
                wire::RequestBody::GetGoal(input) => self
                    .second_mind()
                    .get_goal(actor.into(), input.goal_id.into())
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|goal| {
                        wire::ResponseBody::GetGoal(Box::new(wire::GetGoalResponse {
                            goal: goal_to_wire(&goal),
                        }))
                    }),
                wire::RequestBody::GetFocusSessionView(input) => {
                    let owner: crate::ActorId = actor.into();
                    let state = self
                        .second_mind()
                        .owner_state_snapshot(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    let session_id =
                        crate::FocusSessionId::from_uuid(input.focus_session_id.into_uuid());
                    let session = state
                        .focus_sessions
                        .iter()
                        .find(|session| session.id == session_id)
                        .ok_or_else(|| not_found_application("The focus session was not found."))?;
                    let statuses = self
                        .second_mind()
                        .observation_source_statuses(context.assurance, owner, session_id)
                        .unwrap_or_default();
                    let latest_model_request_receipt =
                        if supports_model_request_receipt(context.negotiated_version) {
                            self.second_mind()
                                .latest_model_request_receipt(context.assurance, owner, session_id)
                                .map_err(crate::application::second_mind_error_to_application)?
                                .as_ref()
                                .map(model_request_receipt_to_wire)
                        } else {
                            None
                        };
                    Ok(wire::ResponseBody::GetFocusSessionView(Box::new(
                        wire::GetFocusSessionViewResponse {
                            focus_session: focus_session_to_wire(session),
                            capture: Some(capture_state_to_wire(
                                self.second_mind(),
                                session,
                                &state.grants,
                                &statuses,
                            )),
                            latest_model_request_receipt,
                        },
                    )))
                }
                wire::RequestBody::GetCapabilityHealth(_) => {
                    Ok(wire::ResponseBody::GetCapabilityHealth(Box::new(
                        wire::GetCapabilityHealthResponse {
                            capabilities: capabilities_to_wire(&self.capability_health()),
                        },
                    )))
                }
                wire::RequestBody::GetPermissionView(input) => {
                    if input.permission_grant_id.is_some()
                        && input.model_route_approval_id.is_some()
                    {
                        Err(invalid_application(
                            "Only one permission record filter may be supplied.",
                        ))
                    } else {
                        let state = self
                            .second_mind()
                            .owner_state_snapshot(context.assurance, actor.into())
                            .map_err(crate::application::second_mind_error_to_application)?;
                        let now = time::OffsetDateTime::now_utc();
                        let mut records = Vec::new();
                        records.extend(
                            state
                                .grants
                                .iter()
                                .filter(|grant| {
                                    input
                                        .permission_grant_id
                                        .is_none_or(|id| grant.id.as_uuid() == id.into_uuid())
                                })
                                .map(|grant| {
                                    wire::PermissionRecordView::SessionGrant(grant_to_wire(
                                        grant, now,
                                    ))
                                }),
                        );
                        records.extend(
                            state
                                .model_routes
                                .iter()
                                .filter(|route| {
                                    input
                                        .model_route_approval_id
                                        .is_none_or(|id| route.id.as_uuid() == id.into_uuid())
                                })
                                .map(|route| {
                                    wire::PermissionRecordView::ModelRouteApproval(
                                        model_route_to_wire(route, now),
                                    )
                                }),
                        );
                        Ok(wire::ResponseBody::GetPermissionView(Box::new(
                            wire::GetPermissionViewResponse { records },
                        )))
                    }
                }
                wire::RequestBody::GetInterventionHistory(input) => {
                    if input.limit == 0 || input.limit > 100 {
                        Err(invalid_application(
                            "The intervention history limit must be between 1 and 100.",
                        ))
                    } else {
                        let state = self
                            .second_mind()
                            .owner_state_snapshot(context.assurance, actor.into())
                            .map_err(crate::application::second_mind_error_to_application)?;
                        let as_of = time::OffsetDateTime::now_utc();
                        let mut entries: Vec<_> = state
                            .interventions
                            .iter()
                            .filter(|intervention| {
                                input.focus_session_id.is_none_or(|id| {
                                    intervention.focus_session_id.as_uuid() == id.into_uuid()
                                }) && input.before.is_none_or(|before| {
                                    intervention.updated_at < before.as_datetime()
                                })
                            })
                            .map(intervention_to_wire)
                            .collect();
                        entries.sort_by_key(|entry| std::cmp::Reverse(entry.updated_at));
                        entries.truncate(usize::from(input.limit));
                        Ok(wire::ResponseBody::GetInterventionHistory(Box::new(
                            wire::GetInterventionHistoryResponse {
                                history: wire::InterventionHistoryView {
                                    as_of: wire::UtcTimestamp::from_datetime(as_of),
                                    entries,
                                },
                            },
                        )))
                    }
                }
                wire::RequestBody::ExplainIntervention(input) => {
                    let state = self
                        .second_mind()
                        .owner_state_snapshot(context.assurance, actor.into())
                        .map_err(crate::application::second_mind_error_to_application)?;
                    let intervention_id =
                        crate::InterventionId::from_uuid(input.intervention_id.into_uuid());
                    let intervention = state
                        .interventions
                        .iter()
                        .find(|value| value.id == intervention_id)
                        .ok_or_else(|| not_found_application("The intervention was not found."))?;
                    let decision = state
                        .policy_decisions
                        .iter()
                        .find(|value| value.id == intervention.policy_decision_id)
                        .ok_or_else(|| {
                            unavailable_application("The intervention explanation is unavailable.")
                        })?;
                    Ok(wire::ResponseBody::ExplainIntervention(Box::new(
                        wire::ExplainInterventionResponse {
                            explanation: explanation_to_wire(intervention, decision),
                        },
                    )))
                }
                wire::RequestBody::DeleteGoal(input) => self
                    .second_mind()
                    .delete_goal_with_context(
                        context.assurance,
                        actor.into(),
                        input.goal_id.into(),
                        input.expected_revision,
                        event_context(request, actor),
                    )
                    .await
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|result| {
                        wire::ResponseBody::DeleteGoal(Box::new(wire::DeleteGoalResponse {
                            tombstone: goal_deletion_to_wire(&result.tombstone),
                            already_deleted: result.already_deleted,
                        }))
                    }),
                wire::RequestBody::RegisterSelectedResource(input) => {
                    let kind = daemon_native_resource_kind(input.kind).ok_or_else(|| {
                        invalid_application(
                            "This resource kind does not have a daemon-owned native selector.",
                        )
                    })?;
                    let resource = self
                        .second_mind()
                        .select_and_register_resource_with_context(
                            context.assurance,
                            actor.into(),
                            kind,
                            crate::IdempotencyContext {
                                key: require_idempotency(request)?,
                                request_digest: stable_request_digest(input)?,
                            },
                            cancellation.clone(),
                            event_context(request, actor),
                        )
                        .await
                        .map_err(crate::application::second_mind_error_to_application)?;
                    Ok(wire::ResponseBody::RegisterSelectedResource(Box::new(
                        wire::RegisterSelectedResourceResponse {
                            resource: selected_resource_to_wire(&resource),
                        },
                    )))
                }
                wire::RequestBody::RemoveSelectedResource(input) => self
                    .second_mind()
                    .remove_resource_binding_with_context(
                        context.assurance,
                        actor.into(),
                        crate::ResourceId::from_uuid(input.selected_resource_id.into_uuid()),
                        input.expected_revision,
                        event_context(request, actor),
                    )
                    .await
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|tombstone| {
                        wire::ResponseBody::RemoveSelectedResource(Box::new(
                            wire::RemoveSelectedResourceResponse {
                                tombstone: resource_deletion_to_wire(&tombstone),
                            },
                        ))
                    }),
                wire::RequestBody::UpdateUserPreferences(input) => {
                    let owner: crate::ActorId = actor.into();
                    let current = self
                        .second_mind()
                        .user_preferences(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    let value = preferences_from_wire(
                        owner,
                        current.default_focus_minutes,
                        &input.preferences,
                    )?;
                    let preferences = self
                        .second_mind()
                        .save_preferences_with_context(
                            context.assurance,
                            value,
                            Some(input.expected_revision),
                            event_context(request, actor),
                        )
                        .map_err(crate::application::second_mind_error_to_application)?;
                    let effective_policy = self
                        .second_mind()
                        .effective_policy_view(context.assurance, owner)
                        .map_err(crate::application::second_mind_error_to_application)?;
                    Ok(wire::ResponseBody::UpdateUserPreferences(Box::new(
                        wire::UpdateUserPreferencesResponse {
                            preferences: preferences_to_wire(&preferences),
                            effective_policy: effective_policy_to_wire(&effective_policy),
                        },
                    )))
                }
                wire::RequestBody::GetSteinIdentity(_) => self
                    .second_mind()
                    .stein_identity(context.assurance, actor.into())
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|identity| {
                        wire::ResponseBody::GetSteinIdentity(Box::new(
                            wire::GetSteinIdentityResponse {
                                identity: identity_to_wire(&identity),
                            },
                        ))
                    }),
                wire::RequestBody::GetUserPreferences(_) => self
                    .second_mind()
                    .user_preferences(context.assurance, actor.into())
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|preferences| {
                        wire::ResponseBody::GetUserPreferences(Box::new(
                            wire::GetUserPreferencesResponse {
                                preferences: preferences_to_wire(&preferences),
                            },
                        ))
                    }),
                wire::RequestBody::GetEffectivePolicy(_) => self
                    .second_mind()
                    .effective_policy_view(context.assurance, actor.into())
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|effective_policy| {
                        wire::ResponseBody::GetEffectivePolicy(Box::new(
                            wire::GetEffectivePolicyResponse {
                                effective_policy: effective_policy_to_wire(&effective_policy),
                            },
                        ))
                    }),
                wire::RequestBody::GetSelectedResources(_) => self
                    .second_mind()
                    .owner_state_snapshot(context.assurance, actor.into())
                    .map_err(crate::application::second_mind_error_to_application)
                    .map(|state| {
                        wire::ResponseBody::GetSelectedResources(Box::new(
                            wire::GetSelectedResourcesResponse {
                                resources: state
                                    .resources
                                    .iter()
                                    .map(selected_resource_to_wire)
                                    .collect(),
                            },
                        ))
                    }),
                wire::RequestBody::DelayEcho(input) => {
                    let deadline = request.metadata.deadline_at.map(|value| {
                        let remaining = value.as_datetime() - time::OffsetDateTime::now_utc();
                        let remaining = if remaining.is_negative() {
                            Duration::ZERO
                        } else {
                            remaining.try_into().unwrap_or(Duration::MAX)
                        };
                        tokio::time::Instant::now() + remaining
                    });
                    let started = tokio::time::Instant::now();
                    self.delay_echo(
                        DelayEcho {
                            value: input.text.clone(),
                            delay: Duration::from_millis(input.delay_ms),
                            deadline,
                        },
                        cancellation,
                    )
                    .await
                    .map(|text| {
                        wire::ResponseBody::DelayEcho(wire::DelayEchoResponse {
                            text,
                            completed_after_ms: u64::try_from(started.elapsed().as_millis())
                                .unwrap_or(u64::MAX),
                        })
                    })
                }
                wire::RequestBody::Shutdown(_) => {
                    // The IPC delivery adapter commits the shutdown only after it
                    // has queued this acknowledgement. Cancelling the daemon here
                    // would race the response writer and make clean shutdown
                    // nondeterministic under load.
                    let runtime = self.runtime_status();
                    Ok(wire::ResponseBody::Shutdown(wire::ShutdownResponse {
                        daemon_instance_id: wire::DaemonInstanceId::from_uuid(
                            runtime.daemon_instance_id,
                        ),
                        accepted: true,
                    }))
                }
            }
        }
        .await;

        result.map_err(|error| error_to_wire(error, request.metadata.correlation_id))
    }
}

const fn daemon_native_resource_kind(
    kind: wire::SelectedResourceKind,
) -> Option<crate::ResourceKind> {
    match kind {
        wire::SelectedResourceKind::Application => Some(crate::ResourceKind::Application),
        wire::SelectedResourceKind::Window => Some(crate::ResourceKind::Window),
        wire::SelectedResourceKind::BrowserSurface => Some(crate::ResourceKind::BrowserSurface),
        wire::SelectedResourceKind::Document => Some(crate::ResourceKind::Document),
        wire::SelectedResourceKind::Workspace => Some(crate::ResourceKind::Workspace),
        wire::SelectedResourceKind::ScreenRegion => Some(crate::ResourceKind::ScreenRegion),
        wire::SelectedResourceKind::Display => None,
    }
}

fn snapshot_to_wire(
    snapshot: &ClientSnapshot,
    active_connections: u32,
    phase2: Option<Box<wire::Phase2Snapshot>>,
) -> wire::ClientSnapshot {
    let runtime = runtime_to_wire(&snapshot.runtime, active_connections);
    let capabilities = capabilities_to_wire(&snapshot.capabilities);
    let goals = snapshot.goals.iter().map(goal_to_wire).collect();
    wire::ClientSnapshot {
        snapshot_id: wire::SnapshotId::new_v7(),
        // Capture the boundary after every contained view was assembled so the
        // snapshot never claims to predate its own runtime observation.
        as_of: wire::UtcTimestamp::now(),
        cursor: cursor(snapshot.runtime.daemon_instance_id, snapshot.event_cursor),
        runtime,
        capabilities,
        goals,
        phase2,
    }
}

fn phase2_snapshot_to_wire(
    runtime: &crate::SecondMindRuntime,
    owner: crate::ActorId,
    state: crate::OwnerStateSnapshot,
) -> Box<wire::Phase2Snapshot> {
    let as_of = time::OffsetDateTime::now_utc();
    let selected_resources = state
        .resources
        .iter()
        .map(selected_resource_to_wire)
        .collect();
    let mut permission_records: Vec<_> = state
        .grants
        .iter()
        .map(|grant| wire::PermissionRecordView::SessionGrant(grant_to_wire(grant, as_of)))
        .collect();
    permission_records.extend(state.model_routes.iter().map(|route| {
        wire::PermissionRecordView::ModelRouteApproval(model_route_to_wire(route, as_of))
    }));
    let focus_sessions: Vec<_> = state
        .focus_sessions
        .iter()
        .map(focus_session_to_wire)
        .collect();
    let capture_states = state
        .focus_sessions
        .iter()
        .map(|session| {
            let statuses = runtime
                .observation_source_statuses(
                    crate::ClientAssurance::PrivateCapabilityBound,
                    owner,
                    session.id,
                )
                .unwrap_or_default();
            capture_state_to_wire(runtime, session, &state.grants, &statuses)
        })
        .collect();
    let mut channel_names = vec!["windows.native_notification".to_owned()];
    for intervention in &state.interventions {
        if let Some(channel) = &intervention.delivery_channel
            && !channel_names.contains(channel)
        {
            channel_names.push(channel.clone());
        }
    }
    let delivery_channels = channel_names
        .iter()
        .map(|channel| delivery_channel_to_wire(runtime, channel, as_of))
        .collect();
    let mut entries: Vec<_> = state
        .interventions
        .iter()
        .map(intervention_to_wire)
        .collect();
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.updated_at));
    entries.truncate(100);
    Box::new(wire::Phase2Snapshot {
        selected_resources,
        permission_records,
        focus_sessions,
        capture_states,
        delivery_channels,
        intervention_history: wire::InterventionHistoryView {
            as_of: wire::UtcTimestamp::from_datetime(as_of),
            entries,
        },
        current_device_id: state
            .current_device
            .as_ref()
            .map(|device| wire::DeviceId::from_uuid(device.device_id.as_uuid())),
        stein_identity: state.identity.as_ref().map(identity_to_wire),
        user_preferences: state.preferences.as_ref().map(preferences_to_wire),
        effective_policy: runtime
            .effective_policy_view(crate::ClientAssurance::PrivateCapabilityBound, owner)
            .ok()
            .as_ref()
            .map(effective_policy_to_wire),
    })
}

fn selected_resource_to_wire(value: &crate::ResourceBinding) -> wire::SelectedResourceView {
    wire::SelectedResourceView {
        selected_resource_id: wire::SelectedResourceId::from_uuid(value.id.as_uuid()),
        kind: match value.kind {
            crate::ResourceKind::Device => wire::SelectedResourceKind::Display,
            crate::ResourceKind::Application => wire::SelectedResourceKind::Application,
            crate::ResourceKind::Window => wire::SelectedResourceKind::Window,
            crate::ResourceKind::BrowserSurface => wire::SelectedResourceKind::BrowserSurface,
            crate::ResourceKind::Document => wire::SelectedResourceKind::Document,
            crate::ResourceKind::Workspace => wire::SelectedResourceKind::Workspace,
            crate::ResourceKind::ScreenRegion => wire::SelectedResourceKind::ScreenRegion,
        },
        display_name: value.display_label.clone(),
        revision: Some(value.revision),
        created_at: Some(wire::UtcTimestamp::from_datetime(value.created_at)),
    }
}

fn grant_to_wire(
    value: &crate::PermissionGrant,
    as_of: time::OffsetDateTime,
) -> wire::PermissionGrantView {
    wire::PermissionGrantView {
        permission_grant_id: wire::PermissionGrantId::from_uuid(value.id.as_uuid()),
        revision: value.revision,
        owner_id: value.owner.into(),
        requested_by_client: wire::ClientInstanceId::from_uuid(
            value.authenticated_client.as_uuid(),
        ),
        device_id: wire::DeviceId::from_uuid(value.device_id.as_uuid()),
        focus_session_id: value
            .focus_session_id
            .map(|id| wire::FocusSessionId::from_uuid(id.as_uuid())),
        goal_id: value.goal_id.into(),
        scope: permission_scope_to_wire(value.scope),
        selected_resource_id: value
            .selected_resource_id
            .map(|id| wire::SelectedResourceId::from_uuid(id.as_uuid())),
        purpose: value.purpose.clone(),
        continuity: wire::PermissionContinuity {
            while_client_disconnected: value.client_disconnect_allowed,
            after_daemon_restart: value.daemon_restart_allowed,
        },
        state: if value.revoked_at.is_some() || value.state == crate::GrantState::Revoked {
            wire::PermissionState::Revoked
        } else if value.expires_at <= as_of
            || matches!(
                value.state,
                crate::GrantState::Expired | crate::GrantState::Superseded
            )
        {
            wire::PermissionState::Expired
        } else {
            wire::PermissionState::Active
        },
        effective_at: wire::UtcTimestamp::from_datetime(value.effective_at),
        expires_at: wire::UtcTimestamp::from_datetime(value.expires_at),
        revoked_at: value.revoked_at.map(wire::UtcTimestamp::from_datetime),
        revocation_reason: value.revocation_reason.clone(),
        consent_copy_version: value.consent_copy_version.clone(),
        sensitivity: wire::SensitivityClass::Sensitive,
        retention: wire::RetentionClass::DurableUntilExpiry,
    }
}

fn model_route_to_wire(
    value: &crate::ModelRouteApproval,
    as_of: time::OffsetDateTime,
) -> wire::ModelRouteApprovalView {
    wire::ModelRouteApprovalView {
        model_route_approval_id: wire::ModelRouteApprovalId::from_uuid(value.id.as_uuid()),
        revision: value.revision,
        owner_id: value.owner.into(),
        route: wire::ModelRouteReference {
            provider_id: value.provider.clone(),
            route_id: value.model.clone(),
            placement: model_placement_to_wire(value.placement),
        },
        account_profile: value.account_profile.clone(),
        allowed_data_categories: value
            .allowed_categories
            .iter()
            .copied()
            .map(data_category_to_wire)
            .collect(),
        handling: wire::ProviderHandlingProfile {
            retention: match &value.handling.retention {
                crate::ProviderRetentionPolicy::None => wire::ProviderRetentionPolicy::None,
                crate::ProviderRetentionPolicy::Transient => {
                    wire::ProviderRetentionPolicy::Transient
                }
                crate::ProviderRetentionPolicy::Bounded { maximum_seconds } => {
                    wire::ProviderRetentionPolicy::Bounded {
                        maximum_seconds: *maximum_seconds,
                    }
                }
                crate::ProviderRetentionPolicy::Unknown => wire::ProviderRetentionPolicy::Unknown,
            },
            training_use: match value.handling.training_use {
                crate::ProviderTrainingUse::Excluded => wire::ProviderTrainingUse::Excluded,
                crate::ProviderTrainingUse::MayUse => wire::ProviderTrainingUse::MayUse,
                crate::ProviderTrainingUse::Unknown => wire::ProviderTrainingUse::Unknown,
            },
            data_residency: value.handling.data_residency.clone(),
            profile_version: value.handling.profile_id.clone(),
        },
        purpose: value.purpose.clone(),
        maximum_request_tokens: value.maximum_input_tokens,
        fallback: value
            .fallback
            .as_ref()
            .map(|fallback| wire::ModelRouteReference {
                provider_id: fallback.provider_id.clone(),
                route_id: fallback.route_id.clone(),
                placement: model_placement_to_wire(fallback.placement),
            }),
        state: if value.revoked_at.is_some() {
            wire::ModelRouteApprovalState::Revoked
        } else if value.expires_at.is_some_and(|expiry| expiry <= as_of) {
            wire::ModelRouteApprovalState::Expired
        } else {
            wire::ModelRouteApprovalState::Active
        },
        effective_at: wire::UtcTimestamp::from_datetime(value.effective_at),
        expires_at: value.expires_at.map(wire::UtcTimestamp::from_datetime),
        revoked_at: value.revoked_at.map(wire::UtcTimestamp::from_datetime),
        disclosure_version: value.disclosure_version.clone(),
    }
}

fn focus_session_to_wire(value: &crate::FocusSession) -> wire::FocusSessionView {
    wire::FocusSessionView {
        focus_session_id: wire::FocusSessionId::from_uuid(value.id.as_uuid()),
        revision: value.revision,
        goal_id: value.goal_id.into(),
        goal_revision: value.goal_revision,
        state: focus_state_to_wire(value.state),
        interventions_muted: value.muted,
        source_degraded: value.source_degraded,
        model_route_approval_id: wire::ModelRouteApprovalId::from_uuid(
            value.model_route_approval_id.as_uuid(),
        ),
        permission_grant_ids: value
            .permission_grant_ids
            .iter()
            .map(|id| wire::PermissionGrantId::from_uuid(id.as_uuid()))
            .collect(),
        selected_resource_ids: value
            .selected_resource_ids
            .iter()
            .map(|id| wire::SelectedResourceId::from_uuid(id.as_uuid()))
            .collect(),
        continuity: wire::PermissionContinuity {
            while_client_disconnected: value.client_disconnect_allowed,
            after_daemon_restart: value.daemon_restart_allowed,
        },
        created_at: wire::UtcTimestamp::from_datetime(value.requested_at),
        started_at: value.started_at.map(wire::UtcTimestamp::from_datetime),
        ended_at: value.ended_at.map(wire::UtcTimestamp::from_datetime),
        updated_at: wire::UtcTimestamp::from_datetime(value.updated_at),
    }
}

fn model_request_receipt_to_wire(
    value: &crate::ModelRequestReceipt,
) -> wire::ModelRequestReceiptView {
    wire::ModelRequestReceiptView {
        request_id: wire::RequestId::from_uuid(value.request_id),
        focus_session_id: wire::FocusSessionId::from_uuid(value.focus_session_id.as_uuid()),
        model_route_approval_id: wire::ModelRouteApprovalId::from_uuid(
            value.model_route_approval_id.as_uuid(),
        ),
        model_route_revision: value.model_route_revision,
        started_at: wire::UtcTimestamp::from_datetime(value.started_at),
        completed_at: value.completed_at.map(wire::UtcTimestamp::from_datetime),
        outcome: match value.outcome {
            crate::ModelRequestReceiptOutcome::InFlight => {
                wire::ModelRequestReceiptOutcome::InFlight
            }
            crate::ModelRequestReceiptOutcome::CompletedStrictSilence => {
                wire::ModelRequestReceiptOutcome::CompletedStrictSilence
            }
            crate::ModelRequestReceiptOutcome::CompletedStrictCandidate => {
                wire::ModelRequestReceiptOutcome::CompletedStrictCandidate
            }
            crate::ModelRequestReceiptOutcome::Cancelled => {
                wire::ModelRequestReceiptOutcome::Cancelled
            }
            crate::ModelRequestReceiptOutcome::DeadlineExceeded => {
                wire::ModelRequestReceiptOutcome::DeadlineExceeded
            }
            crate::ModelRequestReceiptOutcome::Failed => wire::ModelRequestReceiptOutcome::Failed,
        },
    }
}

const fn supports_model_request_receipt(version: wire::ProtocolVersion) -> bool {
    version.major == wire::ProtocolVersion::V1_2.major
        && version.minor >= wire::ProtocolVersion::V1_2.minor
}

fn capture_state_to_wire(
    runtime: &crate::SecondMindRuntime,
    session: &crate::FocusSession,
    grants: &[crate::PermissionGrant],
    statuses: &[crate::ObservationSourceStatus],
) -> wire::CaptureStateView {
    capture_state_from_parts(
        session,
        grants,
        statuses,
        runtime.native_status_availability().is_available(),
        runtime.emergency_control_availability().is_available(),
    )
}

fn capture_projection_to_wire(projection: &crate::CaptureViewProjection) -> wire::CaptureStateView {
    capture_state_from_parts(
        &projection.session,
        &projection.grants,
        &projection.source_statuses,
        projection.native_status_available,
        projection.emergency_control_available,
    )
}

fn capture_state_from_parts(
    session: &crate::FocusSession,
    grants: &[crate::PermissionGrant],
    statuses: &[crate::ObservationSourceStatus],
    native_status_available: bool,
    emergency_control_available: bool,
) -> wire::CaptureStateView {
    let observation_grants: Vec<_> = grants
        .iter()
        .filter(|grant| grant.focus_session_id == Some(session.id) && grant.scope.is_observation())
        .collect();
    let mut active_categories = Vec::new();
    let sources = observation_grants
        .iter()
        .map(|grant| {
            let category = observation_category_to_wire(grant.scope);
            if !active_categories.contains(&category) {
                active_categories.push(category);
            }
            let status = statuses.iter().find(|status| status.grant_id == grant.id);
            wire::ObservationSourceView {
                observation_source_id: observation_source_id(grant.id),
                category,
                selected_resource_id: grant
                    .selected_resource_id
                    .map(|id| wire::SelectedResourceId::from_uuid(id.as_uuid())),
                health: status.map_or_else(
                    || match session.state {
                        crate::FocusSessionState::Starting => {
                            wire::ObservationSourceHealth::Starting
                        }
                        crate::FocusSessionState::Ended | crate::FocusSessionState::Stopping => {
                            wire::ObservationSourceHealth::Stopped
                        }
                        crate::FocusSessionState::Failed => wire::ObservationSourceHealth::Failed,
                        _ => wire::ObservationSourceHealth::Unknown,
                    },
                    |status| source_health_to_wire(status.health),
                ),
                last_complete_at: status
                    .filter(|status| status.health == crate::SourceHealth::Healthy)
                    .map(|status| wire::UtcTimestamp::from_datetime(status.observed_at)),
            }
        })
        .collect();
    let capture_state = match session.state {
        crate::FocusSessionState::Requested => wire::CaptureState::Stopped,
        crate::FocusSessionState::Starting | crate::FocusSessionState::Recovering => {
            wire::CaptureState::Starting
        }
        crate::FocusSessionState::Active
            if statuses
                .iter()
                .any(|status| status.health == crate::SourceHealth::Paused) =>
        {
            wire::CaptureState::Paused
        }
        crate::FocusSessionState::Active => wire::CaptureState::Active,
        crate::FocusSessionState::Stopping => wire::CaptureState::Stopping,
        crate::FocusSessionState::Ended => wire::CaptureState::Stopped,
        crate::FocusSessionState::Failed => wire::CaptureState::Failed,
    };
    wire::CaptureStateView {
        focus_session_id: wire::FocusSessionId::from_uuid(session.id.as_uuid()),
        revision: session.revision,
        state: capture_state,
        active_categories,
        sources,
        native_status_visible: session.is_working() && native_status_available,
        emergency_stop_available: emergency_control_available,
        updated_at: wire::UtcTimestamp::from_datetime(session.updated_at),
    }
}

fn capability_health_to_wire(value: &crate::CapabilityHealth) -> wire::CapabilityHealth {
    let capability = match value.id {
        "core.goals" => wire::CapabilityId::GoalCreate,
        "core.delay_echo" => wire::CapabilityId::DelayEcho,
        "core.persistence" => wire::CapabilityId::DurablePersistence,
        "platform.secret_store" => wire::CapabilityId::SecretStore,
        "platform.native_notification" => wire::CapabilityId::NativeNotification,
        "platform.native_status" => wire::CapabilityId::NativeStatus,
        "platform.emergency_control" => wire::CapabilityId::EmergencyControl,
        "observation.desktop" => wire::CapabilityId::DesktopObservation,
        "model.reasoning" => wire::CapabilityId::ModelReasoning,
        _ => wire::CapabilityId::Snapshot,
    };
    wire::CapabilityHealth {
        capability,
        schema_version: wire::SCHEMA_VERSION_V1,
        state: match value.state {
            crate::CapabilityState::Available => wire::HealthState::Healthy,
            crate::CapabilityState::Unavailable => wire::HealthState::Unavailable,
        },
        unavailable_reason: (value.state == crate::CapabilityState::Unavailable)
            .then_some(wire::CapabilityUnavailableReason::DependencyUnavailable),
    }
}

fn delivery_channel_status_to_wire(
    value: &crate::DeliveryChannelStatus,
) -> wire::DeliveryChannelView {
    wire::DeliveryChannelView {
        delivery_channel_id: delivery_channel_id(&value.channel_id),
        class: if value.channel_id == "connected_desktop" {
            wire::DeliveryChannelClass::ConnectedDesktop
        } else {
            wire::DeliveryChannelClass::NativeDesktopNotification
        },
        state: match value.health {
            crate::DeliveryChannelHealth::Healthy => wire::DeliveryChannelState::Healthy,
            crate::DeliveryChannelHealth::Suppressed => wire::DeliveryChannelState::Suppressed,
            crate::DeliveryChannelHealth::Degraded => wire::DeliveryChannelState::Degraded,
            crate::DeliveryChannelHealth::Unavailable => wire::DeliveryChannelState::Unavailable,
        },
        may_show_content_while_locked: false,
        observed_at: wire::UtcTimestamp::from_datetime(value.observed_at),
        status_code: (value.health != crate::DeliveryChannelHealth::Healthy)
            .then(|| "dependency_unavailable".to_owned()),
    }
}

fn delivery_channel_to_wire(
    runtime: &crate::SecondMindRuntime,
    channel: &str,
    as_of: time::OffsetDateTime,
) -> wire::DeliveryChannelView {
    let available = runtime.notification_availability().is_available();
    wire::DeliveryChannelView {
        delivery_channel_id: delivery_channel_id(channel),
        class: if channel == "connected_desktop" {
            wire::DeliveryChannelClass::ConnectedDesktop
        } else {
            wire::DeliveryChannelClass::NativeDesktopNotification
        },
        state: if available {
            wire::DeliveryChannelState::Healthy
        } else {
            wire::DeliveryChannelState::Unavailable
        },
        may_show_content_while_locked: false,
        observed_at: wire::UtcTimestamp::from_datetime(as_of),
        status_code: (!available).then(|| "dependency_unavailable".to_owned()),
    }
}

fn intervention_to_wire(value: &crate::Intervention) -> wire::InterventionView {
    wire::InterventionView {
        intervention_id: wire::InterventionId::from_uuid(value.id.as_uuid()),
        revision: value.revision,
        candidate_revision: value.candidate_revision,
        focus_session_id: wire::FocusSessionId::from_uuid(value.focus_session_id.as_uuid()),
        goal_id: value.goal_id.into(),
        urgency: match value.urgency {
            crate::Urgency::Low => wire::InterventionUrgency::Low,
            crate::Urgency::Normal => wire::InterventionUrgency::Normal,
            crate::Urgency::High => wire::InterventionUrgency::High,
        },
        reason_codes: vec![reason_code_to_wire(&value.reason_code)],
        state: intervention_state_to_wire(value.state),
        outcome: intervention_outcome_to_wire(value.outcome),
        user_visible_text: (!value.user_visible_text.is_empty())
            .then(|| value.user_visible_text.clone()),
        delivery_channel_id: value.delivery_channel.as_deref().map(delivery_channel_id),
        sensitivity: wire::SensitivityClass::Personal,
        retention: wire::RetentionClass::BoundedAudit,
        created_at: wire::UtcTimestamp::from_datetime(value.created_at),
        expires_at: wire::UtcTimestamp::from_datetime(value.expires_at),
        updated_at: wire::UtcTimestamp::from_datetime(value.updated_at),
    }
}

fn permission_scope_to_wire(value: crate::PermissionScope) -> wire::PermissionScope {
    match value {
        crate::PermissionScope::ObserveDesktopPresence => {
            wire::PermissionScope::ObserveDesktopPresence
        }
        crate::PermissionScope::ObserveDesktopForegroundApplication => {
            wire::PermissionScope::ObserveDesktopForegroundApplication
        }
        crate::PermissionScope::ObserveDesktopWindowMetadata => {
            wire::PermissionScope::ObserveDesktopWindowMetadata
        }
        crate::PermissionScope::ObserveBrowserLocation => {
            wire::PermissionScope::ObserveBrowserLocation
        }
        crate::PermissionScope::ObserveContentVisibleText => {
            wire::PermissionScope::ObserveContentVisibleText
        }
        crate::PermissionScope::ObserveContentSelectedDocument => {
            wire::PermissionScope::ObserveContentSelectedDocument
        }
        crate::PermissionScope::ObserveScreenPixels => wire::PermissionScope::ObserveScreenPixels,
        crate::PermissionScope::ObserveWorkspaceActivity => {
            wire::PermissionScope::ObserveWorkspaceActivity
        }
        crate::PermissionScope::ReasonFocusContext => wire::PermissionScope::ReasonFocusContext,
        crate::PermissionScope::InterveneDesktopNotification => {
            wire::PermissionScope::InterveneDesktopNotification
        }
    }
}

fn data_category_to_wire(value: crate::DataCategory) -> wire::ModelDataCategory {
    match value {
        crate::DataCategory::Goal => wire::ModelDataCategory::Goal,
        crate::DataCategory::FocusSession => wire::ModelDataCategory::FocusSession,
        crate::DataCategory::EvidenceAggregates => wire::ModelDataCategory::EvidenceAggregates,
        crate::DataCategory::WindowMetadata => wire::ModelDataCategory::WindowMetadata,
        crate::DataCategory::BrowserLocation => wire::ModelDataCategory::BrowserLocation,
        crate::DataCategory::VisibleText => wire::ModelDataCategory::VisibleText,
        crate::DataCategory::SelectedDocument => wire::ModelDataCategory::SelectedDocument,
        crate::DataCategory::ScreenPixels => wire::ModelDataCategory::ScreenPixels,
        crate::DataCategory::WorkspaceActivity => wire::ModelDataCategory::WorkspaceActivity,
        crate::DataCategory::DeliveryConstraints => wire::ModelDataCategory::DeliveryConstraints,
    }
}

fn model_placement_to_wire(value: crate::ModelPlacement) -> wire::ModelPlacement {
    match value {
        crate::ModelPlacement::Local => wire::ModelPlacement::Local,
        crate::ModelPlacement::Remote => wire::ModelPlacement::Remote,
    }
}

fn focus_state_to_wire(value: crate::FocusSessionState) -> wire::FocusSessionState {
    match value {
        crate::FocusSessionState::Requested => wire::FocusSessionState::Requested,
        crate::FocusSessionState::Starting => wire::FocusSessionState::Starting,
        crate::FocusSessionState::Active => wire::FocusSessionState::Active,
        crate::FocusSessionState::Recovering => wire::FocusSessionState::Recovering,
        crate::FocusSessionState::Stopping => wire::FocusSessionState::Stopping,
        crate::FocusSessionState::Ended => wire::FocusSessionState::Ended,
        crate::FocusSessionState::Failed => wire::FocusSessionState::Failed,
    }
}

fn observation_category_to_wire(value: crate::PermissionScope) -> wire::ObservationCategory {
    match value {
        crate::PermissionScope::ObserveDesktopPresence => wire::ObservationCategory::Presence,
        crate::PermissionScope::ObserveDesktopForegroundApplication => {
            wire::ObservationCategory::ForegroundApplication
        }
        crate::PermissionScope::ObserveDesktopWindowMetadata => {
            wire::ObservationCategory::WindowMetadata
        }
        crate::PermissionScope::ObserveBrowserLocation => {
            wire::ObservationCategory::BrowserLocation
        }
        crate::PermissionScope::ObserveContentVisibleText => wire::ObservationCategory::VisibleText,
        crate::PermissionScope::ObserveContentSelectedDocument => {
            wire::ObservationCategory::SelectedDocument
        }
        crate::PermissionScope::ObserveScreenPixels => wire::ObservationCategory::ScreenPixels,
        crate::PermissionScope::ObserveWorkspaceActivity => {
            wire::ObservationCategory::WorkspaceActivity
        }
        crate::PermissionScope::ReasonFocusContext
        | crate::PermissionScope::InterveneDesktopNotification => {
            wire::ObservationCategory::SourceHealth
        }
    }
}

fn source_health_to_wire(value: crate::SourceHealth) -> wire::ObservationSourceHealth {
    match value {
        crate::SourceHealth::Unknown => wire::ObservationSourceHealth::Unknown,
        crate::SourceHealth::Healthy => wire::ObservationSourceHealth::Healthy,
        crate::SourceHealth::Degraded => wire::ObservationSourceHealth::Degraded,
        crate::SourceHealth::Paused => wire::ObservationSourceHealth::Paused,
        crate::SourceHealth::Unavailable => wire::ObservationSourceHealth::Failed,
    }
}

fn intervention_state_to_wire(value: crate::InterventionState) -> wire::InterventionState {
    match value {
        crate::InterventionState::Candidate => wire::InterventionState::Candidate,
        crate::InterventionState::Denied => wire::InterventionState::Denied,
        crate::InterventionState::Allowed => wire::InterventionState::Allowed,
        crate::InterventionState::Queued => wire::InterventionState::Queued,
        crate::InterventionState::Delivering => wire::InterventionState::Delivering,
        crate::InterventionState::AcceptedByChannel => wire::InterventionState::AcceptedByChannel,
        crate::InterventionState::DeliveryUnknown => wire::InterventionState::DeliveryUnknown,
        crate::InterventionState::DeliveryFailed => wire::InterventionState::DeliveryFailed,
        crate::InterventionState::Expired => wire::InterventionState::Expired,
        crate::InterventionState::Cancelled => wire::InterventionState::Cancelled,
    }
}

fn intervention_outcome_to_wire(value: crate::InterventionOutcome) -> wire::InterventionOutcome {
    match value {
        crate::InterventionOutcome::Unacknowledged => wire::InterventionOutcome::Unacknowledged,
        crate::InterventionOutcome::Accepted => wire::InterventionOutcome::Accepted,
        crate::InterventionOutcome::Dismissed => wire::InterventionOutcome::Dismissed,
        crate::InterventionOutcome::Corrected => wire::InterventionOutcome::Corrected,
        crate::InterventionOutcome::Expired => wire::InterventionOutcome::Expired,
    }
}

fn reason_code_to_wire(value: &str) -> wire::InterventionReasonCode {
    match value {
        "deadline_near" => wire::InterventionReasonCode::DeadlineNear,
        "success_condition_unobserved" => wire::InterventionReasonCode::SuccessConditionUnobserved,
        "recent_relevant_progress" => wire::InterventionReasonCode::RecentRelevantProgress,
        "evidence_stale" | "no_fresh_significant_evidence" => {
            wire::InterventionReasonCode::EvidenceStale
        }
        "source_unhealthy" => wire::InterventionReasonCode::SourceUnhealthy,
        "user_unavailable" | "presence_not_active" => wire::InterventionReasonCode::UserUnavailable,
        "interventions_muted" => wire::InterventionReasonCode::InterventionsMuted,
        "cooldown_active" => wire::InterventionReasonCode::CooldownActive,
        "session_limit_reached" => wire::InterventionReasonCode::SessionLimitReached,
        "permission_missing" => wire::InterventionReasonCode::PermissionMissing,
        "route_approval_missing" => wire::InterventionReasonCode::RouteApprovalMissing,
        "audit_unavailable" => wire::InterventionReasonCode::AuditUnavailable,
        "channel_unavailable" => wire::InterventionReasonCode::ChannelUnavailable,
        "corrected_context" => wire::InterventionReasonCode::CorrectedContext,
        "superseded" => wire::InterventionReasonCode::Superseded,
        _ => wire::InterventionReasonCode::CandidateInvalid,
    }
}

fn observation_source_id(grant_id: crate::PermissionGrantId) -> wire::ObservationSourceId {
    let namespace = uuid::Uuid::from_u128(0x018f_0000_0000_7000_8000_0000_0000_0201);
    wire::ObservationSourceId::from_uuid(uuid::Uuid::new_v5(
        &namespace,
        grant_id.as_uuid().as_bytes(),
    ))
}

fn delivery_channel_id(channel: &str) -> wire::DeliveryChannelId {
    let namespace = uuid::Uuid::from_u128(0x018f_0000_0000_7000_8000_0000_0000_0202);
    wire::DeliveryChannelId::from_uuid(uuid::Uuid::new_v5(&namespace, channel.as_bytes()))
}

fn invalid_application(summary: &'static str) -> ApplicationError {
    ApplicationError {
        code: ErrorCode::InvalidArgument,
        summary,
        retryable: false,
        field_violations: Vec::new(),
        current_revision: None,
    }
}

fn not_found_application(summary: &'static str) -> ApplicationError {
    ApplicationError {
        code: ErrorCode::NotFound,
        summary,
        retryable: false,
        field_violations: Vec::new(),
        current_revision: None,
    }
}

fn unavailable_application(summary: &'static str) -> ApplicationError {
    ApplicationError {
        code: ErrorCode::Unavailable,
        summary,
        retryable: true,
        field_violations: Vec::new(),
        current_revision: None,
    }
}

fn require_idempotency(
    request: &wire::RequestEnvelope,
) -> Result<crate::IdempotencyKey, ApplicationError> {
    request
        .metadata
        .idempotency_key
        .map(Into::into)
        .ok_or_else(|| {
            invalid_application("This aggregate-creating command requires an idempotency key.")
        })
}

fn stable_request_digest<T: serde::Serialize>(value: &T) -> Result<[u8; 32], ApplicationError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ApplicationError {
        code: ErrorCode::Internal,
        summary: "The typed request could not be prepared for durable replay.",
        retryable: false,
        field_violations: Vec::new(),
        current_revision: None,
    })?;
    Ok(Sha256::digest(encoded).into())
}

fn event_context(request: &wire::RequestEnvelope, actor: wire::ActorId) -> EventContext {
    EventContext {
        actor: actor.into(),
        actor_kind: crate::CoreEventActorKind::LocalOsUser,
        correlation_id: request.metadata.correlation_id.into_uuid(),
        causation_id: Some(request.metadata.message_id.into_uuid()),
    }
}

fn permission_scope_from_wire(value: wire::PermissionScope) -> crate::PermissionScope {
    match value {
        wire::PermissionScope::ObserveDesktopPresence => {
            crate::PermissionScope::ObserveDesktopPresence
        }
        wire::PermissionScope::ObserveDesktopForegroundApplication => {
            crate::PermissionScope::ObserveDesktopForegroundApplication
        }
        wire::PermissionScope::ObserveDesktopWindowMetadata => {
            crate::PermissionScope::ObserveDesktopWindowMetadata
        }
        wire::PermissionScope::ObserveBrowserLocation => {
            crate::PermissionScope::ObserveBrowserLocation
        }
        wire::PermissionScope::ObserveContentVisibleText => {
            crate::PermissionScope::ObserveContentVisibleText
        }
        wire::PermissionScope::ObserveContentSelectedDocument => {
            crate::PermissionScope::ObserveContentSelectedDocument
        }
        wire::PermissionScope::ObserveScreenPixels => crate::PermissionScope::ObserveScreenPixels,
        wire::PermissionScope::ObserveWorkspaceActivity => {
            crate::PermissionScope::ObserveWorkspaceActivity
        }
        wire::PermissionScope::ReasonFocusContext => crate::PermissionScope::ReasonFocusContext,
        wire::PermissionScope::InterveneDesktopNotification => {
            crate::PermissionScope::InterveneDesktopNotification
        }
    }
}

fn data_category_from_wire(value: wire::ModelDataCategory) -> crate::DataCategory {
    match value {
        wire::ModelDataCategory::Goal => crate::DataCategory::Goal,
        wire::ModelDataCategory::FocusSession => crate::DataCategory::FocusSession,
        wire::ModelDataCategory::EvidenceAggregates => crate::DataCategory::EvidenceAggregates,
        wire::ModelDataCategory::WindowMetadata => crate::DataCategory::WindowMetadata,
        wire::ModelDataCategory::BrowserLocation => crate::DataCategory::BrowserLocation,
        wire::ModelDataCategory::VisibleText => crate::DataCategory::VisibleText,
        wire::ModelDataCategory::SelectedDocument => crate::DataCategory::SelectedDocument,
        wire::ModelDataCategory::ScreenPixels => crate::DataCategory::ScreenPixels,
        wire::ModelDataCategory::WorkspaceActivity => crate::DataCategory::WorkspaceActivity,
        wire::ModelDataCategory::DeliveryConstraints => crate::DataCategory::DeliveryConstraints,
    }
}

fn model_placement_from_wire(value: wire::ModelPlacement) -> crate::ModelPlacement {
    match value {
        wire::ModelPlacement::Local => crate::ModelPlacement::Local,
        wire::ModelPlacement::Remote => crate::ModelPlacement::Remote,
    }
}

fn provider_retention_from_wire(
    value: &wire::ProviderRetentionPolicy,
) -> crate::ProviderRetentionPolicy {
    match value {
        wire::ProviderRetentionPolicy::None => crate::ProviderRetentionPolicy::None,
        wire::ProviderRetentionPolicy::Transient => crate::ProviderRetentionPolicy::Transient,
        wire::ProviderRetentionPolicy::Bounded { maximum_seconds } => {
            crate::ProviderRetentionPolicy::Bounded {
                maximum_seconds: *maximum_seconds,
            }
        }
        wire::ProviderRetentionPolicy::Unknown => crate::ProviderRetentionPolicy::Unknown,
    }
}

fn provider_training_from_wire(value: wire::ProviderTrainingUse) -> crate::ProviderTrainingUse {
    match value {
        wire::ProviderTrainingUse::Excluded => crate::ProviderTrainingUse::Excluded,
        wire::ProviderTrainingUse::MayUse => crate::ProviderTrainingUse::MayUse,
        wire::ProviderTrainingUse::Unknown => crate::ProviderTrainingUse::Unknown,
    }
}

fn model_route_reference_from_wire(
    value: &wire::ModelRouteReference,
) -> crate::ModelRouteReference {
    crate::ModelRouteReference {
        provider_id: value.provider_id.clone(),
        route_id: value.route_id.clone(),
        placement: model_placement_from_wire(value.placement),
    }
}

fn end_reason_from_wire(value: wire::FocusSessionEndReason) -> crate::EndFocusReason {
    match value {
        wire::FocusSessionEndReason::UserRequested => crate::EndFocusReason::UserRequested,
        wire::FocusSessionEndReason::GoalCompleted => crate::EndFocusReason::GoalCompleted,
        wire::FocusSessionEndReason::GoalAbandoned => crate::EndFocusReason::GoalAbandoned,
        wire::FocusSessionEndReason::PermissionRevoked => {
            crate::EndFocusReason::RequiredPermissionRevoked
        }
        wire::FocusSessionEndReason::Expired => crate::EndFocusReason::Expired,
    }
}

fn explanation_to_wire(
    intervention: &crate::Intervention,
    decision: &crate::PolicyDecision,
) -> wire::InterventionExplanationView {
    let now = time::OffsetDateTime::now_utc();
    wire::InterventionExplanationView {
        intervention_id: wire::InterventionId::from_uuid(intervention.id.as_uuid()),
        candidate_revision: intervention.candidate_revision,
        focus_session_id: wire::FocusSessionId::from_uuid(intervention.focus_session_id.as_uuid()),
        evidence: intervention
            .evidence
            .iter()
            .map(|evidence| wire::EvidenceSummaryView {
                category: evidence_category_to_wire(evidence.category),
                freshness: if evidence.observed_until > now {
                    wire::EvidenceFreshness::Unknown
                } else if now - evidence.observed_until <= time::Duration::seconds(30) {
                    wire::EvidenceFreshness::Fresh
                } else {
                    wire::EvidenceFreshness::Stale
                },
                confidence: match evidence.confidence_basis_points {
                    0 => wire::ConfidenceBand::Unknown,
                    1..=3_999 => wire::ConfidenceBand::Low,
                    4_000..=7_499 => wire::ConfidenceBand::Medium,
                    _ => wire::ConfidenceBand::High,
                },
                role: match evidence.role {
                    crate::EvidenceRole::SupportsProgress => wire::EvidenceRole::SupportsProgress,
                    crate::EvidenceRole::SupportsDeadlineRisk => {
                        wire::EvidenceRole::SupportsDeadlineRisk
                    }
                    crate::EvidenceRole::Uncertain => wire::EvidenceRole::Uncertain,
                    crate::EvidenceRole::CorrectedRelevantWork => {
                        wire::EvidenceRole::CorrectedRelevantWork
                    }
                },
                observed_from: wire::UtcTimestamp::from_datetime(evidence.observed_from),
                observed_until: wire::UtcTimestamp::from_datetime(evidence.observed_until),
            })
            .collect(),
        decision: wire::PolicyDecisionView {
            policy_decision_id: wire::PolicyDecisionId::from_uuid(decision.id.as_uuid()),
            policy_version: decision.policy_version.clone(),
            policy_trace: decision
                .policy_trace
                .is_complete()
                .then(|| wire::PolicyTraceView {
                    policy_profile_id: decision.policy_trace.policy_profile_id.clone(),
                    user_preferences_revision: decision.policy_trace.user_preferences_revision,
                    proposed_input_schema_version: decision
                        .policy_trace
                        .proposed_input_schema_version,
                    proposed_input_digest: decision.policy_trace.proposed_input_digest,
                }),
            outcome: match decision.outcome {
                crate::PolicyOutcome::Allow => wire::PolicyDecisionOutcome::Allow,
                crate::PolicyOutcome::Deny => wire::PolicyDecisionOutcome::Deny,
                crate::PolicyOutcome::RequireConfirmation => {
                    wire::PolicyDecisionOutcome::RequireConfirmation
                }
            },
            reason_codes: decision
                .reason_codes
                .iter()
                .map(|reason| reason_code_to_wire(reason))
                .collect(),
            authority: decision
                .permission_grant_revisions
                .iter()
                .map(|(id, revision)| wire::AuthorityReference {
                    authority_id: wire::AuthorityId::from_uuid(id.as_uuid()),
                    revision: *revision,
                })
                .collect(),
            issued_at: wire::UtcTimestamp::from_datetime(decision.issued_at),
            expires_at: wire::UtcTimestamp::from_datetime(decision.expires_at),
        },
        delivery_state: intervention_state_to_wire(intervention.state),
        outcome: intervention_outcome_to_wire(intervention.outcome),
        delivered_text: (!intervention.user_visible_text.is_empty())
            .then(|| intervention.user_visible_text.clone()),
        correction_recorded: intervention.outcome == crate::InterventionOutcome::Corrected,
    }
}

fn evidence_category_to_wire(value: crate::DataCategory) -> wire::ObservationCategory {
    match value {
        crate::DataCategory::WindowMetadata => wire::ObservationCategory::WindowMetadata,
        crate::DataCategory::BrowserLocation => wire::ObservationCategory::BrowserLocation,
        crate::DataCategory::VisibleText => wire::ObservationCategory::VisibleText,
        crate::DataCategory::SelectedDocument => wire::ObservationCategory::SelectedDocument,
        crate::DataCategory::ScreenPixels => wire::ObservationCategory::ScreenPixels,
        crate::DataCategory::WorkspaceActivity => wire::ObservationCategory::WorkspaceActivity,
        crate::DataCategory::Goal
        | crate::DataCategory::FocusSession
        | crate::DataCategory::EvidenceAggregates
        | crate::DataCategory::DeliveryConstraints => wire::ObservationCategory::SourceHealth,
    }
}

fn goal_to_wire(goal: &Goal) -> wire::GoalView {
    wire::GoalView {
        goal_id: goal.id.into(),
        revision: goal.revision.get(),
        owner_id: goal.owner.into(),
        title: goal.title.clone(),
        success_statement: goal.success_statement.clone(),
        deadline: goal.deadline.map(wire::UtcTimestamp::from_datetime),
        state: match goal.state {
            GoalState::Active => wire::GoalState::Active,
            GoalState::Completed => wire::GoalState::Completed,
            GoalState::Abandoned => wire::GoalState::Abandoned,
        },
        created_at: wire::UtcTimestamp::from_datetime(goal.created_at),
        updated_at: wire::UtcTimestamp::from_datetime(goal.updated_at),
    }
}

fn runtime_to_wire(runtime: &RuntimeStatus, active_connections: u32) -> wire::RuntimeStatus {
    wire::RuntimeStatus {
        daemon_instance_id: wire::DaemonInstanceId::from_uuid(runtime.daemon_instance_id),
        state: match runtime.health {
            RuntimeHealth::Healthy => wire::RuntimeState::Ready,
            RuntimeHealth::Degraded => wire::RuntimeState::Degraded,
            RuntimeHealth::Stopping => wire::RuntimeState::Stopping,
        },
        started_at: wire::UtcTimestamp::from_datetime(runtime.started_at),
        observed_at: wire::UtcTimestamp::now(),
        build_id: runtime.build_id.clone(),
        protocol_version: wire::ProtocolVersion::V1_0,
        active_connections,
    }
}

fn capabilities_to_wire(
    runtime_capabilities: &[crate::CapabilityHealth],
) -> Vec<wire::CapabilityHealth> {
    use wire::CapabilityId::{
        CaptureState, DeliveryChannels, EffectivePolicy, FocusSessions, GoalDelete, GoalUpdate,
        InterventionExplanation, InterventionFeedback, InterventionHistory, ModelRouteApproval,
        RequestCancellation, RuntimeShutdown, RuntimeStatus, SelectedResources, SessionPermissions,
        Snapshot, SteinIdentity, UserPreferences, ViewEvents,
    };

    let mut capabilities: Vec<_> = [
        Snapshot,
        RuntimeStatus,
        RuntimeShutdown,
        ViewEvents,
        RequestCancellation,
        GoalUpdate,
        GoalDelete,
        ModelRouteApproval,
        SessionPermissions,
        FocusSessions,
        CaptureState,
        DeliveryChannels,
        InterventionFeedback,
        InterventionHistory,
        InterventionExplanation,
        SteinIdentity,
        UserPreferences,
        EffectivePolicy,
        SelectedResources,
    ]
    .into_iter()
    .map(|capability| wire::CapabilityHealth {
        capability,
        schema_version: wire::SCHEMA_VERSION_V1,
        state: wire::HealthState::Healthy,
        unavailable_reason: None,
    })
    .collect();
    capabilities.extend(runtime_capabilities.iter().map(capability_health_to_wire));
    capabilities
}

fn event_to_wire(event: CoreEvent, active_connections: u32) -> wire::ViewEvent {
    match event {
        CoreEvent::GoalViewChanged { change, goal } => {
            wire::ViewEvent::GoalViewChanged(wire::GoalViewChanged {
                change: match change {
                    crate::GoalViewChange::Created => wire::GoalChangeKind::Created,
                    crate::GoalViewChange::Updated => wire::GoalChangeKind::Updated,
                    crate::GoalViewChange::Completed => wire::GoalChangeKind::Completed,
                    crate::GoalViewChange::Abandoned => wire::GoalChangeKind::Abandoned,
                },
                goal: goal_to_wire(&goal),
            })
        }
        CoreEvent::RuntimeStatusChanged { runtime } => {
            wire::ViewEvent::RuntimeStatusChanged(wire::RuntimeStatusChanged {
                runtime: runtime_to_wire(&runtime, active_connections),
            })
        }
        CoreEvent::FocusSessionViewChanged {
            change,
            focus_session,
        } => wire::ViewEvent::FocusSessionViewChanged(wire::FocusSessionViewChanged {
            change: match change {
                crate::FocusSessionViewChange::Requested => wire::FocusSessionChangeKind::Requested,
                crate::FocusSessionViewChange::Started => wire::FocusSessionChangeKind::Started,
                crate::FocusSessionViewChange::Muted => wire::FocusSessionChangeKind::Muted,
                crate::FocusSessionViewChange::Unmuted => wire::FocusSessionChangeKind::Unmuted,
                crate::FocusSessionViewChange::RecoveryStarted => {
                    wire::FocusSessionChangeKind::RecoveryStarted
                }
                crate::FocusSessionViewChange::Recovered => wire::FocusSessionChangeKind::Recovered,
                crate::FocusSessionViewChange::Stopping => wire::FocusSessionChangeKind::Stopping,
                crate::FocusSessionViewChange::Ended => wire::FocusSessionChangeKind::Ended,
                crate::FocusSessionViewChange::Failed => wire::FocusSessionChangeKind::Failed,
            },
            focus_session: focus_session_to_wire(&focus_session),
        }),
        CoreEvent::CaptureStateChanged { capture } => {
            wire::ViewEvent::CaptureStateChanged(wire::CaptureStateChanged {
                capture: capture_projection_to_wire(&capture),
            })
        }
        CoreEvent::CapabilityHealthChanged { capability } => {
            wire::ViewEvent::CapabilityHealthChanged(wire::CapabilityHealthChanged {
                capability: capability_health_to_wire(&capability),
            })
        }
        CoreEvent::DeliveryChannelViewChanged { channel, .. } => {
            wire::ViewEvent::DeliveryChannelViewChanged(wire::DeliveryChannelViewChanged {
                channel: delivery_channel_status_to_wire(&channel),
            })
        }
        CoreEvent::PermissionViewChanged { change, permission } => {
            let as_of = time::OffsetDateTime::now_utc();
            wire::ViewEvent::PermissionViewChanged(wire::PermissionViewChanged {
                change: match change {
                    crate::PermissionViewChange::Granted => wire::PermissionChangeKind::Granted,
                    crate::PermissionViewChange::Updated => wire::PermissionChangeKind::Updated,
                    crate::PermissionViewChange::Revoked => wire::PermissionChangeKind::Revoked,
                    crate::PermissionViewChange::Expired => wire::PermissionChangeKind::Expired,
                },
                permission: match permission {
                    crate::PermissionRecord::SessionGrant(value) => {
                        wire::PermissionRecordView::SessionGrant(grant_to_wire(&value, as_of))
                    }
                    crate::PermissionRecord::ModelRouteApproval(value) => {
                        wire::PermissionRecordView::ModelRouteApproval(model_route_to_wire(
                            &value, as_of,
                        ))
                    }
                },
            })
        }
        CoreEvent::InterventionAvailable { intervention } => {
            wire::ViewEvent::InterventionAvailable(wire::InterventionAvailable {
                intervention: intervention_to_wire(&intervention),
            })
        }
        CoreEvent::InterventionViewChanged { intervention } => {
            wire::ViewEvent::InterventionViewChanged(wire::InterventionViewChanged {
                intervention: intervention_to_wire(&intervention),
            })
        }
        CoreEvent::InterventionHistoryChanged {
            change,
            intervention_id,
            entry,
            ..
        } => wire::ViewEvent::InterventionHistoryChanged(wire::InterventionHistoryChanged {
            change: match change {
                crate::InterventionHistoryViewChange::Added => {
                    wire::InterventionHistoryChangeKind::Added
                }
                crate::InterventionHistoryViewChange::Updated => {
                    wire::InterventionHistoryChangeKind::Updated
                }
                crate::InterventionHistoryViewChange::Deleted => {
                    wire::InterventionHistoryChangeKind::Deleted
                }
            },
            intervention_id: wire::InterventionId::from_uuid(intervention_id.as_uuid()),
            entry: entry.as_ref().map(intervention_to_wire),
        }),
        CoreEvent::GoalDeleted { tombstone } => wire::ViewEvent::GoalDeleted(wire::GoalDeleted {
            tombstone: goal_deletion_to_wire(&tombstone),
        }),
        CoreEvent::SelectedResourceViewChanged {
            change,
            resource,
            tombstone,
            ..
        } => wire::ViewEvent::SelectedResourceViewChanged(wire::SelectedResourceViewChanged {
            change: match change {
                crate::SelectedResourceViewChange::Registered => {
                    wire::SelectedResourceChangeKind::Registered
                }
                crate::SelectedResourceViewChange::Removed => {
                    wire::SelectedResourceChangeKind::Removed
                }
            },
            resource: resource.as_ref().map(selected_resource_to_wire),
            tombstone: tombstone.as_ref().map(resource_deletion_to_wire),
        }),
        CoreEvent::UserPreferencesViewChanged {
            preferences,
            effective_policy,
        } => wire::ViewEvent::UserPreferencesViewChanged(wire::UserPreferencesViewChanged {
            preferences: preferences_to_wire(&preferences),
            effective_policy: effective_policy_to_wire(&effective_policy),
        }),
    }
}

fn goal_deletion_to_wire(value: &crate::GoalDeletionTombstone) -> wire::GoalDeletionTombstoneView {
    wire::GoalDeletionTombstoneView {
        goal_id: value.goal_id.into(),
        deleted_revision: value.deleted_revision,
        deleted_at: wire::UtcTimestamp::from_datetime(value.deleted_at),
        focus_sessions_deleted: value.summary.focus_sessions,
        grants_deleted: value.summary.grants,
        interventions_deleted: value.summary.interventions,
        pending_deliveries_deleted: value.summary.outbox_entries,
        private_audit_records_deleted: value.summary.audit_records,
        resource_bindings_deleted: value.summary.resource_bindings,
    }
}

fn resource_deletion_to_wire(
    value: &crate::SelectedResourceDeletionTombstone,
) -> wire::SelectedResourceDeletionTombstoneView {
    wire::SelectedResourceDeletionTombstoneView {
        selected_resource_id: wire::SelectedResourceId::from_uuid(value.resource_id.as_uuid()),
        deleted_revision: value.deleted_revision,
        deleted_at: wire::UtcTimestamp::from_datetime(value.deleted_at),
    }
}

fn preferences_from_wire(
    owner: crate::ActorId,
    default_focus_minutes: u16,
    value: &wire::UserPreferencesV1Input,
) -> Result<crate::ExplicitPreferences, ApplicationError> {
    if !value.minimum_intervention_cooldown_ms.is_multiple_of(1_000) {
        return Err(invalid_application(
            "The intervention cooldown must be a whole number of seconds.",
        ));
    }
    let mut allowed_delivery_channels = std::collections::BTreeSet::new();
    for channel in &value.allowed_delivery_channels {
        let wire_name = match channel {
            wire::DeliveryChannelClass::NativeDesktopNotification => "windows.native_notification",
            wire::DeliveryChannelClass::ConnectedDesktop => "connected_desktop",
        };
        if !allowed_delivery_channels.insert(wire_name.to_owned()) {
            return Err(invalid_application(
                "Delivery channel preferences must be unique.",
            ));
        }
    }
    let now = time::OffsetDateTime::now_utc();
    Ok(crate::ExplicitPreferences {
        schema_version: crate::USER_PREFERENCES_SCHEMA_V1,
        owner,
        revision: 0,
        preferred_form_of_address: value.preferred_form_of_address.clone(),
        intervention_tone: match value.intervention_style {
            wire::InterventionStyle::Concise => crate::InterventionTone::Concise,
            wire::InterventionStyle::Neutral => crate::InterventionTone::Neutral,
            wire::InterventionStyle::Reflective => crate::InterventionTone::Reflective,
        },
        default_focus_minutes,
        maximum_interventions_per_session: value.maximum_interventions_per_session,
        maximum_model_requests_per_hour: value.maximum_model_requests_per_hour,
        minimum_intervention_cooldown_seconds: value.minimum_intervention_cooldown_ms / 1_000,
        proactive_interventions_enabled: value.proactive_enabled,
        proactive_interventions_muted: value.proactive_muted,
        do_not_disturb_windows: value
            .do_not_disturb_windows
            .iter()
            .map(|window| crate::DoNotDisturbWindow {
                start_minute_local: window.start_minute_local,
                end_minute_local: window.end_minute_local,
                utc_offset_minutes: window.utc_offset_minutes,
            })
            .collect(),
        allowed_delivery_channels,
        remote_processing_enabled: value.remote_processing_enabled,
        restart_continuity_default: value.restart_continuity_default,
        provenance: crate::RecordProvenance {
            source: crate::RecordProvenanceSource::DirectUser,
            version: "user-preferences-v1".to_owned(),
            recorded_at: now,
        },
        updated_at: now,
    })
}

fn identity_to_wire(value: &crate::SteinIdentity) -> wire::SteinIdentityV1View {
    wire::SteinIdentityV1View {
        schema_version: value.schema_version,
        owner_id: value.owner.into(),
        revision: value.revision,
        display_name: value
            .preferred_name
            .clone()
            .unwrap_or_else(|| "STEIN".to_owned()),
        role_statement: value.identity_statement.clone(),
        invariant_behavioral_constraints: value
            .invariant_behavioral_constraints
            .iter()
            .copied()
            .map(|constraint| match constraint {
                crate::SteinIdentityConstraint::AdvisesRatherThanActs => {
                    wire::SteinIdentityConstraint::AdvisesRatherThanActs
                }
                crate::SteinIdentityConstraint::PreservesUncertainty => {
                    wire::SteinIdentityConstraint::PreservesUncertainty
                }
                crate::SteinIdentityConstraint::RespectsSilence => {
                    wire::SteinIdentityConstraint::RespectsSilence
                }
                crate::SteinIdentityConstraint::NeverImpersonatesUser => {
                    wire::SteinIdentityConstraint::NeverImpersonatesUser
                }
                crate::SteinIdentityConstraint::NeverBypassesPolicy => {
                    wire::SteinIdentityConstraint::NeverBypassesPolicy
                }
            })
            .collect(),
        provenance: provenance_to_wire(&value.provenance),
    }
}

fn provenance_to_wire(value: &crate::RecordProvenance) -> wire::RecordProvenanceView {
    wire::RecordProvenanceView {
        source: match value.source {
            crate::RecordProvenanceSource::ProductMigration => {
                wire::RecordProvenanceSource::ProductMigration
            }
            crate::RecordProvenanceSource::ProductDefault => {
                wire::RecordProvenanceSource::ProductDefault
            }
            crate::RecordProvenanceSource::DirectUser => wire::RecordProvenanceSource::DirectUser,
        },
        version: value.version.clone(),
        recorded_at: wire::UtcTimestamp::from_datetime(value.recorded_at),
    }
}

fn preferences_to_wire(value: &crate::ExplicitPreferences) -> wire::UserPreferencesV1View {
    wire::UserPreferencesV1View {
        schema_version: value.schema_version,
        owner_id: value.owner.into(),
        revision: value.revision,
        preferred_form_of_address: value.preferred_form_of_address.clone(),
        intervention_style: match value.intervention_tone {
            crate::InterventionTone::Concise => wire::InterventionStyle::Concise,
            crate::InterventionTone::Neutral => wire::InterventionStyle::Neutral,
            crate::InterventionTone::Reflective => wire::InterventionStyle::Reflective,
        },
        proactive_enabled: value.proactive_interventions_enabled,
        proactive_muted: value.proactive_interventions_muted,
        maximum_interventions_per_session: value.maximum_interventions_per_session,
        maximum_model_requests_per_hour: value.maximum_model_requests_per_hour,
        minimum_intervention_cooldown_ms: value
            .minimum_intervention_cooldown_seconds
            .saturating_mul(1_000),
        do_not_disturb_windows: value
            .do_not_disturb_windows
            .iter()
            .map(|window| wire::DoNotDisturbWindowView {
                start_minute_local: window.start_minute_local,
                end_minute_local: window.end_minute_local,
                utc_offset_minutes: window.utc_offset_minutes,
            })
            .collect(),
        allowed_delivery_channels: delivery_channels_to_wire(&value.allowed_delivery_channels),
        remote_processing_enabled: value.remote_processing_enabled,
        restart_continuity_default: value.restart_continuity_default,
        provenance: provenance_to_wire(&value.provenance),
    }
}

fn effective_policy_to_wire(value: &crate::EffectivePolicy) -> wire::EffectivePolicyView {
    wire::EffectivePolicyView {
        schema_version: wire::SCHEMA_VERSION_V1,
        policy_profile_id: value.policy_profile_id.to_owned(),
        user_preferences_revision: value.user_preferences_revision,
        source_stale_after_ms: duration_millis(value.source_stale_after),
        maximum_model_evidence_age_ms: duration_millis(value.maximum_model_evidence_age),
        model_request_cooldown_ms: duration_millis(value.model_request_cooldown),
        maximum_model_requests_per_hour: value.maximum_model_requests_per_hour,
        intervention_cooldown_ms: duration_millis(value.intervention_cooldown),
        maximum_interventions_per_session: value.maximum_interventions_per_session,
        proactive_enabled: value.proactive_interventions_enabled,
        proactive_muted: value.proactive_interventions_muted,
        do_not_disturb_windows: value
            .do_not_disturb_windows
            .iter()
            .map(|window| wire::DoNotDisturbWindowView {
                start_minute_local: window.start_minute_local,
                end_minute_local: window.end_minute_local,
                utc_offset_minutes: window.utc_offset_minutes,
            })
            .collect(),
        allowed_delivery_channels: delivery_channels_to_wire(&value.allowed_delivery_channels),
        remote_processing_enabled: value.remote_processing_enabled,
        restart_continuity_default: value.restart_continuity_default,
        outbox_capacity_per_user: u16::try_from(value.outbox_capacity_per_user).unwrap_or(u16::MAX),
        outbox_capacity_per_session: u16::try_from(value.outbox_capacity_per_session)
            .unwrap_or(u16::MAX),
    }
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn delivery_channels_to_wire(
    channels: &std::collections::BTreeSet<String>,
) -> Vec<wire::DeliveryChannelClass> {
    channels
        .iter()
        .filter_map(|channel| match channel.as_str() {
            "windows.native_notification" => {
                Some(wire::DeliveryChannelClass::NativeDesktopNotification)
            }
            "connected_desktop" => Some(wire::DeliveryChannelClass::ConnectedDesktop),
            _ => None,
        })
        .collect()
}

fn cursor(daemon_instance_id: uuid::Uuid, sequence: u64) -> wire::EventCursor {
    wire::EventCursor {
        daemon_instance_id: wire::DaemonInstanceId::from_uuid(daemon_instance_id),
        sequence,
    }
}

fn unsupported_schema(request: &wire::RequestEnvelope) -> wire::PublicError {
    wire::PublicError {
        code: wire::ErrorCode::UnsupportedSchema,
        category: wire::ErrorCategory::IncompatibleVersion,
        summary: "The request schema version is not supported.".to_owned(),
        retryable: false,
        correlation_id: request.metadata.correlation_id,
        details: Some(wire::ErrorDetails::SupportedSchema(
            wire::SupportedSchemaDetails {
                request_kind: request.body.kind(),
                supported_versions: vec![wire::SCHEMA_VERSION_V1],
            },
        )),
    }
}

fn error_to_wire(
    error: ApplicationError,
    correlation_id: wire::CorrelationId,
) -> wire::PublicError {
    let (code, category) = match error.code {
        ErrorCode::InvalidArgument => (
            wire::ErrorCode::InvalidArgument,
            wire::ErrorCategory::InvalidArgument,
        ),
        ErrorCode::PermissionDenied => (
            wire::ErrorCode::PermissionDenied,
            wire::ErrorCategory::PermissionDenied,
        ),
        ErrorCode::NotFound => (wire::ErrorCode::NotFound, wire::ErrorCategory::NotFound),
        ErrorCode::Conflict => (wire::ErrorCode::Conflict, wire::ErrorCategory::Conflict),
        ErrorCode::Unavailable => (
            wire::ErrorCode::CapabilityUnavailable,
            wire::ErrorCategory::Unavailable,
        ),
        ErrorCode::DeadlineExceeded => (
            wire::ErrorCode::DeadlineExceeded,
            wire::ErrorCategory::DeadlineExceeded,
        ),
        ErrorCode::Cancelled => (wire::ErrorCode::Cancelled, wire::ErrorCategory::Cancelled),
        ErrorCode::Internal => (wire::ErrorCode::Internal, wire::ErrorCategory::Internal),
    };

    let details = error
        .current_revision
        .map(|revision| {
            wire::ErrorDetails::CurrentRevision(wire::CurrentRevisionDetails {
                current_revision: revision.get(),
            })
        })
        .or_else(|| {
            let violations: Vec<_> = error
                .field_violations
                .iter()
                .filter_map(field_violation_to_wire)
                .collect();
            (!violations.is_empty()).then_some(wire::ErrorDetails::Validation(
                wire::ValidationErrorDetails { violations },
            ))
        });
    wire::PublicError {
        code,
        category,
        summary: error.summary.to_owned(),
        retryable: error.retryable,
        correlation_id,
        details,
    }
}

fn field_violation_to_wire(value: &crate::FieldViolation) -> Option<wire::FieldViolation> {
    let field = match value.field {
        "title" => wire::ValidationField::Title,
        "success_statement" => wire::ValidationField::SuccessStatement,
        "deadline" => wire::ValidationField::Deadline,
        "delay_ms" => wire::ValidationField::DelayMs,
        _ => return None,
    };
    let reason = match value.reason {
        "must not be blank" => wire::ValidationReason::Required,
        "exceeds the maximum character count" => wire::ValidationReason::TooLong,
        "exceeds the configured maximum" => wire::ValidationReason::OutOfRange,
        _ => wire::ValidationReason::InvalidFormat,
    };
    Some(wire::FieldViolation { field, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreConfig, StaticConfigProvider, UnavailableSecretStore};

    fn runtime() -> CoreApplication {
        CoreApplication::build(
            "test-build",
            &StaticConfigProvider::new(CoreConfig {
                maximum_delay_echo: Duration::from_millis(20),
                ..CoreConfig::default()
            }),
            &UnavailableSecretStore::default(),
        )
        .unwrap()
    }

    fn actor() -> wire::ActorId {
        wire::ActorId::new_v7()
    }

    fn synthetic_view_state() -> (crate::Goal, crate::FocusSession, crate::Intervention) {
        let owner: crate::ActorId = actor().into();
        let now = time::OffsetDateTime::now_utc();
        let goal = crate::Goal {
            id: crate::GoalId::new_v7(),
            owner,
            title: "Synthetic goal".to_owned(),
            success_statement: "Exercise every view mapping.".to_owned(),
            deadline: None,
            state: crate::GoalState::Active,
            revision: crate::Revision::INITIAL,
            created_at: now,
            updated_at: now,
        };
        let session = crate::FocusSession {
            id: crate::FocusSessionId::new_v7(),
            revision: 1,
            owner,
            goal_id: goal.id,
            goal_revision: goal.revision.get(),
            state: crate::FocusSessionState::Starting,
            muted: false,
            source_degraded: false,
            client_disconnect_allowed: false,
            daemon_restart_allowed: false,
            permission_grant_ids: std::collections::BTreeSet::new(),
            selected_resource_ids: std::collections::BTreeSet::new(),
            model_route_approval_id: crate::ModelRouteApprovalId::new_v7(),
            requested_at: now,
            started_at: None,
            ended_at: None,
            updated_at: now,
            failure_reason: None,
        };
        let intervention = crate::Intervention {
            id: crate::InterventionId::new_v7(),
            candidate_id: crate::CandidateId::new_v7(),
            candidate_revision: 1,
            policy_decision_id: crate::PolicyDecisionId::new_v7(),
            revision: 1,
            owner,
            focus_session_id: session.id,
            goal_id: goal.id,
            state: crate::InterventionState::Allowed,
            outcome: crate::InterventionOutcome::Unacknowledged,
            user_visible_text: "Synthetic intervention".to_owned(),
            reason_code: "synthetic_reason".to_owned(),
            evidence_summary: "Synthetic aggregate only".to_owned(),
            evidence: Vec::new(),
            urgency: crate::Urgency::Normal,
            created_at: now,
            expires_at: now + time::Duration::minutes(5),
            updated_at: now,
            delivery_channel: Some("windows.native_notification".to_owned()),
            delivered_at: None,
            outcome_at: None,
            correction_summary: None,
        };
        (goal, session, intervention)
    }

    #[test]
    fn every_core_event_maps_to_its_v1_2_view_event() {
        let (goal, session, intervention) = synthetic_view_state();
        let owner = goal.owner;
        let goal_id = goal.id;
        let now = goal.updated_at;
        let permission = crate::PermissionGrant {
            id: crate::PermissionGrantId::new_v7(),
            revision: 1,
            owner,
            goal_id: goal.id,
            authenticated_client: crate::ClientId::new_v7(),
            device_id: crate::DeviceId::new_v7(),
            focus_session_id: Some(session.id),
            scope: crate::PermissionScope::ObserveDesktopPresence,
            selected_resource_id: None,
            model_route_approval_id: None,
            purpose: "Synthetic contract proof".to_owned(),
            placement: None,
            client_disconnect_allowed: false,
            daemon_restart_allowed: false,
            issued_at: now,
            effective_at: now,
            expires_at: now + time::Duration::hours(1),
            state: crate::GrantState::Active,
            revoked_at: None,
            revocation_reason: None,
            consent_copy_version: "synthetic-v1".to_owned(),
        };
        let resource = crate::ResourceBinding {
            id: crate::ResourceId::new_v7(),
            owner,
            kind: crate::ResourceKind::Document,
            opaque_reference: "synthetic-native-token".to_owned(),
            display_label: "Selected document".to_owned(),
            revision: 1,
            created_at: now,
        };
        let preferences = crate::ExplicitPreferences::phase2_defaults(owner, now);
        let config = crate::SecondMindConfig::default();
        let effective_policy = crate::EffectivePolicy {
            policy_profile_id: "phase2-focus-v1",
            user_preferences_revision: preferences.revision,
            source_stale_after: config.source_freshness,
            maximum_model_evidence_age: config.maximum_model_evidence_age,
            model_request_cooldown: config.model_request_cooldown,
            maximum_model_requests_per_hour: preferences.maximum_model_requests_per_hour,
            intervention_cooldown: config.intervention_cooldown,
            maximum_interventions_per_session: preferences.maximum_interventions_per_session,
            proactive_interventions_enabled: false,
            proactive_interventions_muted: false,
            do_not_disturb_windows: Vec::new(),
            allowed_delivery_channels: preferences.allowed_delivery_channels.clone(),
            remote_processing_enabled: false,
            restart_continuity_default: false,
            outbox_capacity_per_user: config.outbox_capacity_per_user,
            outbox_capacity_per_session: config.outbox_capacity_per_session,
        };
        let runtime_status = runtime().runtime_status();
        let events = vec![
            CoreEvent::GoalViewChanged {
                change: crate::GoalViewChange::Created,
                goal,
            },
            CoreEvent::RuntimeStatusChanged {
                runtime: runtime_status,
            },
            CoreEvent::FocusSessionViewChanged {
                change: crate::FocusSessionViewChange::Requested,
                focus_session: session.clone(),
            },
            CoreEvent::CaptureStateChanged {
                capture: crate::CaptureViewProjection {
                    session,
                    grants: vec![permission.clone()],
                    source_statuses: Vec::new(),
                    native_status_available: true,
                    emergency_control_available: true,
                },
            },
            CoreEvent::CapabilityHealthChanged {
                capability: crate::CapabilityHealth {
                    id: "observation.desktop",
                    state: crate::CapabilityState::Available,
                    detail: "Synthetic capability is available.",
                },
            },
            CoreEvent::DeliveryChannelViewChanged {
                owner,
                channel: crate::DeliveryChannelStatus {
                    channel_id: "windows.native_notification".to_owned(),
                    health: crate::DeliveryChannelHealth::Healthy,
                    detail: "Synthetic channel is healthy.",
                    observed_at: now,
                },
            },
            CoreEvent::PermissionViewChanged {
                change: crate::PermissionViewChange::Granted,
                permission: crate::PermissionRecord::SessionGrant(permission),
            },
            CoreEvent::InterventionAvailable {
                intervention: intervention.clone(),
            },
            CoreEvent::InterventionViewChanged {
                intervention: intervention.clone(),
            },
            CoreEvent::InterventionHistoryChanged {
                change: crate::InterventionHistoryViewChange::Added,
                owner,
                intervention_id: intervention.id,
                entry: Some(intervention),
            },
            CoreEvent::GoalDeleted {
                tombstone: crate::GoalDeletionTombstone {
                    owner,
                    goal_id,
                    deleted_revision: 1,
                    deleted_at: now,
                    summary: crate::DeletionSummary::default(),
                },
            },
            CoreEvent::SelectedResourceViewChanged {
                change: crate::SelectedResourceViewChange::Registered,
                owner,
                resource: Some(resource),
                tombstone: None,
            },
            CoreEvent::UserPreferencesViewChanged {
                preferences,
                effective_policy,
            },
        ];

        let kinds: Vec<_> = events
            .into_iter()
            .map(|event| event_to_wire(event, 1).kind())
            .collect();
        assert_eq!(kinds, wire::ViewEventKind::ALL);
    }

    fn create_request(key: wire::IdempotencyKey) -> wire::RequestEnvelope {
        let mut metadata = wire::RequestMetadata::new(
            wire::Component::TestFixture,
            wire::SensitivityClass::Personal,
            wire::RetentionClass::Runtime,
        );
        metadata.idempotency_key = Some(key);
        wire::RequestEnvelope::new(
            metadata,
            wire::RequestBody::CreateGoal(wire::CreateGoalRequest {
                title: "Synthetic goal".to_owned(),
                success_statement: "The contract proof passes.".to_owned(),
                deadline: None,
            }),
        )
    }

    #[tokio::test]
    async fn protocol_create_is_idempotent_and_snapshot_is_authoritative() {
        let runtime = runtime();
        let actor = actor();
        let request = create_request(wire::IdempotencyKey::new_v7());
        let first = runtime
            .handle_protocol_request(actor, &request, 1, CancellationToken::new())
            .await
            .unwrap();
        let duplicate = runtime
            .handle_protocol_request(actor, &request, 1, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(first, duplicate);

        let subscription = runtime.open_protocol_subscription(actor, 1).unwrap();
        assert_eq!(subscription.snapshot.goals.len(), 1);
        assert_eq!(subscription.snapshot.cursor.sequence, 1);
    }

    #[tokio::test]
    async fn missing_idempotency_key_fails_without_echoing_private_input() {
        let runtime = runtime();
        let mut request = create_request(wire::IdempotencyKey::new_v7());
        request.metadata.idempotency_key = None;
        if let wire::RequestBody::CreateGoal(input) = &mut request.body {
            input.title = "private-title-marker".to_owned();
        }

        let error = runtime
            .handle_protocol_request(actor(), &request, 1, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ErrorCode::InvalidArgument);
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("private-title-marker")
        );
    }

    #[tokio::test]
    async fn protocol_subscription_maps_the_event_after_its_snapshot_cursor() {
        let runtime = runtime();
        let actor = actor();
        let mut subscription = runtime.open_protocol_subscription(actor, 1).unwrap();
        let request = create_request(wire::IdempotencyKey::new_v7());
        runtime
            .handle_protocol_request(actor, &request, 1, CancellationToken::new())
            .await
            .unwrap();

        let event = subscription.receive().await.unwrap();
        assert_eq!(
            event.cursor.sequence,
            subscription.snapshot.cursor.sequence + 1
        );
        assert_eq!(event.actor.actor_id, actor);
        assert_eq!(event.actor.kind, wire::ActorKind::LocalOsUser);
        assert_eq!(event.correlation_id, request.metadata.correlation_id);
        assert_eq!(event.causation_id, Some(request.metadata.message_id));
        assert_eq!(event.sensitivity, wire::SensitivityClass::Personal);
        assert_eq!(event.retention, wire::RetentionClass::Runtime);
        assert!(matches!(event.event, wire::ViewEvent::GoalViewChanged(_)));
    }

    #[tokio::test]
    async fn unsupported_schema_returns_typed_compatibility_detail() {
        let runtime = runtime();
        let mut request = create_request(wire::IdempotencyKey::new_v7());
        request.metadata.schema_version = 99;
        let error = runtime
            .handle_protocol_request(actor(), &request, 1, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ErrorCode::UnsupportedSchema);
        assert!(matches!(
            error.details,
            Some(wire::ErrorDetails::SupportedSchema(_))
        ));
    }

    #[tokio::test]
    async fn protocol_delay_respects_cancellation() {
        let runtime = runtime();
        let metadata = wire::RequestMetadata::new(
            wire::Component::TestFixture,
            wire::SensitivityClass::Operational,
            wire::RetentionClass::TransientProcessing,
        );
        let request = wire::RequestEnvelope::new(
            metadata,
            wire::RequestBody::DelayEcho(wire::DelayEchoRequest {
                delay_ms: 10,
                text: "synthetic".to_owned(),
            }),
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = runtime
            .handle_protocol_request(actor(), &request, 1, cancellation)
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ErrorCode::Cancelled);
    }

    #[test]
    fn protocol_health_maps_composed_capabilities_without_hard_coding() {
        let runtime = runtime();
        let subscription = runtime.open_protocol_subscription(actor(), 1).unwrap();
        for expected in [
            wire::CapabilityId::DesktopObservation,
            wire::CapabilityId::ModelReasoning,
            wire::CapabilityId::DurablePersistence,
            wire::CapabilityId::NativeNotification,
            wire::CapabilityId::NativeStatus,
            wire::CapabilityId::EmergencyControl,
            wire::CapabilityId::SecretStore,
        ] {
            assert!(subscription.snapshot.capabilities.iter().any(|capability| {
                capability.capability == expected
                    && capability.state == wire::HealthState::Unavailable
                    && capability.unavailable_reason
                        == Some(wire::CapabilityUnavailableReason::DependencyUnavailable)
            }));
        }
    }

    #[test]
    fn protocol_capability_mapping_preserves_available_composition_health() {
        let capabilities = capabilities_to_wire(&[
            crate::CapabilityHealth {
                id: "core.persistence",
                state: crate::CapabilityState::Available,
                detail: "Synthetic durable repository is healthy.",
            },
            crate::CapabilityHealth {
                id: "observation.desktop",
                state: crate::CapabilityState::Available,
                detail: "Synthetic observation adapter is healthy.",
            },
        ]);
        for expected in [
            wire::CapabilityId::DurablePersistence,
            wire::CapabilityId::DesktopObservation,
        ] {
            assert!(capabilities.iter().any(|capability| {
                capability.capability == expected
                    && capability.state == wire::HealthState::Healthy
                    && capability.unavailable_reason.is_none()
            }));
        }
    }

    #[test]
    fn daemon_native_resource_kind_maps_every_supported_picker_exactly() {
        for (wire_kind, domain_kind) in [
            (
                wire::SelectedResourceKind::Application,
                crate::ResourceKind::Application,
            ),
            (
                wire::SelectedResourceKind::Window,
                crate::ResourceKind::Window,
            ),
            (
                wire::SelectedResourceKind::BrowserSurface,
                crate::ResourceKind::BrowserSurface,
            ),
            (
                wire::SelectedResourceKind::Document,
                crate::ResourceKind::Document,
            ),
            (
                wire::SelectedResourceKind::Workspace,
                crate::ResourceKind::Workspace,
            ),
            (
                wire::SelectedResourceKind::ScreenRegion,
                crate::ResourceKind::ScreenRegion,
            ),
        ] {
            assert_eq!(daemon_native_resource_kind(wire_kind), Some(domain_kind));
        }
        assert_eq!(
            daemon_native_resource_kind(wire::SelectedResourceKind::Display),
            None
        );
    }

    #[tokio::test]
    async fn protocol_validation_is_structured_and_does_not_echo_input() {
        let runtime = runtime();
        let mut request = create_request(wire::IdempotencyKey::new_v7());
        if let wire::RequestBody::CreateGoal(input) = &mut request.body {
            input.title = "private-marker".repeat(30);
        }
        let error = runtime
            .handle_protocol_request(actor(), &request, 1, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(
            error.details,
            Some(wire::ErrorDetails::Validation(wire::ValidationErrorDetails {
                ref violations
            })) if *violations == vec![wire::FieldViolation {
                field: wire::ValidationField::Title,
                reason: wire::ValidationReason::TooLong,
            }]
        ));
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("private-marker")
        );
    }

    #[test]
    fn model_request_receipt_is_v1_2_only_content_free_and_route_exact() {
        assert!(!supports_model_request_receipt(wire::ProtocolVersion::V1_1));
        assert!(supports_model_request_receipt(wire::ProtocolVersion::V1_2));

        let session_id = crate::FocusSessionId::new_v7();
        let route_id = crate::ModelRouteApprovalId::new_v7();
        let request_id = uuid::Uuid::now_v7();
        let started_at = time::OffsetDateTime::now_utc();
        let completed_at = started_at + time::Duration::milliseconds(25);
        let mapped = model_request_receipt_to_wire(&crate::ModelRequestReceipt {
            request_id,
            focus_session_id: session_id,
            model_route_approval_id: route_id,
            model_route_revision: 7,
            started_at,
            completed_at: Some(completed_at),
            outcome: crate::ModelRequestReceiptOutcome::CompletedStrictCandidate,
        });

        assert_eq!(mapped.request_id.into_uuid(), request_id);
        assert_eq!(mapped.focus_session_id.into_uuid(), session_id.as_uuid());
        assert_eq!(
            mapped.model_route_approval_id.into_uuid(),
            route_id.as_uuid()
        );
        assert_eq!(mapped.model_route_revision, 7);
        assert_eq!(
            mapped.outcome,
            wire::ModelRequestReceiptOutcome::CompletedStrictCandidate
        );
        let encoded = serde_json::to_value(mapped).unwrap();
        let fields: std::collections::BTreeSet<_> = encoded
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            std::collections::BTreeSet::from([
                "completed_at",
                "focus_session_id",
                "model_route_approval_id",
                "model_route_revision",
                "outcome",
                "request_id",
                "started_at",
            ])
        );
    }

    #[tokio::test]
    async fn diagnostic_client_cannot_query_focus_session_model_receipts() {
        let runtime = runtime();
        let actor = actor();
        let metadata = wire::RequestMetadata::new(
            wire::Component::TestFixture,
            wire::SensitivityClass::Personal,
            wire::RetentionClass::TransientProcessing,
        );
        let request = wire::RequestEnvelope::new(
            metadata,
            wire::RequestBody::GetFocusSessionView(wire::GetFocusSessionViewRequest {
                focus_session_id: wire::FocusSessionId::new_v7(),
            }),
        );
        let error = runtime
            .handle_protocol_request_with_context(
                ProtocolRequestContext {
                    actor,
                    client_id: wire::ClientInstanceId::from_uuid(actor.into_uuid()),
                    assurance: crate::ClientAssurance::Diagnostic,
                    negotiated_version: wire::ProtocolVersion::V1_2,
                },
                &request,
                1,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, wire::ErrorCode::PermissionDenied);
        assert_eq!(error.category, wire::ErrorCategory::PermissionDenied);
    }

    #[tokio::test]
    async fn phase2_secrets_diagnostic_client_cannot_query_model_route_state() {
        let runtime = runtime();
        let actor = actor();
        let route_id = wire::ModelRouteApprovalId::new_v7();
        let metadata = wire::RequestMetadata::new(
            wire::Component::TestFixture,
            wire::SensitivityClass::Restricted,
            wire::RetentionClass::TransientProcessing,
        );
        let request = wire::RequestEnvelope::new(
            metadata,
            wire::RequestBody::GetPermissionView(wire::GetPermissionViewRequest {
                permission_grant_id: None,
                model_route_approval_id: Some(route_id),
            }),
        );
        let error = runtime
            .handle_protocol_request_with_context(
                ProtocolRequestContext {
                    actor,
                    client_id: wire::ClientInstanceId::from_uuid(actor.into_uuid()),
                    assurance: crate::ClientAssurance::Diagnostic,
                    negotiated_version: wire::ProtocolVersion::V1_2,
                },
                &request,
                1,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, wire::ErrorCode::PermissionDenied);
        assert_eq!(error.category, wire::ErrorCategory::PermissionDenied);
        assert!(error.details.is_none());
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains(&route_id.to_string()));
        assert!(!encoded.contains("secret_ref"));
    }
}
