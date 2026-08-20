//! The only module allowed to depend on `stein-ipc` or protocol wire DTOs.
//! Native credential collection and storage remain isolated in the sibling
//! `native_credential_prompt` module.
//!
//! The React renderer receives projections and typed command results. It never
//! receives a pipe name, broker authority, native handle, or a secret read API.

use std::{collections::BTreeMap, str::FromStr};

use stein_core::SecretStoreErrorKind;
use stein_ipc::{Client, ClientAssurance, ClientError, ClientSubscription};
use stein_protocol::{
    AbandonGoalRequest, ApproveModelRouteRequest, CompleteGoalRequest, Component,
    DeleteGoalRequest, DeliveryChannelClass, DoNotDisturbWindowView as ProtocolDndWindow,
    ErrorCategory as ProtocolErrorCategory, ErrorCode, ErrorDetails, ExplainInterventionRequest,
    FocusSessionEndReason, GetInterventionHistoryRequest, GoalDeadlinePatch, GoalPatch,
    GrantSessionPermissionRequest, InterventionFeedback, InterventionStyle, ModelDataCategory,
    ModelPlacement, ModelRouteReference, PermissionContinuity, PermissionReference,
    PermissionScope, ProtocolSupport, ProviderHandlingProfile, ProviderRetentionPolicy,
    ProviderTrainingUse, RecordInterventionFeedbackRequest, RegisterSelectedResourceRequest,
    RemoveSelectedResourceRequest, RevokePermissionRequest, SelectedResourceKind,
    SetInterventionsMutedRequest, StartFocusSessionRequest, UpdateGoalRequest,
    UpdateUserPreferencesRequest, UserPreferencesV1Input, UtcTimestamp, ValidationField,
    ValidationReason,
};

use crate::{
    native_credential_prompt::{self, NativeCredentialPromptError},
    view::{
        AbandonGoalInput, ApproveModelRouteInput, CreateGoalInput, EffectivePolicyView,
        EndFocusSessionInput, ErrorCategory, ExplainInterventionInput, FocusSessionView,
        GoalDeadlinePatchInput, GoalDeletionView, GoalRevisionInput, GoalView,
        GrantPermissionInput, InterventionExplanationView, InterventionFeedbackInput,
        InterventionHistoryInput, InterventionHistoryView, InterventionView, ModelRouteView,
        PublicErrorView, RegisterSelectedResourceInput, RemoveSelectedResourceInput, ResourceView,
        RevokePermissionInput, SecretMutationView, SelectedResourceDeletionView, SessionGrantView,
        SetMutedInput, StartFocusSessionInput, SteinIdentityView, StoreModelSecretInput,
        UpdateGoalInput, UpdateUserPreferencesInput, UserPreferencesUpdateView,
        UserPreferencesView,
    },
};

const DESKTOP_PROTOCOL_SUPPORT: ProtocolSupport = ProtocolSupport::V1_2;

#[derive(Clone)]
pub struct SteinClientAdapter {
    client: Client,
}

impl SteinClientAdapter {
    #[cfg(windows)]
    pub async fn connect_default() -> Result<Self, PublicErrorView> {
        match crate::private_broker::connect().await {
            Ok(transport) => {
                let (pipe, authority) = transport.into_parts();
                Client::connect_private_brokered(
                    "stein-desktop",
                    Component::DesktopClient,
                    DESKTOP_PROTOCOL_SUPPORT,
                    pipe,
                    authority,
                )
                .await
                .map(|client| Self { client })
                .map_err(public_client_error)
            }
            Err(crate::private_broker::PrivateBrokerError::Unpackaged) => {
                // The retained unpackaged Phase 1 build is diagnostic-only.
                // A packaged production desktop never silently downgrades when
                // its broker identity or activation boundary fails.
                Client::connect_with_identity(
                    "stein-desktop",
                    Component::DesktopClient,
                    DESKTOP_PROTOCOL_SUPPORT,
                )
                .await
                .map(|client| Self { client })
                .map_err(public_client_error)
            }
            Err(error) => Err(private_broker_error(error)),
        }
    }

    #[cfg(not(windows))]
    pub async fn connect_default() -> Result<Self, PublicErrorView> {
        Client::connect_with_identity(
            "stein-desktop",
            Component::DesktopClient,
            DESKTOP_PROTOCOL_SUPPORT,
        )
        .await
        .map(|client| Self { client })
        .map_err(public_client_error)
    }

    pub fn private_protocol_available(&self) -> bool {
        matches!(
            self.client.assurance(),
            ClientAssurance::PrivateCapabilityBound
        )
    }

    pub async fn authoritative_snapshot(
        &self,
    ) -> Result<stein_protocol::ClientSnapshot, PublicErrorView> {
        if self.private_protocol_available() {
            self.client
                .get_client_snapshot()
                .await
                .map_err(public_client_error)
        } else {
            // GetSnapshot is deliberately private. Refresh only the diagnostic
            // allowlist and construct a content-free replacement snapshot.
            let status = self
                .client
                .get_runtime_status()
                .await
                .map_err(public_client_error)?;
            let mut snapshot = self.client.session().snapshot.clone();
            snapshot.snapshot_id = stein_protocol::SnapshotId::new_v7();
            snapshot.as_of = UtcTimestamp::now();
            snapshot.runtime = status.runtime;
            snapshot.capabilities = status.capabilities;
            snapshot.goals.clear();
            snapshot.phase2 = None;
            Ok(snapshot)
        }
    }

    pub async fn open_subscription(&self) -> Result<ClientSubscription, PublicErrorView> {
        self.client
            .open_subscription()
            .await
            .map_err(public_client_error)
    }

    pub async fn cached_snapshot(&self) -> stein_protocol::ClientSnapshot {
        self.client.cached_snapshot().await
    }

    pub async fn create_goal(&self, input: CreateGoalInput) -> Result<GoalView, PublicErrorView> {
        self.require_private()?;
        let deadline = optional_timestamp(input.deadline.as_deref(), "deadline")?;
        let idempotency_key = parse_id(&input.idempotency_key, "idempotencyKey")?;
        self.client
            .create_goal_idempotent(
                stein_protocol::CreateGoalRequest {
                    title: input.title,
                    success_statement: input.success_statement,
                    deadline,
                },
                idempotency_key,
            )
            .await
            .map(|response| GoalView::from_protocol(&response.goal))
            .map_err(public_client_error)
    }

    pub async fn update_goal(&self, input: UpdateGoalInput) -> Result<GoalView, PublicErrorView> {
        self.require_private()?;
        let deadline = match input.patch.deadline {
            None => None,
            Some(GoalDeadlinePatchInput::Clear) => Some(GoalDeadlinePatch::Clear),
            Some(GoalDeadlinePatchInput::Set { deadline }) => Some(GoalDeadlinePatch::Set {
                deadline: required_timestamp(&deadline, "patch.deadline.deadline")?,
            }),
        };
        self.client
            .update_goal(UpdateGoalRequest {
                goal_id: parse_id(&input.goal_id, "goalId")?,
                expected_revision: input.expected_revision,
                patch: GoalPatch {
                    title: input.patch.title,
                    success_statement: input.patch.success_statement,
                    deadline,
                },
            })
            .await
            .map(|response| GoalView::from_protocol(&response.goal))
            .map_err(public_client_error)
    }

    pub async fn complete_goal(
        &self,
        input: GoalRevisionInput,
    ) -> Result<GoalView, PublicErrorView> {
        self.require_private()?;
        self.client
            .complete_goal(CompleteGoalRequest {
                goal_id: parse_id(&input.goal_id, "goalId")?,
                expected_revision: input.expected_revision,
            })
            .await
            .map(|response| GoalView::from_protocol(&response.goal))
            .map_err(public_client_error)
    }

    pub async fn abandon_goal(&self, input: AbandonGoalInput) -> Result<GoalView, PublicErrorView> {
        self.require_private()?;
        self.client
            .abandon_goal(AbandonGoalRequest {
                goal_id: parse_id(&input.goal_id, "goalId")?,
                expected_revision: input.expected_revision,
                reason: input.reason,
            })
            .await
            .map(|response| GoalView::from_protocol(&response.goal))
            .map_err(public_client_error)
    }

    pub async fn delete_goal(
        &self,
        input: GoalRevisionInput,
    ) -> Result<GoalDeletionView, PublicErrorView> {
        self.require_private()?;
        self.client
            .delete_goal(DeleteGoalRequest {
                goal_id: parse_id(&input.goal_id, "goalId")?,
                expected_revision: input.expected_revision,
            })
            .await
            .map(|response| {
                GoalDeletionView::from_protocol(&response.tombstone, response.already_deleted)
            })
            .map_err(public_client_error)
    }

    pub async fn store_model_secret(
        &self,
        input: StoreModelSecretInput,
        parent_window: isize,
    ) -> Result<SecretMutationView, PublicErrorView> {
        self.require_private()?;
        let route_id = input.route_id;
        let response_route_id = route_id.clone();
        tokio::task::spawn_blocking(move || {
            native_credential_prompt::prompt_and_store(route_id, parent_window)
        })
        .await
        .map_err(|_| {
            PublicErrorView::unavailable(
                "secret_store_task_failed",
                "The native secret-store operation did not complete.",
            )
        })?
        .map_err(native_credential_error)?;
        Ok(SecretMutationView {
            route_id: response_route_id,
            configured: true,
        })
    }

    pub async fn approve_model_route(
        &self,
        input: ApproveModelRouteInput,
    ) -> Result<ModelRouteView, PublicErrorView> {
        self.require_private()?;
        let allowed_data_categories = input
            .allowed_data_categories
            .iter()
            .map(|category| parse_model_data_category(category))
            .collect::<Result<Vec<_>, _>>()?;
        let retention = parse_retention(&input.retention_kind, input.retention_maximum_seconds)?;
        let request = ApproveModelRouteRequest {
            route: ModelRouteReference {
                provider_id: input.provider_id,
                route_id: input.route_id,
                placement: parse_placement(&input.placement)?,
            },
            account_profile: input.account_profile,
            allowed_data_categories,
            handling: ProviderHandlingProfile {
                retention,
                training_use: parse_training_use(&input.training_use)?,
                data_residency: input.data_residency,
                profile_version: input.handling_profile_version,
            },
            purpose: input.purpose,
            maximum_request_tokens: input.maximum_request_tokens,
            fallback: None,
            expires_at: optional_timestamp(input.expires_at.as_deref(), "expiresAt")?,
            disclosure_version: input.disclosure_version,
        };
        self.client
            .approve_model_route(request, parse_id(&input.idempotency_key, "idempotencyKey")?)
            .await
            .map(|response| ModelRouteView::from_protocol(&response.approval))
            .map_err(public_client_error)
    }

    pub async fn grant_permission(
        &self,
        input: GrantPermissionInput,
    ) -> Result<SessionGrantView, PublicErrorView> {
        self.require_private()?;
        let _legacy_device_id = input.device_id;
        let request = GrantSessionPermissionRequest {
            goal_id: parse_id(&input.goal_id, "goalId")?,
            device_id: None,
            scope: parse_permission_scope(&input.scope)?,
            selected_resource_id: optional_id(
                input.selected_resource_id.as_deref(),
                "selectedResourceId",
            )?,
            purpose: input.purpose,
            expires_at: required_timestamp(&input.expires_at, "expiresAt")?,
            continuity: PermissionContinuity {
                while_client_disconnected: input.while_client_disconnected,
                after_daemon_restart: input.after_daemon_restart,
            },
            consent_copy_version: input.consent_copy_version,
        };
        self.client
            .grant_session_permission(request, parse_id(&input.idempotency_key, "idempotencyKey")?)
            .await
            .map(|response| SessionGrantView::from_protocol(&response.permission))
            .map_err(public_client_error)
    }

    pub async fn revoke_permission(
        &self,
        input: RevokePermissionInput,
    ) -> Result<(), PublicErrorView> {
        self.require_private()?;
        let target = match input.permission_type.as_str() {
            "session_grant" => PermissionReference::SessionGrant {
                permission_grant_id: parse_id(&input.permission_id, "permissionId")?,
            },
            "model_route_approval" => PermissionReference::ModelRouteApproval {
                model_route_approval_id: parse_id(&input.permission_id, "permissionId")?,
            },
            _ => {
                return Err(invalid_field(
                    "permissionType",
                    "Choose a supported permission type.",
                ));
            }
        };
        self.client
            .revoke_permission(RevokePermissionRequest {
                target,
                expected_revision: input.expected_revision,
                reason: input.reason,
            })
            .await
            .map(|_| ())
            .map_err(public_client_error)
    }

    pub async fn start_focus_session(
        &self,
        input: StartFocusSessionInput,
    ) -> Result<FocusSessionView, PublicErrorView> {
        self.require_private()?;
        let request = StartFocusSessionRequest {
            goal_id: parse_id(&input.goal_id, "goalId")?,
            goal_revision: input.goal_revision,
            selected_resource_ids: input
                .selected_resource_ids
                .iter()
                .map(|value| parse_id(value, "selectedResourceIds"))
                .collect::<Result<Vec<_>, _>>()?,
            permission_grant_ids: input
                .permission_grant_ids
                .iter()
                .map(|value| parse_id(value, "permissionGrantIds"))
                .collect::<Result<Vec<_>, _>>()?,
            model_route_approval_id: parse_id(
                &input.model_route_approval_id,
                "modelRouteApprovalId",
            )?,
        };
        self.client
            .start_focus_session(request, parse_id(&input.idempotency_key, "idempotencyKey")?)
            .await
            .map(|response| FocusSessionView::from_protocol(&response.focus_session))
            .map_err(public_client_error)
    }

    pub async fn register_selected_resource(
        &self,
        input: RegisterSelectedResourceInput,
    ) -> Result<ResourceView, PublicErrorView> {
        self.require_private()?;
        self.client
            .register_selected_resource(
                RegisterSelectedResourceRequest {
                    kind: parse_selected_resource_kind(&input.kind)?,
                },
                parse_id(&input.idempotency_key, "idempotencyKey")?,
            )
            .await
            .map(|response| ResourceView::from_protocol(&response.resource))
            .map_err(public_client_error)
    }

    pub async fn remove_selected_resource(
        &self,
        input: RemoveSelectedResourceInput,
    ) -> Result<SelectedResourceDeletionView, PublicErrorView> {
        self.require_private()?;
        self.client
            .remove_selected_resource(RemoveSelectedResourceRequest {
                selected_resource_id: parse_id(&input.selected_resource_id, "selectedResourceId")?,
                expected_revision: input.expected_revision,
            })
            .await
            .map(|response| SelectedResourceDeletionView::from_protocol(&response.tombstone))
            .map_err(public_client_error)
    }

    pub async fn update_user_preferences(
        &self,
        input: UpdateUserPreferencesInput,
    ) -> Result<UserPreferencesUpdateView, PublicErrorView> {
        self.require_private()?;
        let preferences = input.preferences;
        let allowed_delivery_channels = preferences
            .allowed_delivery_channels
            .iter()
            .map(|channel| parse_delivery_channel_class(channel))
            .collect::<Result<Vec<_>, _>>()?;
        self.client
            .update_user_preferences(UpdateUserPreferencesRequest {
                expected_revision: input.expected_revision,
                preferences: UserPreferencesV1Input {
                    preferred_form_of_address: preferences.preferred_form_of_address,
                    intervention_style: parse_intervention_style(&preferences.intervention_style)?,
                    proactive_enabled: preferences.proactive_enabled,
                    proactive_muted: preferences.proactive_muted,
                    maximum_interventions_per_session: preferences
                        .maximum_interventions_per_session,
                    maximum_model_requests_per_hour: preferences.maximum_model_requests_per_hour,
                    minimum_intervention_cooldown_ms: preferences.minimum_intervention_cooldown_ms,
                    do_not_disturb_windows: preferences
                        .do_not_disturb_windows
                        .iter()
                        .map(|window| ProtocolDndWindow {
                            start_minute_local: window.start_minute_local,
                            end_minute_local: window.end_minute_local,
                            utc_offset_minutes: window.utc_offset_minutes,
                        })
                        .collect(),
                    allowed_delivery_channels,
                    remote_processing_enabled: preferences.remote_processing_enabled,
                    restart_continuity_default: preferences.restart_continuity_default,
                },
            })
            .await
            .map(|response| UserPreferencesUpdateView {
                preferences: UserPreferencesView::from_protocol(&response.preferences),
                effective_policy: EffectivePolicyView::from_protocol(&response.effective_policy),
            })
            .map_err(public_client_error)
    }

    pub async fn get_stein_identity(&self) -> Result<SteinIdentityView, PublicErrorView> {
        self.require_private()?;
        self.client
            .get_stein_identity()
            .await
            .map(|response| SteinIdentityView::from_protocol(&response.identity))
            .map_err(public_client_error)
    }

    pub async fn get_user_preferences(&self) -> Result<UserPreferencesView, PublicErrorView> {
        self.require_private()?;
        self.client
            .get_user_preferences()
            .await
            .map(|response| UserPreferencesView::from_protocol(&response.preferences))
            .map_err(public_client_error)
    }

    pub async fn get_effective_policy(&self) -> Result<EffectivePolicyView, PublicErrorView> {
        self.require_private()?;
        self.client
            .get_effective_policy()
            .await
            .map(|response| EffectivePolicyView::from_protocol(&response.effective_policy))
            .map_err(public_client_error)
    }

    pub async fn get_selected_resources(&self) -> Result<Vec<ResourceView>, PublicErrorView> {
        self.require_private()?;
        self.client
            .get_selected_resources()
            .await
            .map(|response| {
                response
                    .resources
                    .iter()
                    .map(ResourceView::from_protocol)
                    .collect()
            })
            .map_err(public_client_error)
    }

    pub async fn set_muted(
        &self,
        input: SetMutedInput,
    ) -> Result<FocusSessionView, PublicErrorView> {
        self.require_private()?;
        self.client
            .set_interventions_muted(SetInterventionsMutedRequest {
                focus_session_id: parse_id(&input.focus_session_id, "focusSessionId")?,
                expected_revision: input.expected_revision,
                muted: input.muted,
            })
            .await
            .map(|response| FocusSessionView::from_protocol(&response.focus_session))
            .map_err(public_client_error)
    }

    pub async fn end_focus_session(
        &self,
        input: EndFocusSessionInput,
    ) -> Result<FocusSessionView, PublicErrorView> {
        self.require_private()?;
        self.client
            .end_focus_session(stein_protocol::EndFocusSessionRequest {
                focus_session_id: parse_id(&input.focus_session_id, "focusSessionId")?,
                expected_revision: input.expected_revision,
                reason: FocusSessionEndReason::UserRequested,
            })
            .await
            .map(|response| FocusSessionView::from_protocol(&response.focus_session))
            .map_err(public_client_error)
    }

    pub async fn record_feedback(
        &self,
        input: InterventionFeedbackInput,
    ) -> Result<InterventionView, PublicErrorView> {
        self.require_private()?;
        let feedback = match input.feedback.as_str() {
            "accepted" => InterventionFeedback::Accepted,
            "dismissed" => InterventionFeedback::Dismissed,
            "corrected" => {
                let correction = input
                    .correction
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| invalid_field("correction", "Enter the corrected context."))?;
                InterventionFeedback::Corrected {
                    correction,
                    associate_resource_id: optional_id(
                        input.associate_resource_id.as_deref(),
                        "associateResourceId",
                    )?,
                }
            }
            _ => {
                return Err(invalid_field(
                    "feedback",
                    "Choose a supported feedback outcome.",
                ));
            }
        };
        self.client
            .record_intervention_feedback(RecordInterventionFeedbackRequest {
                intervention_id: parse_id(&input.intervention_id, "interventionId")?,
                expected_revision: input.expected_revision,
                feedback,
            })
            .await
            .map(|response| InterventionView::from_protocol(&response.intervention))
            .map_err(public_client_error)
    }

    pub async fn explain_intervention(
        &self,
        input: ExplainInterventionInput,
    ) -> Result<InterventionExplanationView, PublicErrorView> {
        self.require_private()?;
        self.client
            .explain_intervention(ExplainInterventionRequest {
                intervention_id: parse_id(&input.intervention_id, "interventionId")?,
            })
            .await
            .map(|response| InterventionExplanationView::from_protocol(&response.explanation))
            .map_err(public_client_error)
    }

    pub async fn get_intervention_history(
        &self,
        input: InterventionHistoryInput,
    ) -> Result<InterventionHistoryView, PublicErrorView> {
        self.require_private()?;
        if input.limit == 0 {
            return Err(invalid_field(
                "limit",
                "Request at least one history entry.",
            ));
        }
        self.client
            .get_intervention_history(GetInterventionHistoryRequest {
                focus_session_id: optional_id(input.focus_session_id.as_deref(), "focusSessionId")?,
                limit: input.limit,
                before: optional_timestamp(input.before.as_deref(), "before")?,
            })
            .await
            .map(|response| InterventionHistoryView::from_protocol(&response.history))
            .map_err(public_client_error)
    }

    fn require_private(&self) -> Result<(), PublicErrorView> {
        if self.private_protocol_available() {
            Ok(())
        } else {
            Err(PublicErrorView::permission_denied(
                "private_client_required",
                "This desktop connection is diagnostic-only. Signed-package broker admission is required for private state and controls.",
            ))
        }
    }
}

fn parse_id<T>(value: &str, field: &str) -> Result<T, PublicErrorView>
where
    T: FromStr,
{
    value
        .parse()
        .map_err(|_| invalid_field(field, "Use a canonical UUID identifier."))
}

fn optional_id<T>(value: Option<&str>, field: &str) -> Result<Option<T>, PublicErrorView>
where
    T: FromStr,
{
    value.map(|value| parse_id(value, field)).transpose()
}

fn required_timestamp(value: &str, field: &str) -> Result<UtcTimestamp, PublicErrorView> {
    UtcTimestamp::from_str(value)
        .map_err(|_| invalid_field(field, "Use an RFC 3339 UTC timestamp."))
}

fn optional_timestamp(
    value: Option<&str>,
    field: &str,
) -> Result<Option<UtcTimestamp>, PublicErrorView> {
    value
        .map(|value| required_timestamp(value, field))
        .transpose()
}

fn parse_placement(value: &str) -> Result<ModelPlacement, PublicErrorView> {
    match value {
        "local" => Ok(ModelPlacement::Local),
        "remote" => Ok(ModelPlacement::Remote),
        _ => Err(invalid_field(
            "placement",
            "Choose local or remote placement.",
        )),
    }
}

fn parse_training_use(value: &str) -> Result<ProviderTrainingUse, PublicErrorView> {
    match value {
        "excluded" => Ok(ProviderTrainingUse::Excluded),
        "may_use" => Ok(ProviderTrainingUse::MayUse),
        "unknown" => Ok(ProviderTrainingUse::Unknown),
        _ => Err(invalid_field(
            "trainingUse",
            "Choose a disclosed training-use value.",
        )),
    }
}

fn parse_retention(
    kind: &str,
    maximum_seconds: Option<u64>,
) -> Result<ProviderRetentionPolicy, PublicErrorView> {
    match kind {
        "none" => Ok(ProviderRetentionPolicy::None),
        "transient" => Ok(ProviderRetentionPolicy::Transient),
        "bounded" => maximum_seconds
            .filter(|seconds| *seconds > 0)
            .map(|maximum_seconds| ProviderRetentionPolicy::Bounded { maximum_seconds })
            .ok_or_else(|| {
                invalid_field(
                    "retentionMaximumSeconds",
                    "Bounded retention requires a positive maximum.",
                )
            }),
        "unknown" => Ok(ProviderRetentionPolicy::Unknown),
        _ => Err(invalid_field(
            "retentionKind",
            "Choose a supported provider-retention disclosure.",
        )),
    }
}

fn parse_model_data_category(value: &str) -> Result<ModelDataCategory, PublicErrorView> {
    match value {
        "goal" => Ok(ModelDataCategory::Goal),
        "focus_session" => Ok(ModelDataCategory::FocusSession),
        "evidence_aggregates" => Ok(ModelDataCategory::EvidenceAggregates),
        "window_metadata" => Ok(ModelDataCategory::WindowMetadata),
        "browser_location" => Ok(ModelDataCategory::BrowserLocation),
        "visible_text" => Ok(ModelDataCategory::VisibleText),
        "selected_document" => Ok(ModelDataCategory::SelectedDocument),
        "screen_pixels" => Ok(ModelDataCategory::ScreenPixels),
        "workspace_activity" => Ok(ModelDataCategory::WorkspaceActivity),
        "delivery_constraints" => Ok(ModelDataCategory::DeliveryConstraints),
        _ => Err(invalid_field(
            "allowedDataCategories",
            "Choose only supported model data categories.",
        )),
    }
}

fn parse_permission_scope(value: &str) -> Result<PermissionScope, PublicErrorView> {
    match value {
        "observe.desktop.presence" => Ok(PermissionScope::ObserveDesktopPresence),
        "observe.desktop.foreground_application" => {
            Ok(PermissionScope::ObserveDesktopForegroundApplication)
        }
        "observe.desktop.window_metadata" => Ok(PermissionScope::ObserveDesktopWindowMetadata),
        "observe.browser.location" => Ok(PermissionScope::ObserveBrowserLocation),
        "observe.content.visible_text" => Ok(PermissionScope::ObserveContentVisibleText),
        "observe.content.selected_document" => Ok(PermissionScope::ObserveContentSelectedDocument),
        "observe.screen.pixels" => Ok(PermissionScope::ObserveScreenPixels),
        "observe.workspace.activity" => Ok(PermissionScope::ObserveWorkspaceActivity),
        "reason.focus_context" => Ok(PermissionScope::ReasonFocusContext),
        "intervene.desktop.notification" => Ok(PermissionScope::InterveneDesktopNotification),
        _ => Err(invalid_field(
            "scope",
            "Choose a supported permission scope.",
        )),
    }
}

fn parse_selected_resource_kind(value: &str) -> Result<SelectedResourceKind, PublicErrorView> {
    match value {
        "application" => Ok(SelectedResourceKind::Application),
        "window" => Ok(SelectedResourceKind::Window),
        "browser_surface" => Ok(SelectedResourceKind::BrowserSurface),
        "document" => Ok(SelectedResourceKind::Document),
        "workspace" => Ok(SelectedResourceKind::Workspace),
        "screen_region" => Ok(SelectedResourceKind::ScreenRegion),
        "display" => Ok(SelectedResourceKind::Display),
        _ => Err(invalid_field(
            "kind",
            "Choose a supported selected-resource kind.",
        )),
    }
}

fn parse_intervention_style(value: &str) -> Result<InterventionStyle, PublicErrorView> {
    match value {
        "concise" => Ok(InterventionStyle::Concise),
        "neutral" => Ok(InterventionStyle::Neutral),
        "reflective" => Ok(InterventionStyle::Reflective),
        _ => Err(invalid_field(
            "interventionStyle",
            "Choose a supported intervention style.",
        )),
    }
}

fn parse_delivery_channel_class(value: &str) -> Result<DeliveryChannelClass, PublicErrorView> {
    match value {
        "native_desktop_notification" => Ok(DeliveryChannelClass::NativeDesktopNotification),
        "connected_desktop" => Ok(DeliveryChannelClass::ConnectedDesktop),
        _ => Err(invalid_field(
            "allowedDeliveryChannels",
            "Choose only supported delivery channels.",
        )),
    }
}

fn invalid_field(field: &str, summary: &str) -> PublicErrorView {
    PublicErrorView::invalid_argument(
        "invalid_argument",
        "The desktop command contains an invalid field.",
        BTreeMap::from([(field.to_owned(), summary.to_owned())]),
    )
}

fn secret_store_error(error: stein_core::SecretStoreError) -> PublicErrorView {
    match error.kind {
        SecretStoreErrorKind::AccessDenied | SecretStoreErrorKind::Locked => {
            PublicErrorView::permission_denied("secret_store_denied", error.summary)
        }
        SecretStoreErrorKind::InvalidReference | SecretStoreErrorKind::ValueTooLarge => {
            invalid_field("secret", error.summary)
        }
        SecretStoreErrorKind::NotFound
        | SecretStoreErrorKind::Unavailable
        | SecretStoreErrorKind::Internal => {
            PublicErrorView::unavailable("secret_store_unavailable", error.summary)
        }
    }
}

fn native_credential_error(error: NativeCredentialPromptError) -> PublicErrorView {
    match error {
        NativeCredentialPromptError::Cancelled => PublicErrorView {
            code: "credential_prompt_cancelled".to_owned(),
            category: ErrorCategory::Cancelled,
            summary: "The Windows credential prompt was cancelled.".to_owned(),
            retryable: true,
            correlation_id: None,
            field_errors: None,
        },
        NativeCredentialPromptError::InvalidReference => invalid_field(
            "routeId",
            "Use an exact route identifier containing only letters, numbers, '.', '-', or '_'.",
        ),
        NativeCredentialPromptError::Unavailable => PublicErrorView::unavailable(
            "credential_prompt_unavailable",
            "Windows could not open the native credential prompt.",
        ),
        NativeCredentialPromptError::Internal => PublicErrorView::unavailable(
            "credential_prompt_failed",
            "Windows returned an unusable credential value.",
        ),
        NativeCredentialPromptError::Store(error) => secret_store_error(error),
    }
}

fn public_client_error(error: ClientError) -> PublicErrorView {
    match error {
        ClientError::Request(error) => public_protocol_error(error),
        ClientError::Timeout => PublicErrorView {
            code: "deadline_exceeded".to_owned(),
            category: ErrorCategory::DeadlineExceeded,
            summary: "CORE did not answer before the desktop request timed out.".to_owned(),
            retryable: true,
            correlation_id: None,
            field_errors: None,
        },
        ClientError::Handshake(_) => PublicErrorView {
            code: "protocol_handshake_failed".to_owned(),
            category: ErrorCategory::IncompatibleVersion,
            summary: "The desktop and CORE could not negotiate protocol 1.2.".to_owned(),
            retryable: false,
            correlation_id: None,
            field_errors: None,
        },
        ClientError::EventGap => PublicErrorView::unavailable(
            "event_gap",
            "The event stream lost continuity. Reconnect for an authoritative snapshot.",
        ),
        ClientError::Cancelled => PublicErrorView {
            code: "cancelled".to_owned(),
            category: ErrorCategory::Cancelled,
            summary: "The CORE request was cancelled.".to_owned(),
            retryable: true,
            correlation_id: None,
            field_errors: None,
        },
        ClientError::CancellationUnconfirmed => PublicErrorView::unavailable(
            "cancellation_unconfirmed",
            "CORE did not confirm cancellation before the safety deadline.",
        ),
        ClientError::PrivateCapabilityRequired => PublicErrorView::permission_denied(
            "private_client_required",
            "Signed-package broker admission is required for this private operation.",
        ),
        ClientError::PrivateBrokerAdmission => PublicErrorView::permission_denied(
            "private_broker_admission_failed",
            "The installed private broker did not retain valid Windows admission for this session.",
        ),
        ClientError::UnsupportedProtocol { .. } => PublicErrorView {
            code: "incompatible_protocol".to_owned(),
            category: ErrorCategory::IncompatibleVersion,
            summary: "This operation requires CORE protocol 1.2.".to_owned(),
            retryable: false,
            correlation_id: None,
            field_errors: None,
        },
        ClientError::Transport(_) | ClientError::Closed | ClientError::UnexpectedResponse => {
            PublicErrorView::unavailable(
                "core_unavailable",
                "The desktop bridge cannot reach the per-user CORE daemon.",
            )
        }
    }
}

#[cfg(windows)]
fn private_broker_error(error: crate::private_broker::PrivateBrokerError) -> PublicErrorView {
    match error {
        crate::private_broker::PrivateBrokerError::WrongDesktopIdentity
        | crate::private_broker::PrivateBrokerError::BrokerAdmissionFailed => {
            PublicErrorView::permission_denied(
                "private_broker_identity_failed",
                "Windows could not verify the installed STEIN private-client identity.",
            )
        }
        crate::private_broker::PrivateBrokerError::ActivationUnavailable
        | crate::private_broker::PrivateBrokerError::ConnectionUnavailable => {
            PublicErrorView::unavailable(
                "private_broker_unavailable",
                "The installed STEIN private broker is unavailable.",
            )
        }
        crate::private_broker::PrivateBrokerError::Unpackaged => {
            PublicErrorView::permission_denied(
                "private_broker_package_required",
                "Private controls require the installed signed STEIN package.",
            )
        }
    }
}

fn public_protocol_error(error: stein_protocol::PublicError) -> PublicErrorView {
    let field_errors = match error.details {
        Some(ErrorDetails::Validation(details)) => Some(
            details
                .violations
                .into_iter()
                .map(|violation| {
                    (
                        validation_field(violation.field).to_owned(),
                        validation_reason(violation.reason).to_owned(),
                    )
                })
                .collect(),
        ),
        _ => None,
    };
    PublicErrorView {
        code: error_code(error.code).to_owned(),
        category: error_category(error.category),
        summary: error.summary,
        retryable: error.retryable,
        correlation_id: Some(error.correlation_id.to_string()),
        field_errors,
    }
}

fn validation_field(field: ValidationField) -> &'static str {
    match field {
        ValidationField::Title => "title",
        ValidationField::SuccessStatement => "successStatement",
        ValidationField::Deadline => "deadline",
        ValidationField::ExpectedRevision => "expectedRevision",
        ValidationField::GoalId => "goalId",
        ValidationField::FocusSessionId => "focusSessionId",
        ValidationField::InterventionId => "interventionId",
        ValidationField::PermissionGrantId => "permissionGrantId",
        ValidationField::ModelRouteApprovalId => "modelRouteApprovalId",
        ValidationField::SelectedResourceId => "selectedResourceId",
        ValidationField::Scope => "scope",
        ValidationField::Purpose => "purpose",
        ValidationField::ExpiresAt => "expiresAt",
        ValidationField::Continuity => "continuity",
        ValidationField::ConsentCopyVersion => "consentCopyVersion",
        ValidationField::Provider => "provider",
        ValidationField::Route => "route",
        ValidationField::Placement => "placement",
        ValidationField::DataCategories => "allowedDataCategories",
        ValidationField::HandlingProfile => "handlingProfile",
        ValidationField::Feedback => "feedback",
        ValidationField::DelayMs => "delayMs",
        ValidationField::Text => "text",
        ValidationField::SchemaVersion => "schemaVersion",
    }
}

fn validation_reason(reason: ValidationReason) -> &'static str {
    match reason {
        ValidationReason::Required => "This field is required.",
        ValidationReason::TooLong => "This value is too long.",
        ValidationReason::OutOfRange => "This value is outside the allowed range.",
        ValidationReason::InvalidFormat => "This value has an invalid format.",
        ValidationReason::Unsupported => "This value is not supported.",
    }
}

fn error_category(category: ProtocolErrorCategory) -> ErrorCategory {
    match category {
        ProtocolErrorCategory::InvalidArgument => ErrorCategory::InvalidArgument,
        ProtocolErrorCategory::Unauthenticated => ErrorCategory::Unauthenticated,
        ProtocolErrorCategory::PermissionDenied => ErrorCategory::PermissionDenied,
        ProtocolErrorCategory::ConfirmationRequired => ErrorCategory::ConfirmationRequired,
        ProtocolErrorCategory::NotFound => ErrorCategory::NotFound,
        ProtocolErrorCategory::Conflict => ErrorCategory::Conflict,
        ProtocolErrorCategory::IncompatibleVersion => ErrorCategory::IncompatibleVersion,
        ProtocolErrorCategory::Unavailable => ErrorCategory::Unavailable,
        ProtocolErrorCategory::DeadlineExceeded => ErrorCategory::DeadlineExceeded,
        ProtocolErrorCategory::Cancelled => ErrorCategory::Cancelled,
        ProtocolErrorCategory::Internal => ErrorCategory::Internal,
    }
}

fn error_code(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidArgument => "invalid_argument",
        ErrorCode::Unauthenticated => "unauthenticated",
        ErrorCode::PermissionDenied => "permission_denied",
        ErrorCode::ConfirmationRequired => "confirmation_required",
        ErrorCode::NotFound => "not_found",
        ErrorCode::Conflict => "conflict",
        ErrorCode::IncompatibleProtocol => "incompatible_protocol",
        ErrorCode::UnsupportedSchema => "unsupported_schema",
        ErrorCode::CapabilityUnavailable => "capability_unavailable",
        ErrorCode::DeadlineExceeded => "deadline_exceeded",
        ErrorCode::Cancelled => "cancelled",
        ErrorCode::RateLimited => "rate_limited",
        ErrorCode::Internal => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DESKTOP_PROTOCOL_SUPPORT, ErrorCategory, NativeCredentialPromptError,
        native_credential_error,
    };

    #[test]
    fn desktop_negotiates_exact_protocol_v1_2() {
        assert_eq!(
            DESKTOP_PROTOCOL_SUPPORT,
            stein_protocol::ProtocolSupport::V1_2
        );
    }

    #[test]
    fn native_prompt_cancellation_stays_a_typed_public_cancellation() {
        let error = native_credential_error(NativeCredentialPromptError::Cancelled);

        assert_eq!(error.code, "credential_prompt_cancelled");
        assert_eq!(error.category, ErrorCategory::Cancelled);
        assert!(error.retryable);
        assert!(error.field_errors.is_none());
    }
}
