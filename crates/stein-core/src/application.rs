use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::view_publication::{
    CoreEvent, CoreEventEnvelope, EventContext, PublicationState, ViewPublication,
};
use crate::{
    ApplicationError, ConfigError, ConfigProvider, CoreConfig, CreateGoal, EmergencyControlPort,
    ErrorCode, Goal, GoalId, GoalViewChange, IdempotencyKey, NativeStatusPort, NotificationPort,
    PlatformPortAvailability, SecretStore, UnavailableEmergencyControlPort,
    UnavailableNativeStatusPort, UnavailableNotificationPort, UpdateGoal,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeHealth {
    #[default]
    Healthy,
    Degraded,
    Stopping,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStatus {
    pub daemon_instance_id: Uuid,
    pub build_id: String,
    pub started_at: OffsetDateTime,
    pub health: RuntimeHealth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityState {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityHealth {
    pub id: &'static str,
    pub state: CapabilityState,
    pub detail: &'static str,
}

/// Composition-owned health for capabilities whose implementation cannot be
/// inferred from a trait object (notably durable versus in-memory storage and
/// the aggregate observation surface). The daemon supplies these facts when it
/// wires production adapters; legacy builders remain fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCapabilityInputs {
    pub durable_persistence: PlatformPortAvailability,
    pub desktop_observation: PlatformPortAvailability,
    pub model_reasoning: PlatformPortAvailability,
}

impl Default for RuntimeCapabilityInputs {
    fn default() -> Self {
        Self {
            durable_persistence: PlatformPortAvailability::Unavailable {
                reason: "No durable repository is configured.",
            },
            desktop_observation: PlatformPortAvailability::Unavailable {
                reason: "No desktop observation adapter is configured.",
            },
            model_reasoning: PlatformPortAvailability::Unavailable {
                reason: "No model reasoning adapter is configured.",
            },
        }
    }
}

const fn capability_state(availability: PlatformPortAvailability) -> CapabilityState {
    if availability.is_available() {
        CapabilityState::Available
    } else {
        CapabilityState::Unavailable
    }
}

fn capability_from_availability(
    id: &'static str,
    availability: PlatformPortAvailability,
) -> CapabilityHealth {
    CapabilityHealth {
        id,
        state: capability_state(availability),
        detail: availability.detail(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientSnapshot {
    pub runtime: RuntimeStatus,
    pub capabilities: Vec<CapabilityHealth>,
    pub goals: Vec<Goal>,
    pub event_cursor: u64,
}

pub struct Subscription {
    pub snapshot: ClientSnapshot,
    actor: crate::ActorId,
    receiver: broadcast::Receiver<CoreEventEnvelope>,
}

impl Subscription {
    pub async fn receive(&mut self) -> Result<CoreEventEnvelope, EventStreamError> {
        loop {
            match self.receiver.recv().await {
                Ok(event)
                    if event.cursor > self.snapshot.event_cursor
                        && event_visible_to(&event.event, self.actor) =>
                {
                    return Ok(event);
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    return Err(EventStreamError::Gap { missed });
                }
                Err(broadcast::error::RecvError::Closed) => return Err(EventStreamError::Closed),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventStreamError {
    Gap { missed: u64 },
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayEcho {
    pub value: String,
    pub delay: Duration,
    pub deadline: Option<tokio::time::Instant>,
}

#[derive(Clone)]
pub struct CoreApplication {
    config: CoreConfig,
    runtime: RuntimeStatus,
    capabilities: Vec<CapabilityHealth>,
    second_mind: crate::SecondMindRuntime,
    publication: ViewPublication,
    shutdown: CancellationToken,
}

/// Preferred name for a cloneable application handle owned by daemon adapters.
pub type CoreRuntime = CoreApplication;

impl CoreApplication {
    pub fn build(
        build_id: impl Into<String>,
        config_provider: &dyn ConfigProvider,
        secret_store: &dyn SecretStore,
    ) -> Result<Self, ConfigError> {
        Self::build_with_platform_ports(
            build_id,
            config_provider,
            secret_store,
            &UnavailableNotificationPort,
            &UnavailableNativeStatusPort,
            &UnavailableEmergencyControlPort,
        )
    }

    pub fn build_with_platform_ports(
        build_id: impl Into<String>,
        config_provider: &dyn ConfigProvider,
        secret_store: &dyn SecretStore,
        notification_port: &dyn NotificationPort,
        native_status_port: &dyn NativeStatusPort,
        emergency_control_port: &dyn EmergencyControlPort,
    ) -> Result<Self, ConfigError> {
        Self::build_with_second_mind(
            build_id,
            config_provider,
            secret_store,
            notification_port,
            native_status_port,
            emergency_control_port,
            crate::SecondMindRuntime::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_with_second_mind(
        build_id: impl Into<String>,
        config_provider: &dyn ConfigProvider,
        secret_store: &dyn SecretStore,
        notification_port: &dyn NotificationPort,
        native_status_port: &dyn NativeStatusPort,
        emergency_control_port: &dyn EmergencyControlPort,
        second_mind: crate::SecondMindRuntime,
    ) -> Result<Self, ConfigError> {
        Self::build_with_second_mind_capabilities(
            build_id,
            config_provider,
            secret_store,
            notification_port,
            native_status_port,
            emergency_control_port,
            second_mind,
            RuntimeCapabilityInputs::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_with_second_mind_capabilities(
        build_id: impl Into<String>,
        config_provider: &dyn ConfigProvider,
        secret_store: &dyn SecretStore,
        notification_port: &dyn NotificationPort,
        native_status_port: &dyn NativeStatusPort,
        emergency_control_port: &dyn EmergencyControlPort,
        second_mind: crate::SecondMindRuntime,
        capability_inputs: RuntimeCapabilityInputs,
    ) -> Result<Self, ConfigError> {
        let config = config_provider.load()?;
        if config.event_buffer_capacity == 0 {
            return Err(ConfigError {
                summary: "Event buffer capacity must be greater than zero.",
            });
        }
        if config.maximum_goal_count == 0 {
            return Err(ConfigError {
                summary: "Maximum goal count must be greater than zero.",
            });
        }

        let runtime = RuntimeStatus {
            daemon_instance_id: Uuid::now_v7(),
            build_id: build_id.into(),
            started_at: OffsetDateTime::now_utc(),
            health: RuntimeHealth::Healthy,
        };
        let publication =
            ViewPublication::new(config.event_buffer_capacity, runtime.daemon_instance_id);
        second_mind
            .attach_publication(publication.clone())
            .map_err(|_| ConfigError {
                summary: "The second-mind runtime is already attached to an application.",
            })?;
        let secret_state = if secret_store.is_available() {
            CapabilityState::Available
        } else {
            CapabilityState::Unavailable
        };
        let notification = notification_port.availability();
        let native_status = native_status_port.availability();
        let emergency_control = emergency_control_port.availability();

        Ok(Self {
            config,
            runtime,
            capabilities: vec![
                CapabilityHealth {
                    id: "core.goals",
                    state: CapabilityState::Available,
                    detail: "Typed goal commands and authoritative goal views are available.",
                },
                CapabilityHealth {
                    id: "core.delay_echo",
                    state: CapabilityState::Available,
                    detail: "Cancellable synthetic delay operation.",
                },
                capability_from_availability(
                    "core.persistence",
                    capability_inputs.durable_persistence,
                ),
                CapabilityHealth {
                    id: "platform.secret_store",
                    state: secret_state,
                    detail: if secret_store.is_available() {
                        "A platform secret store is configured."
                    } else {
                        "No platform secret store is configured."
                    },
                },
                CapabilityHealth {
                    id: "platform.native_notification",
                    state: if notification.is_available() {
                        CapabilityState::Available
                    } else {
                        CapabilityState::Unavailable
                    },
                    detail: notification.detail(),
                },
                CapabilityHealth {
                    id: "platform.native_status",
                    state: if native_status.is_available() {
                        CapabilityState::Available
                    } else {
                        CapabilityState::Unavailable
                    },
                    detail: native_status.detail(),
                },
                CapabilityHealth {
                    id: "platform.emergency_control",
                    state: if emergency_control.is_available() {
                        CapabilityState::Available
                    } else {
                        CapabilityState::Unavailable
                    },
                    detail: emergency_control.detail(),
                },
                CapabilityHealth {
                    id: "observation.desktop",
                    state: capability_state(capability_inputs.desktop_observation),
                    detail: capability_inputs.desktop_observation.detail(),
                },
                CapabilityHealth {
                    id: "model.reasoning",
                    state: capability_state(capability_inputs.model_reasoning),
                    detail: capability_inputs.model_reasoning.detail(),
                },
            ],
            second_mind,
            publication,
            shutdown: CancellationToken::new(),
        })
    }

    pub fn runtime_status(&self) -> RuntimeStatus {
        self.publication
            .read(|state| self.runtime_status_locked(state))
    }

    pub fn capability_health(&self) -> Vec<CapabilityHealth> {
        self.publication
            .read(|state| self.capability_health_locked(state))
    }

    pub fn second_mind(&self) -> &crate::SecondMindRuntime {
        &self.second_mind
    }

    pub fn create_goal(&self, command: CreateGoal) -> Result<Goal, ApplicationError> {
        let context = EventContext::direct(command.actor);
        self.create_goal_with_context(command, context)
    }

    pub(crate) fn create_goal_with_context(
        &self,
        command: CreateGoal,
        context: EventContext,
    ) -> Result<Goal, ApplicationError> {
        validate_actor(&command.actor)?;
        validate_idempotency_key(&command.idempotency_key)?;
        validate_goal_text("title", &command.title, 200)?;
        validate_goal_text("success_statement", &command.success_statement, 2_000)?;
        self.publication.commit(context, |_state, events| {
            let already_existed = self
                .second_mind
                .repository()
                .find_goal_create(command.actor, command.idempotency_key)
                .map_err(crate::SecondMindError::from)
                .map_err(second_mind_error_to_application)?
                .is_some();
            if !already_existed
                && self
                    .second_mind
                    .list_goals(command.actor)
                    .map_err(second_mind_error_to_application)?
                    .len()
                    >= self.config.maximum_goal_count
            {
                return Err(ApplicationError {
                    code: ErrorCode::Unavailable,
                    summary: "The goal capacity is exhausted.",
                    retryable: false,
                    field_violations: Vec::new(),
                    current_revision: None,
                });
            }
            let goal = self
                .second_mind
                .create_goal_unpublished(crate::ClientAssurance::PrivateCapabilityBound, command)
                .map_err(second_mind_error_to_application)?;
            if !already_existed {
                events.push(CoreEvent::GoalViewChanged {
                    change: GoalViewChange::Created,
                    goal: goal.clone(),
                });
            }
            Ok(goal)
        })
    }

    pub fn update_goal(&self, command: UpdateGoal) -> Result<Goal, ApplicationError> {
        validate_actor(&command.actor)?;
        let context = EventContext::direct(command.actor);
        if command.patch.is_empty() {
            return Err(ApplicationError::invalid(
                "patch",
                "must change at least one field",
            ));
        }
        if let Some(title) = &command.patch.title {
            validate_goal_text("title", title, 200)?;
        }
        if let Some(success) = &command.patch.success_statement {
            validate_goal_text("success_statement", success, 2_000)?;
        }

        self.publication.commit(context, |_state, events| {
            let updated = self
                .second_mind
                .update_goal_unpublished(crate::ClientAssurance::PrivateCapabilityBound, command)
                .map_err(second_mind_error_to_application)?;
            events.push(CoreEvent::GoalViewChanged {
                change: GoalViewChange::Updated,
                goal: updated.clone(),
            });
            Ok(updated)
        })
    }

    pub(crate) async fn set_goal_state_with_context(
        &self,
        owner: crate::ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        goal_state: crate::GoalState,
        context: EventContext,
    ) -> Result<Goal, ApplicationError> {
        self.second_mind
            .set_goal_state_with_context(
                crate::ClientAssurance::PrivateCapabilityBound,
                owner,
                goal_id,
                expected_revision,
                goal_state,
                context,
            )
            .await
            .map_err(second_mind_error_to_application)
    }

    pub fn get_goal(&self, actor: &crate::ActorId, id: GoalId) -> Result<Goal, ApplicationError> {
        validate_actor(actor)?;
        self.second_mind
            .get_goal(*actor, id)
            .map_err(second_mind_error_to_application)
    }

    pub fn open_subscription(
        &self,
        actor: &crate::ActorId,
    ) -> Result<Subscription, ApplicationError> {
        self.open_subscription_with(actor, |_snapshot, _owner_state| Ok(()))
            .map(|(subscription, ())| subscription)
    }

    pub(crate) fn open_subscription_with<T>(
        &self,
        actor: &crate::ActorId,
        project: impl FnOnce(&ClientSnapshot, crate::OwnerStateSnapshot) -> Result<T, ApplicationError>,
    ) -> Result<(Subscription, T), ApplicationError> {
        validate_actor(actor)?;

        // Receiver registration and every authoritative owner view are captured
        // under the same publication read boundary. Visible mutations commit and
        // publish under its write boundary, so the returned cursor cannot miss a
        // racing state transition.
        self.publication.capture(|state, receiver| {
            let mut owner_state = self
                .second_mind
                .owner_state_snapshot_unpublished(*actor)
                .map_err(second_mind_error_to_application)?;
            owner_state.goals.sort_by_key(|goal| goal.id);
            let snapshot = ClientSnapshot {
                runtime: self.runtime_status_locked(state),
                capabilities: self.capability_health_locked(state),
                goals: owner_state.goals.clone(),
                event_cursor: state.event_cursor,
            };
            let projected = project(&snapshot, owner_state)?;
            Ok((
                Subscription {
                    snapshot,
                    actor: *actor,
                    receiver,
                },
                projected,
            ))
        })
    }

    fn capability_health_locked(&self, state: &PublicationState) -> Vec<CapabilityHealth> {
        let mut capabilities = self.capabilities.clone();
        for capability in state.capability_overrides.values() {
            if let Some(current) = capabilities
                .iter_mut()
                .find(|current| current.id == capability.id)
            {
                *current = capability.clone();
            } else {
                capabilities.push(capability.clone());
            }
        }
        capabilities
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Starts application shutdown exactly once and returns current runtime state.
    pub fn request_shutdown(&self) -> RuntimeStatus {
        let context = self.publication.fresh_daemon_context();
        self.publication
            .commit_infallible(context, |state, events| {
                if state.runtime_health != RuntimeHealth::Stopping {
                    state.runtime_health = RuntimeHealth::Stopping;
                    self.shutdown.cancel();
                    let runtime = self.runtime_status_locked(state);
                    events.push(CoreEvent::RuntimeStatusChanged {
                        runtime: runtime.clone(),
                    });
                    runtime
                } else {
                    self.runtime_status_locked(state)
                }
            })
    }

    pub async fn delay_echo(
        &self,
        request: DelayEcho,
        cancellation: CancellationToken,
    ) -> Result<String, ApplicationError> {
        if request.delay > self.config.maximum_delay_echo {
            return Err(ApplicationError::invalid(
                "delay_ms",
                "exceeds the configured maximum",
            ));
        }

        let sleep = tokio::time::sleep(request.delay);
        tokio::pin!(sleep);
        match request.deadline {
            Some(deadline) => {
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => Err(ApplicationError::cancelled()),
                    _ = cancellation.cancelled() => Err(ApplicationError::cancelled()),
                    _ = tokio::time::sleep_until(deadline) => Err(ApplicationError::deadline_exceeded()),
                    _ = &mut sleep => Ok(request.value),
                }
            }
            None => {
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => Err(ApplicationError::cancelled()),
                    _ = cancellation.cancelled() => Err(ApplicationError::cancelled()),
                    _ = &mut sleep => Ok(request.value),
                }
            }
        }
    }

    fn runtime_status_locked(&self, state: &PublicationState) -> RuntimeStatus {
        RuntimeStatus {
            health: state.runtime_health,
            ..self.runtime.clone()
        }
    }
}

pub(crate) fn second_mind_error_to_application(error: crate::SecondMindError) -> ApplicationError {
    let code = match error.code {
        crate::SecondMindErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        crate::SecondMindErrorCode::Unauthenticated
        | crate::SecondMindErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        crate::SecondMindErrorCode::NotFound => ErrorCode::NotFound,
        crate::SecondMindErrorCode::Conflict => ErrorCode::Conflict,
        crate::SecondMindErrorCode::Unavailable => ErrorCode::Unavailable,
        crate::SecondMindErrorCode::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        crate::SecondMindErrorCode::Cancelled => ErrorCode::Cancelled,
        crate::SecondMindErrorCode::Internal => ErrorCode::Internal,
    };
    ApplicationError {
        code,
        summary: error.summary,
        retryable: error.retryable,
        field_violations: Vec::new(),
        current_revision: error.current_revision.and_then(crate::Revision::new),
    }
}

fn validate_actor(actor: &crate::ActorId) -> Result<(), ApplicationError> {
    if actor.as_uuid().is_nil() {
        return Err(ApplicationError::invalid(
            "actor",
            "must not be the nil identifier",
        ));
    }
    Ok(())
}

fn validate_idempotency_key(key: &IdempotencyKey) -> Result<(), ApplicationError> {
    if key.as_uuid().is_nil() {
        return Err(ApplicationError::invalid(
            "idempotency_key",
            "must not be the nil identifier",
        ));
    }
    Ok(())
}

fn event_visible_to(event: &CoreEvent, actor: crate::ActorId) -> bool {
    event.owner().is_none_or(|owner| owner == actor)
}

fn validate_goal_text(
    field: &'static str,
    value: &str,
    maximum_chars: usize,
) -> Result<(), ApplicationError> {
    let length = value.chars().count();
    if value.trim().is_empty() {
        return Err(ApplicationError::invalid(field, "must not be blank"));
    }
    if length > maximum_chars {
        return Err(ApplicationError::invalid(
            field,
            "exceeds the maximum character count",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tokio::time::timeout;

    use super::*;
    use crate::{GoalPatch, Revision, StaticConfigProvider, UnavailableSecretStore};

    fn app() -> Arc<CoreApplication> {
        Arc::new(
            CoreApplication::build(
                "test-build",
                &StaticConfigProvider::default(),
                &UnavailableSecretStore::default(),
            )
            .unwrap(),
        )
    }

    fn actor() -> crate::ActorId {
        crate::ActorId::from_uuid(Uuid::from_u128(0x018f_0000_0000_7000_8000_0000_0000_0001))
    }

    fn create(key: IdempotencyKey, title: &str) -> CreateGoal {
        CreateGoal {
            actor: actor(),
            idempotency_key: key,
            title: title.to_owned(),
            success_statement: "A synthetic proof is visible.".to_owned(),
            deadline: None,
        }
    }

    #[test]
    fn generated_ids_are_uuid_v7_and_revisions_start_at_one() {
        let goal = app()
            .create_goal(create(IdempotencyKey::new_v7(), "Synthetic goal"))
            .unwrap();
        assert_eq!(goal.id.as_uuid().get_version_num(), 7);
        assert_eq!(goal.revision, Revision::INITIAL);
    }

    #[tokio::test]
    async fn duplicate_create_returns_original_result_without_an_event() {
        let app = app();
        let mut subscription = app.open_subscription(&actor()).unwrap();
        let key = IdempotencyKey::new_v7();
        let first = app.create_goal(create(key, "Synthetic goal")).unwrap();
        let event = timeout(Duration::from_secs(1), subscription.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.cursor, 1);

        let duplicate = app.create_goal(create(key, "Synthetic goal")).unwrap();
        assert_eq!(duplicate, first);
        assert!(
            timeout(Duration::from_millis(20), subscription.receive())
                .await
                .is_err()
        );
        assert_eq!(
            app.open_subscription(&actor())
                .unwrap()
                .snapshot
                .event_cursor,
            1
        );
    }

    #[test]
    fn reusing_idempotency_key_for_different_input_is_a_safe_conflict() {
        let app = app();
        let key = IdempotencyKey::new_v7();
        app.create_goal(create(key, "First title")).unwrap();
        let error = app
            .create_goal(create(key, "Different private text"))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(!error.summary.contains("Different private text"));
        assert_eq!(
            app.open_subscription(&actor())
                .unwrap()
                .snapshot
                .goals
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn update_requires_expected_revision_and_preserves_winning_state() {
        let app = app();
        let goal = app
            .create_goal(create(IdempotencyKey::new_v7(), "Original"))
            .unwrap();
        let winner = app
            .update_goal(UpdateGoal {
                actor: actor(),
                id: goal.id,
                expected_revision: Revision::INITIAL,
                patch: GoalPatch {
                    title: Some("Winner".to_owned()),
                    ..GoalPatch::default()
                },
            })
            .unwrap();
        assert_eq!(winner.revision.get(), 2);

        let error = app
            .update_goal(UpdateGoal {
                actor: actor(),
                id: goal.id,
                expected_revision: Revision::INITIAL,
                patch: GoalPatch {
                    title: Some("Loser private text".to_owned()),
                    ..GoalPatch::default()
                },
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(error.current_revision, Some(winner.revision));
        assert!(!error.summary.contains("Loser private text"));
        assert_eq!(app.get_goal(&actor(), goal.id).unwrap().title, "Winner");
    }

    #[test]
    fn another_actor_cannot_discover_read_or_update_a_goal() {
        let app = app();
        let goal = app
            .create_goal(create(IdempotencyKey::new_v7(), "Synthetic goal"))
            .unwrap();
        let other = crate::ActorId::new_v7();
        assert_eq!(
            app.get_goal(&other, goal.id).unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            app.update_goal(UpdateGoal {
                actor: other,
                id: goal.id,
                expected_revision: goal.revision,
                patch: GoalPatch {
                    title: Some("Unauthorized".to_owned()),
                    ..GoalPatch::default()
                },
            })
            .unwrap_err()
            .code,
            ErrorCode::NotFound
        );
    }

    #[tokio::test]
    async fn snapshot_and_cursor_cover_before_and_after_connection() {
        let app = app();
        let first = app
            .create_goal(create(IdempotencyKey::new_v7(), "Before"))
            .unwrap();
        let mut subscription = app.open_subscription(&actor()).unwrap();
        assert_eq!(subscription.snapshot.event_cursor, 1);
        assert_eq!(subscription.snapshot.goals, vec![first]);

        let second = app
            .create_goal(create(IdempotencyKey::new_v7(), "After"))
            .unwrap();
        let event = timeout(Duration::from_secs(1), subscription.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.cursor, 2);
        assert_eq!(
            event.event,
            CoreEvent::GoalViewChanged {
                change: GoalViewChange::Created,
                goal: second,
            }
        );
    }

    #[tokio::test]
    async fn concurrent_connect_never_loses_the_racing_mutation() {
        for iteration in 0..64 {
            let app = app();
            let barrier = Arc::new(Barrier::new(2));
            let writer_app = Arc::clone(&app);
            let writer_barrier = Arc::clone(&barrier);
            let writer = thread::spawn(move || {
                writer_barrier.wait();
                let _ = iteration;
                writer_app
                    .create_goal(create(IdempotencyKey::new_v7(), "Racing goal"))
                    .unwrap()
            });

            barrier.wait();
            let mut subscription = app.open_subscription(&actor()).unwrap();
            let goal = writer.join().unwrap();
            if !subscription
                .snapshot
                .goals
                .iter()
                .any(|item| item.id == goal.id)
            {
                let event = timeout(Duration::from_secs(1), subscription.receive())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    event.event,
                    CoreEvent::GoalViewChanged {
                        change: GoalViewChange::Created,
                        goal,
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn delay_echo_is_cancelled_promptly() {
        let app = app();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = app
            .delay_echo(
                DelayEcho {
                    value: "synthetic".to_owned(),
                    delay: Duration::from_secs(10),
                    deadline: None,
                },
                cancellation,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn delay_echo_honors_deadline() {
        let app = app();
        let error = app
            .delay_echo(
                DelayEcho {
                    value: "synthetic".to_owned(),
                    delay: Duration::from_secs(10),
                    deadline: Some(tokio::time::Instant::now()),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
    }

    #[test]
    fn health_is_truthful_about_fake_phase_two_capabilities() {
        let app = app();
        assert_eq!(app.runtime_status().health, RuntimeHealth::Healthy);
        let capabilities = app.capability_health();
        assert!(capabilities.iter().any(|capability| {
            capability.id == "platform.secret_store"
                && capability.state == CapabilityState::Unavailable
        }));
        for id in [
            "platform.native_notification",
            "platform.native_status",
            "platform.emergency_control",
        ] {
            assert!(capabilities.iter().any(|capability| {
                capability.id == id && capability.state == CapabilityState::Unavailable
            }));
        }
        assert!(capabilities.iter().any(|capability| {
            capability.id == "observation.desktop"
                && capability.state == CapabilityState::Unavailable
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.id == "model.reasoning" && capability.state == CapabilityState::Unavailable
        }));
    }

    #[test]
    fn production_composition_can_report_real_phase_two_capabilities() {
        let app = CoreApplication::build_with_second_mind_capabilities(
            "test-build",
            &StaticConfigProvider::default(),
            &UnavailableSecretStore::default(),
            &UnavailableNotificationPort,
            &UnavailableNativeStatusPort,
            &UnavailableEmergencyControlPort,
            crate::SecondMindRuntime::default(),
            RuntimeCapabilityInputs {
                durable_persistence: PlatformPortAvailability::Available,
                desktop_observation: PlatformPortAvailability::Available,
                model_reasoning: PlatformPortAvailability::Available,
            },
        )
        .unwrap();
        for id in ["core.persistence", "observation.desktop", "model.reasoning"] {
            assert!(app.capability_health().iter().any(|capability| {
                capability.id == id && capability.state == CapabilityState::Available
            }));
        }
        assert!(app.capability_health().iter().any(|capability| {
            capability.id == "core.goals"
                && capability.detail
                    == "Typed goal commands and authoritative goal views are available."
        }));
    }

    #[test]
    fn unavailable_secret_store_never_returns_a_value() {
        let store = UnavailableSecretStore::default();
        assert!(!store.is_available());
        let error = match store.read(&crate::SecretKey::new("synthetic-key")) {
            Ok(_) => panic!("unavailable store unexpectedly returned success"),
            Err(error) => error,
        };
        assert_eq!(error.kind, crate::SecretStoreErrorKind::Unavailable);
        assert!(!format!("{store:?}").contains("synthetic-key"));
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_cancels_long_running_work() {
        let app = app();
        let mut subscription = app.open_subscription(&actor()).unwrap();
        let first = app.request_shutdown();
        let second = app.request_shutdown();
        assert_eq!(first.health, RuntimeHealth::Stopping);
        assert_eq!(first, second);
        assert!(app.shutdown_token().is_cancelled());

        let event = timeout(Duration::from_secs(1), subscription.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event.event,
            CoreEvent::RuntimeStatusChanged { .. }
        ));
        assert!(
            timeout(Duration::from_millis(20), subscription.receive())
                .await
                .is_err()
        );

        let error = app
            .delay_echo(
                DelayEcho {
                    value: "synthetic".to_owned(),
                    delay: Duration::from_secs(10),
                    deadline: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
    }

    #[test]
    fn cloned_runtime_handles_share_canonical_state() {
        let first = app();
        let second = (*first).clone();
        let goal = first
            .create_goal(create(IdempotencyKey::new_v7(), "Shared state"))
            .unwrap();
        assert_eq!(second.get_goal(&actor(), goal.id).unwrap(), goal);
    }

    #[tokio::test]
    async fn lagged_subscription_reports_a_gap_instead_of_guessing() {
        let app = CoreApplication::build(
            "test-build",
            &StaticConfigProvider::new(CoreConfig {
                event_buffer_capacity: 1,
                ..CoreConfig::default()
            }),
            &UnavailableSecretStore::default(),
        )
        .unwrap();
        let mut subscription = app.open_subscription(&actor()).unwrap();
        for _ in 0..3 {
            app.create_goal(create(IdempotencyKey::new_v7(), "Synthetic goal"))
                .unwrap();
        }
        assert!(matches!(
            subscription.receive().await,
            Err(EventStreamError::Gap { missed }) if missed >= 1
        ));
    }

    #[tokio::test]
    async fn subscriptions_do_not_publish_another_actors_goal_content() {
        let app = app();
        let other = crate::ActorId::new_v7();
        let mut subscription = app.open_subscription(&other).unwrap();
        app.create_goal(create(IdempotencyKey::new_v7(), "Private marker"))
            .unwrap();
        app.request_shutdown();
        let event = timeout(Duration::from_secs(1), subscription.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event.event,
            CoreEvent::RuntimeStatusChanged { .. }
        ));
    }

    #[test]
    fn invalid_configuration_fails_before_runtime_start() {
        let error = CoreApplication::build(
            "test-build",
            &StaticConfigProvider::new(CoreConfig {
                event_buffer_capacity: 0,
                ..CoreConfig::default()
            }),
            &UnavailableSecretStore::default(),
        )
        .err()
        .expect("invalid configuration should fail");
        assert_eq!(
            error.summary,
            "Event buffer capacity must be greater than zero."
        );
    }
}
