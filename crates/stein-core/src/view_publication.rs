use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, RwLock};

use time::OffsetDateTime;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    ActorId, CapabilityHealth, DeliveryChannelStatus, EffectivePolicy, ExplicitPreferences,
    FocusSession, Goal, GoalDeletionTombstone, Intervention, InterventionId, ModelRouteApproval,
    ObservationSourceStatus, PermissionGrant, ResourceBinding, RuntimeHealth, RuntimeStatus,
    SelectedResourceDeletionTombstone,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoalViewChange {
    Created,
    Updated,
    Completed,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FocusSessionViewChange {
    Requested,
    Started,
    Muted,
    Unmuted,
    RecoveryStarted,
    Recovered,
    Stopping,
    Ended,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionViewChange {
    Granted,
    Updated,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterventionHistoryViewChange {
    Added,
    Updated,
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedResourceViewChange {
    Registered,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PermissionRecord {
    SessionGrant(PermissionGrant),
    ModelRouteApproval(ModelRouteApproval),
}

impl PermissionRecord {
    fn owner(&self) -> ActorId {
        match self {
            Self::SessionGrant(value) => value.owner,
            Self::ModelRouteApproval(value) => value.owner,
        }
    }
}

/// The complete privacy-filtered input required to construct one capture view.
/// It deliberately contains no normalized observation payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureViewProjection {
    pub session: FocusSession,
    pub grants: Vec<PermissionGrant>,
    pub source_statuses: Vec<ObservationSourceStatus>,
    pub native_status_available: bool,
    pub emergency_control_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreEvent {
    GoalViewChanged {
        change: GoalViewChange,
        goal: Goal,
    },
    RuntimeStatusChanged {
        runtime: RuntimeStatus,
    },
    FocusSessionViewChanged {
        change: FocusSessionViewChange,
        focus_session: FocusSession,
    },
    CaptureStateChanged {
        capture: CaptureViewProjection,
    },
    CapabilityHealthChanged {
        capability: CapabilityHealth,
    },
    DeliveryChannelViewChanged {
        owner: ActorId,
        channel: DeliveryChannelStatus,
    },
    PermissionViewChanged {
        change: PermissionViewChange,
        permission: PermissionRecord,
    },
    InterventionAvailable {
        intervention: Intervention,
    },
    InterventionViewChanged {
        intervention: Intervention,
    },
    InterventionHistoryChanged {
        change: InterventionHistoryViewChange,
        owner: ActorId,
        intervention_id: InterventionId,
        entry: Option<Intervention>,
    },
    GoalDeleted {
        tombstone: GoalDeletionTombstone,
    },
    SelectedResourceViewChanged {
        change: SelectedResourceViewChange,
        owner: ActorId,
        resource: Option<ResourceBinding>,
        tombstone: Option<SelectedResourceDeletionTombstone>,
    },
    UserPreferencesViewChanged {
        preferences: ExplicitPreferences,
        effective_policy: EffectivePolicy,
    },
}

impl CoreEvent {
    pub(crate) fn owner(&self) -> Option<ActorId> {
        match self {
            Self::GoalViewChanged { goal, .. } => Some(goal.owner),
            Self::RuntimeStatusChanged { .. } | Self::CapabilityHealthChanged { .. } => None,
            Self::FocusSessionViewChanged { focus_session, .. } => Some(focus_session.owner),
            Self::CaptureStateChanged { capture } => Some(capture.session.owner),
            Self::DeliveryChannelViewChanged { owner, .. }
            | Self::InterventionHistoryChanged { owner, .. } => Some(*owner),
            Self::PermissionViewChanged { permission, .. } => Some(permission.owner()),
            Self::InterventionAvailable { intervention }
            | Self::InterventionViewChanged { intervention } => Some(intervention.owner),
            Self::GoalDeleted { tombstone } => Some(tombstone.owner),
            Self::SelectedResourceViewChanged { owner, .. } => Some(*owner),
            Self::UserPreferencesViewChanged { preferences, .. } => Some(preferences.owner),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreEventActorKind {
    LocalOsUser,
    CoreDaemon,
    System,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreEventEnvelope {
    pub event_id: Uuid,
    pub cursor: u64,
    pub occurred_at: OffsetDateTime,
    pub actor: ActorId,
    pub actor_kind: CoreEventActorKind,
    pub correlation_id: Uuid,
    pub causation_id: Option<Uuid>,
    pub event: CoreEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventContext {
    pub actor: ActorId,
    pub actor_kind: CoreEventActorKind,
    pub correlation_id: Uuid,
    pub causation_id: Option<Uuid>,
}

impl EventContext {
    pub(crate) fn direct(actor: ActorId) -> Self {
        Self {
            actor,
            actor_kind: CoreEventActorKind::LocalOsUser,
            correlation_id: Uuid::now_v7(),
            causation_id: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PublicationState {
    pub event_cursor: u64,
    pub runtime_health: RuntimeHealth,
    pub capability_overrides: BTreeMap<&'static str, CapabilityHealth>,
}

#[derive(Clone)]
pub(crate) struct ViewPublication {
    inner: Arc<RwLock<PublicationState>>,
    events: broadcast::Sender<CoreEventEnvelope>,
    daemon_actor: ActorId,
    deferred_gate: Arc<(Mutex<bool>, Condvar)>,
}

/// Reserves the snapshot/event publication boundary while an asynchronous
/// durable transaction is in flight. Snapshot capture and ordinary commits
/// wait at the gate, but the asynchronous task never holds a synchronous lock
/// across `.await`.
pub(crate) struct DeferredPublication {
    inner: Arc<RwLock<PublicationState>>,
    events: broadcast::Sender<CoreEventEnvelope>,
    context: EventContext,
    gate: Arc<(Mutex<bool>, Condvar)>,
    released: bool,
}

impl ViewPublication {
    pub(crate) fn new(capacity: usize, daemon_instance_id: Uuid) -> Self {
        let (events, _) = broadcast::channel(capacity);
        Self {
            inner: Arc::new(RwLock::new(PublicationState {
                event_cursor: 0,
                runtime_health: RuntimeHealth::Healthy,
                capability_overrides: BTreeMap::new(),
            })),
            events,
            daemon_actor: ActorId::from_uuid(daemon_instance_id),
            deferred_gate: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    fn enter_gate(&self) -> MutexGuard<'_, bool> {
        let (gate, wake) = &*self.deferred_gate;
        let pending = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        wake.wait_while(pending, |pending| *pending)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn begin_deferred(&self, context: EventContext) -> DeferredPublication {
        let mut pending = self.enter_gate();
        // Acquire the state boundary while still owning the gate so a capture
        // that just passed the gate cannot race the reservation.
        let boundary = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *pending = true;
        drop(boundary);
        drop(pending);
        DeferredPublication {
            inner: self.inner.clone(),
            events: self.events.clone(),
            context,
            gate: self.deferred_gate.clone(),
            released: false,
        }
    }

    pub(crate) fn daemon_context(
        &self,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
    ) -> EventContext {
        EventContext {
            actor: self.daemon_actor,
            actor_kind: CoreEventActorKind::CoreDaemon,
            correlation_id,
            causation_id,
        }
    }

    pub(crate) fn fresh_daemon_context(&self) -> EventContext {
        self.daemon_context(Uuid::now_v7(), None)
    }

    pub(crate) fn commit<T, E>(
        &self,
        context: EventContext,
        operation: impl FnOnce(&mut PublicationState, &mut Vec<CoreEvent>) -> Result<T, E>,
    ) -> Result<T, E> {
        let gate = self.enter_gate();
        let mut state = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(gate);
        let mut pending = Vec::new();
        let result = operation(&mut state, &mut pending)?;
        publish_pending(&mut state, &self.events, context, pending);
        Ok(result)
    }

    pub(crate) fn commit_infallible<T>(
        &self,
        context: EventContext,
        operation: impl FnOnce(&mut PublicationState, &mut Vec<CoreEvent>) -> T,
    ) -> T {
        match self.commit(context, |state, events| {
            Ok::<T, std::convert::Infallible>(operation(state, events))
        }) {
            Ok(value) => value,
            Err(never) => match never {},
        }
    }

    pub(crate) fn capture<T, E>(
        &self,
        operation: impl FnOnce(
            &PublicationState,
            broadcast::Receiver<CoreEventEnvelope>,
        ) -> Result<T, E>,
    ) -> Result<T, E> {
        let gate = self.enter_gate();
        let state = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(gate);
        let receiver = self.events.subscribe();
        operation(&state, receiver)
    }

    pub(crate) fn read<T>(&self, operation: impl FnOnce(&PublicationState) -> T) -> T {
        let gate = self.enter_gate();
        let state = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(gate);
        operation(&state)
    }
}

impl DeferredPublication {
    pub(crate) fn publish(mut self, pending: Vec<CoreEvent>) {
        {
            let mut state = self
                .inner
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            publish_pending(&mut state, &self.events, self.context, pending);
        }
        self.release();
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        let (gate, wake) = &*self.gate;
        let mut pending = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *pending = false;
        self.released = true;
        wake.notify_all();
    }
}

impl Drop for DeferredPublication {
    fn drop(&mut self) {
        self.release();
    }
}

fn publish_pending(
    state: &mut PublicationState,
    events: &broadcast::Sender<CoreEventEnvelope>,
    context: EventContext,
    pending: Vec<CoreEvent>,
) {
    for event in pending {
        if let CoreEvent::CapabilityHealthChanged { capability } = &event {
            state
                .capability_overrides
                .insert(capability.id, capability.clone());
        }
        state.event_cursor = state
            .event_cursor
            .checked_add(1)
            .expect("event cursor space exhausted");
        let _ = events.send(CoreEventEnvelope {
            event_id: Uuid::now_v7(),
            cursor: state.event_cursor,
            occurred_at: OffsetDateTime::now_utc(),
            actor: context.actor,
            actor_kind: context.actor_kind,
            correlation_id: context.correlation_id,
            causation_id: context.causation_id,
            event,
        });
    }
}

pub(crate) type PublicationBinding = Arc<OnceLock<ViewPublication>>;
