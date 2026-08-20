use std::{
    collections::VecDeque,
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use stein_protocol::{ClientSnapshot, EventEnvelope, UtcTimestamp};
use tauri::{AppHandle, Emitter};
use tokio::sync::{Mutex, broadcast::error::RecvError};

use crate::{
    stein_adapter::SteinClientAdapter,
    view::{
        AbandonGoalInput, ApproveModelRouteInput, ConnectionView, CoreEventView, CreateGoalInput,
        DESKTOP_BRIDGE_SCHEMA_VERSION, DashboardSnapshot, DesktopBridgeEvent, EffectivePolicyView,
        EndFocusSessionInput, ExplainInterventionInput, FocusSessionView, GoalDeletionView,
        GoalRevisionInput, GoalView, GrantPermissionInput, InterventionExplanationView,
        InterventionFeedbackInput, InterventionHistoryInput, InterventionHistoryView,
        InterventionView, ModelRouteView, PublicErrorView, RegisterSelectedResourceInput,
        RemoveSelectedResourceInput, ResourceView, RevokePermissionInput, SecretMutationView,
        SelectedResourceDeletionView, SessionGrantView, SetMutedInput, StartFocusSessionInput,
        SteinIdentityView, StoreModelSecretInput, UpdateGoalInput, UpdateUserPreferencesInput,
        UserPreferencesUpdateView, UserPreferencesView,
    },
};

pub const DESKTOP_BRIDGE_EVENT: &str = "stein://desktop-bridge";
const RECENT_EVENT_LIMIT: usize = 30;
const HEALTH_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct CoreBridge {
    connect_gate: Arc<Mutex<()>>,
    inner: Arc<Mutex<BridgeState>>,
    generation: Arc<AtomicU64>,
}

struct BridgeState {
    client: Option<SteinClientAdapter>,
    snapshot: Option<ClientSnapshot>,
    connection: ConnectionView,
    recent_events: VecDeque<CoreEventView>,
    reconnect_attempt: u32,
}

impl Default for CoreBridge {
    fn default() -> Self {
        Self {
            connect_gate: Arc::new(Mutex::new(())),
            inner: Arc::new(Mutex::new(BridgeState {
                client: None,
                snapshot: None,
                connection: ConnectionView::connecting(UtcTimestamp::now().to_string(), 0),
                recent_events: VecDeque::with_capacity(RECENT_EVENT_LIMIT),
                reconnect_attempt: 0,
            })),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl CoreBridge {
    pub async fn bootstrap(&self, app: &AppHandle) -> Result<DashboardSnapshot, PublicErrorView> {
        if let Some(snapshot) = self.current_dashboard().await {
            return Ok(snapshot);
        }
        self.connect(app).await
    }

    pub async fn refresh(&self, app: &AppHandle) -> Result<DashboardSnapshot, PublicErrorView> {
        let client = self.connected_client().await?;
        match client.authoritative_snapshot().await {
            Ok(snapshot) => {
                let dashboard = self.store_snapshot(snapshot).await;
                emit_snapshot(app, dashboard.clone());
                Ok(dashboard)
            }
            Err(error) => {
                self.mark_disconnected(app, error.clone()).await;
                Err(error)
            }
        }
    }

    pub async fn reconnect(&self, app: &AppHandle) -> Result<DashboardSnapshot, PublicErrorView> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        {
            let mut inner = self.inner.lock().await;
            inner.client = None;
            inner.snapshot = None;
            inner.recent_events.clear();
        }
        self.connect(app).await
    }

    pub async fn create_goal(
        &self,
        app: &AppHandle,
        input: CreateGoalInput,
    ) -> Result<GoalView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.create_goal(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn update_goal(
        &self,
        app: &AppHandle,
        input: UpdateGoalInput,
    ) -> Result<GoalView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.update_goal(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn complete_goal(
        &self,
        app: &AppHandle,
        input: GoalRevisionInput,
    ) -> Result<GoalView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.complete_goal(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn abandon_goal(
        &self,
        app: &AppHandle,
        input: AbandonGoalInput,
    ) -> Result<GoalView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.abandon_goal(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn delete_goal(
        &self,
        app: &AppHandle,
        input: GoalRevisionInput,
    ) -> Result<GoalDeletionView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.delete_goal(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn store_model_secret(
        &self,
        input: StoreModelSecretInput,
        parent_window: isize,
    ) -> Result<SecretMutationView, PublicErrorView> {
        self.connected_client()
            .await?
            .store_model_secret(input, parent_window)
            .await
    }

    pub async fn approve_model_route(
        &self,
        app: &AppHandle,
        input: ApproveModelRouteInput,
    ) -> Result<ModelRouteView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.approve_model_route(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn grant_permission(
        &self,
        app: &AppHandle,
        input: GrantPermissionInput,
    ) -> Result<SessionGrantView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.grant_permission(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn revoke_permission(
        &self,
        app: &AppHandle,
        input: RevokePermissionInput,
    ) -> Result<(), PublicErrorView> {
        let client = self.connected_client().await?;
        client.revoke_permission(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(())
    }

    pub async fn start_focus_session(
        &self,
        app: &AppHandle,
        input: StartFocusSessionInput,
    ) -> Result<FocusSessionView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.start_focus_session(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn register_selected_resource(
        &self,
        app: &AppHandle,
        input: RegisterSelectedResourceInput,
    ) -> Result<ResourceView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.register_selected_resource(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn remove_selected_resource(
        &self,
        app: &AppHandle,
        input: RemoveSelectedResourceInput,
    ) -> Result<SelectedResourceDeletionView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.remove_selected_resource(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn update_user_preferences(
        &self,
        app: &AppHandle,
        input: UpdateUserPreferencesInput,
    ) -> Result<UserPreferencesUpdateView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.update_user_preferences(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn get_stein_identity(&self) -> Result<SteinIdentityView, PublicErrorView> {
        self.connected_client().await?.get_stein_identity().await
    }

    pub async fn get_user_preferences(&self) -> Result<UserPreferencesView, PublicErrorView> {
        self.connected_client().await?.get_user_preferences().await
    }

    pub async fn get_effective_policy(&self) -> Result<EffectivePolicyView, PublicErrorView> {
        self.connected_client().await?.get_effective_policy().await
    }

    pub async fn get_selected_resources(&self) -> Result<Vec<ResourceView>, PublicErrorView> {
        self.connected_client()
            .await?
            .get_selected_resources()
            .await
    }

    pub async fn set_muted(
        &self,
        app: &AppHandle,
        input: SetMutedInput,
    ) -> Result<FocusSessionView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.set_muted(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn end_focus_session(
        &self,
        app: &AppHandle,
        input: EndFocusSessionInput,
    ) -> Result<FocusSessionView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.end_focus_session(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn record_feedback(
        &self,
        app: &AppHandle,
        input: InterventionFeedbackInput,
    ) -> Result<InterventionView, PublicErrorView> {
        let client = self.connected_client().await?;
        let result = client.record_feedback(input).await?;
        self.publish_after_mutation(app, &client).await;
        Ok(result)
    }

    pub async fn explain_intervention(
        &self,
        input: ExplainInterventionInput,
    ) -> Result<InterventionExplanationView, PublicErrorView> {
        self.connected_client()
            .await?
            .explain_intervention(input)
            .await
    }

    pub async fn get_intervention_history(
        &self,
        input: InterventionHistoryInput,
    ) -> Result<InterventionHistoryView, PublicErrorView> {
        self.connected_client()
            .await?
            .get_intervention_history(input)
            .await
    }

    async fn connect(&self, app: &AppHandle) -> Result<DashboardSnapshot, PublicErrorView> {
        let _gate = self.connect_gate.lock().await;
        if let Some(snapshot) = self.current_dashboard().await {
            return Ok(snapshot);
        }

        let (attempt, connecting) = {
            let mut inner = self.inner.lock().await;
            inner.reconnect_attempt = inner.reconnect_attempt.saturating_add(1);
            let attempt = inner.reconnect_attempt;
            inner.connection = ConnectionView::connecting(UtcTimestamp::now().to_string(), attempt);
            (attempt, inner.connection.clone())
        };
        emit_connection(app, connecting);

        let client = match SteinClientAdapter::connect_default().await {
            Ok(client) => client,
            Err(error) => {
                self.mark_disconnected(app, error.clone()).await;
                return Err(error);
            }
        };

        // For a private client, open_subscription produces the authoritative
        // snapshot and event receiver atomically. A diagnostic connection never
        // opens the private event stream and refreshes only its allowlisted view.
        let (snapshot, events) = if client.private_protocol_available() {
            let subscription = match client.open_subscription().await {
                Ok(subscription) => subscription,
                Err(error) => {
                    self.mark_disconnected(app, error.clone()).await;
                    return Err(error);
                }
            };
            (subscription.snapshot, Some(subscription.events))
        } else {
            match client.authoritative_snapshot().await {
                Ok(snapshot) => (snapshot, None),
                Err(error) => {
                    self.mark_disconnected(app, error.clone()).await;
                    return Err(error);
                }
            }
        };

        let connected_at = UtcTimestamp::now().to_string();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let dashboard = {
            let mut inner = self.inner.lock().await;
            inner.client = Some(client.clone());
            inner.snapshot = Some(snapshot.clone());
            inner.connection = ConnectionView::connected(connected_at, attempt);
            dashboard_from(&inner, &snapshot)
        };
        emit_snapshot(app, dashboard.clone());
        self.spawn_monitor(app.clone(), client, events, generation);
        Ok(dashboard)
    }

    fn spawn_monitor(
        &self,
        app: AppHandle,
        client: SteinClientAdapter,
        mut events: Option<tokio::sync::broadcast::Receiver<EventEnvelope>>,
        generation: u64,
    ) {
        let bridge = self.clone();
        tauri::async_runtime::spawn(async move {
            let mut health_tick = tokio::time::interval(HEALTH_REFRESH_INTERVAL);
            health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            health_tick.tick().await;

            loop {
                if bridge.generation.load(Ordering::SeqCst) != generation {
                    return;
                }

                tokio::select! {
                    received = receive_event(&mut events) => match received {
                        Ok(event) => bridge.accept_event(&app, &client, event, generation).await,
                        Err(RecvError::Lagged(_)) => {
                            let error = PublicErrorView::unavailable(
                                "event_gap",
                                "The desktop event stream lost continuity. Reconnect for a current snapshot.",
                            );
                            bridge.mark_disconnected_if_current(&app, error, generation).await;
                            return;
                        }
                        Err(RecvError::Closed) => {
                            let error = PublicErrorView::unavailable(
                                "core_connection_closed",
                                "CORE closed the private desktop event stream.",
                            );
                            bridge.mark_disconnected_if_current(&app, error, generation).await;
                            return;
                        }
                    },
                    _ = health_tick.tick() => match client.authoritative_snapshot().await {
                        Ok(snapshot) => {
                            if let Some(snapshot) = bridge.store_snapshot_if_current(snapshot, generation).await {
                                emit_snapshot(&app, snapshot);
                            }
                        }
                        Err(error) => {
                            bridge.mark_disconnected_if_current(&app, error, generation).await;
                            return;
                        }
                    },
                }
            }
        });
    }

    async fn accept_event(
        &self,
        app: &AppHandle,
        client: &SteinClientAdapter,
        event: EventEnvelope,
        generation: u64,
    ) {
        if self.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        let event_view = CoreEventView::from_protocol(&event);
        let snapshot = client.cached_snapshot().await;
        let dashboard = {
            let mut inner = self.inner.lock().await;
            if self.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            inner.snapshot = Some(snapshot.clone());
            if !inner
                .recent_events
                .iter()
                .any(|item| item.message_id == event_view.message_id)
            {
                inner.recent_events.push_front(event_view.clone());
                inner.recent_events.truncate(RECENT_EVENT_LIMIT);
            }
            dashboard_from(&inner, &snapshot)
        };
        emit(
            app,
            DesktopBridgeEvent::ViewEvent {
                schema_version: DESKTOP_BRIDGE_SCHEMA_VERSION,
                event: event_view,
            },
        );
        emit_snapshot(app, dashboard);
    }

    async fn publish_after_mutation(&self, app: &AppHandle, client: &SteinClientAdapter) {
        match client.authoritative_snapshot().await {
            Ok(snapshot) => {
                let dashboard = self.store_snapshot(snapshot).await;
                emit_snapshot(app, dashboard);
            }
            Err(error) => self.mark_disconnected(app, error).await,
        }
    }

    async fn connected_client(&self) -> Result<SteinClientAdapter, PublicErrorView> {
        self.inner.lock().await.client.clone().ok_or_else(|| {
            PublicErrorView::unavailable(
                "core_not_connected",
                "Reconnect to CORE before issuing a command.",
            )
        })
    }

    async fn store_snapshot(&self, snapshot: ClientSnapshot) -> DashboardSnapshot {
        let mut inner = self.inner.lock().await;
        inner.snapshot = Some(snapshot.clone());
        dashboard_from(&inner, &snapshot)
    }

    async fn store_snapshot_if_current(
        &self,
        snapshot: ClientSnapshot,
        generation: u64,
    ) -> Option<DashboardSnapshot> {
        let mut inner = self.inner.lock().await;
        if self.generation.load(Ordering::SeqCst) != generation {
            return None;
        }
        inner.snapshot = Some(snapshot.clone());
        Some(dashboard_from(&inner, &snapshot))
    }

    async fn current_dashboard(&self) -> Option<DashboardSnapshot> {
        let inner = self.inner.lock().await;
        inner
            .snapshot
            .as_ref()
            .map(|snapshot| dashboard_from(&inner, snapshot))
    }

    async fn mark_disconnected(&self, app: &AppHandle, error: PublicErrorView) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let connection = {
            let mut inner = self.inner.lock().await;
            inner.client = None;
            inner.snapshot = None;
            inner.recent_events.clear();
            let reconnect_attempt = inner.reconnect_attempt;
            inner.connection = ConnectionView::disconnected(
                UtcTimestamp::now().to_string(),
                reconnect_attempt,
                error,
            );
            inner.connection.clone()
        };
        emit_connection(app, connection);
    }

    async fn mark_disconnected_if_current(
        &self,
        app: &AppHandle,
        error: PublicErrorView,
        generation: u64,
    ) {
        if self
            .generation
            .compare_exchange(
                generation,
                generation.saturating_add(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return;
        }
        let connection = {
            let mut inner = self.inner.lock().await;
            inner.client = None;
            inner.snapshot = None;
            inner.recent_events.clear();
            let reconnect_attempt = inner.reconnect_attempt;
            inner.connection = ConnectionView::disconnected(
                UtcTimestamp::now().to_string(),
                reconnect_attempt,
                error,
            );
            inner.connection.clone()
        };
        emit_connection(app, connection);
    }
}

async fn receive_event(
    events: &mut Option<tokio::sync::broadcast::Receiver<EventEnvelope>>,
) -> Result<EventEnvelope, RecvError> {
    match events {
        Some(events) => events.recv().await,
        None => pending().await,
    }
}

fn dashboard_from(state: &BridgeState, snapshot: &ClientSnapshot) -> DashboardSnapshot {
    DashboardSnapshot::from_protocol(
        snapshot,
        state.connection.clone(),
        state
            .client
            .as_ref()
            .is_some_and(SteinClientAdapter::private_protocol_available),
        state.recent_events.iter().cloned().collect(),
    )
}

fn emit_snapshot(app: &AppHandle, snapshot: DashboardSnapshot) {
    emit(
        app,
        DesktopBridgeEvent::SnapshotChanged {
            schema_version: DESKTOP_BRIDGE_SCHEMA_VERSION,
            snapshot: Box::new(snapshot),
        },
    );
}

fn emit_connection(app: &AppHandle, connection: ConnectionView) {
    emit(
        app,
        DesktopBridgeEvent::ConnectionChanged {
            schema_version: DESKTOP_BRIDGE_SCHEMA_VERSION,
            connection,
        },
    );
}

fn emit(app: &AppHandle, event: DesktopBridgeEvent) {
    if let Err(error) = app.emit(DESKTOP_BRIDGE_EVENT, event) {
        tracing::warn!(%error, "failed to emit a privacy-filtered desktop bridge event");
    }
}
