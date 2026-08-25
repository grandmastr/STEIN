#[cfg(windows)]
mod implementation {
    use std::{
        collections::{HashMap, HashSet},
        os::windows::io::{AsRawHandle, BorrowedHandle},
        sync::{Arc, Mutex as StdMutex},
        time::{Duration, Instant as StdInstant},
    };

    use stein_broker_windows::PackageServerConnectionAuthority;
    use stein_core::ClientAssurance;
    use stein_protocol::{
        AbandonGoalRequest, AbandonGoalResponse, ActorKind, ActorReference,
        ApproveModelRouteRequest, ApproveModelRouteResponse, CancelRequest, CancellationId,
        CancellationStatus, CapabilityHealth, CaptureStateView, ClientHello, ClientInstanceId,
        ClientMessage, ClientSnapshot, CompleteGoalRequest, CompleteGoalResponse, Component,
        CreateGoalRequest, CreateGoalResponse, DelayEchoRequest, DelayEchoResponse,
        DeleteGoalRequest, DeleteGoalResponse, EndFocusSessionRequest, EndFocusSessionResponse,
        ErrorCode, EventEnvelope, ExplainInterventionRequest, ExplainInterventionResponse,
        FocusSessionChangeKind, FocusSessionState, FocusSessionView, GetCapabilityHealthRequest,
        GetCapabilityHealthResponse, GetEffectivePolicyRequest, GetEffectivePolicyResponse,
        GetFocusSessionViewRequest, GetFocusSessionViewResponse, GetGoalRequest, GetGoalResponse,
        GetInterventionHistoryRequest, GetInterventionHistoryResponse, GetPermissionViewRequest,
        GetPermissionViewResponse, GetRuntimeStatusRequest, GetRuntimeStatusResponse,
        GetSelectedResourcesRequest, GetSelectedResourcesResponse, GetSnapshotRequest,
        GetSteinIdentityRequest, GetSteinIdentityResponse, GetUserPreferencesRequest,
        GetUserPreferencesResponse, GoalChangeKind, GoalState, GrantSessionPermissionRequest,
        GrantSessionPermissionResponse, HealthState, IdempotencyKey, InterventionHistoryChangeKind,
        InterventionState, InterventionView, MessageId, ModelRouteApprovalId,
        ModelRouteApprovalState, PermissionChangeKind, PermissionGrantId, PermissionRecordView,
        PermissionState, Phase2Snapshot, ProtocolSupport, ProtocolVersion, PublicError,
        RecordInterventionFeedbackRequest, RecordInterventionFeedbackResponse,
        RegisterSelectedResourceRequest, RegisterSelectedResourceResponse,
        RemoveSelectedResourceRequest, RemoveSelectedResourceResponse, RequestBody,
        RequestEnvelope, RequestId, RequestKind, RequestMetadata, ResponseBody, ResponseEnvelope,
        ResponseOutcome, RetentionClass, RevokePermissionRequest, RevokePermissionResponse,
        RuntimeStatusChanged, SensitivityClass, ServerMessage, SessionOpened,
        SetInterventionsMutedRequest, SetInterventionsMutedResponse, ShutdownReason,
        ShutdownRequest, ShutdownResponse, StartFocusSessionRequest, StartFocusSessionResponse,
        UpdateGoalRequest, UpdateGoalResponse, UpdateUserPreferencesRequest,
        UpdateUserPreferencesResponse, UtcTimestamp, ViewEvent,
    };
    use thiserror::Error;
    use tokio::{
        io::split,
        net::windows::named_pipe::NamedPipeClient,
        sync::{Mutex, RwLock, broadcast, mpsc, oneshot},
        time::{Instant, timeout, timeout_at},
    };
    use tokio_util::sync::CancellationToken;

    use crate::{
        capability_supported,
        codec::{read_frame, write_frame},
        default_pipe_name,
        windows::connect_pipe,
    };

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    const CANCELLATION_CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);
    const MAX_APPLIED_EVENT_IDENTITIES: usize = 4_096;
    type PendingResult = Result<ResponseEnvelope, PendingFailure>;
    type CancellationResult = Result<CancellationStatus, PendingFailure>;

    fn borrowed_client_handle(pipe: &NamedPipeClient) -> BorrowedHandle<'_> {
        // SAFETY: the borrow cannot outlive the referenced Tokio pipe and no
        // ownership of its native handle is transferred.
        unsafe { BorrowedHandle::borrow_raw(pipe.as_raw_handle()) }
    }

    enum PipeAdmission {
        Diagnostic,
        #[cfg(feature = "private-client-test-harness")]
        PrivateCapabilityBoundForTest,
        PrivateBroker(PackageServerConnectionAuthority),
    }

    impl PipeAdmission {
        const fn assurance(&self) -> ClientAssurance {
            match self {
                Self::Diagnostic => ClientAssurance::Diagnostic,
                #[cfg(feature = "private-client-test-harness")]
                Self::PrivateCapabilityBoundForTest => ClientAssurance::PrivateCapabilityBound,
                Self::PrivateBroker(_) => ClientAssurance::PrivateCapabilityBound,
            }
        }

        fn is_current_for(&self, pipe: &NamedPipeClient, now: StdInstant) -> bool {
            match self {
                Self::Diagnostic => true,
                #[cfg(feature = "private-client-test-harness")]
                Self::PrivateCapabilityBoundForTest => true,
                Self::PrivateBroker(authority) => {
                    authority.is_current_for(borrowed_client_handle(pipe), now)
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PendingFailure {
        Closed,
        EventGap,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum EventApplication {
        Applied,
        AlreadyCovered,
        Gap,
    }

    impl PendingFailure {
        const fn into_client_error(self) -> ClientError {
            match self {
                Self::Closed => ClientError::Closed,
                Self::EventGap => ClientError::EventGap,
            }
        }
    }

    struct CancellationWaiter {
        target_request_id: RequestId,
        correlation_id: stein_protocol::CorrelationId,
        causation_id: stein_protocol::MessageId,
        sender: oneshot::Sender<CancellationResult>,
    }

    #[derive(Debug, Error)]
    pub enum ClientError {
        #[error("CORE local transport is unavailable: {0}")]
        Transport(#[from] std::io::Error),
        #[error("CORE closed the local protocol connection")]
        Closed,
        #[error("CORE protocol handshake failed: {0}")]
        Handshake(String),
        #[error("CORE request timed out")]
        Timeout,
        #[error("CORE request failed: {0:?}")]
        Request(PublicError),
        #[error("CORE returned an unexpected response variant")]
        UnexpectedResponse,
        #[error("CORE event stream requires an authoritative reconnect")]
        EventGap,
        #[error("request was cancelled")]
        Cancelled,
        #[error("CORE did not confirm request cancellation before the deadline")]
        CancellationUnconfirmed,
        #[error("the request requires a private capability-bound client session")]
        PrivateCapabilityRequired,
        #[error("the connected private broker did not have current native admission")]
        PrivateBrokerAdmission,
        #[error(
            "the request requires protocol {required:?}, but the session negotiated {negotiated:?}"
        )]
        UnsupportedProtocol {
            required: ProtocolVersion,
            negotiated: ProtocolVersion,
        },
    }

    #[derive(Clone)]
    pub struct Client {
        owner: Arc<ClientOwner>,
    }

    /// An authoritative cached snapshot paired with an event receiver that
    /// cannot miss any later applied view event. Consumers should still discard
    /// an event whose cursor is already covered by `snapshot.cursor`.
    pub struct ClientSubscription {
        pub snapshot: ClientSnapshot,
        pub events: broadcast::Receiver<EventEnvelope>,
    }

    struct ClientOwner {
        inner: Arc<ClientInner>,
    }

    impl Drop for ClientOwner {
        fn drop(&mut self) {
            // Background tasks own ClientInner directly, never ClientOwner. The
            // final externally owned Client therefore closes the connection
            // even while reader and writer tasks are still running.
            record_terminal_failure(&self.inner, PendingFailure::Closed);
            self.inner.closed.cancel();
        }
    }

    struct ClientInner {
        session: SessionOpened,
        assurance: ClientAssurance,
        origin: Component,
        snapshot: RwLock<ClientSnapshot>,
        writer: mpsc::Sender<ClientMessage>,
        pending: Mutex<HashMap<RequestId, oneshot::Sender<PendingResult>>>,
        cancellation_waiters: Mutex<HashMap<CancellationId, CancellationWaiter>>,
        terminal_failure: StdMutex<Option<PendingFailure>>,
        applied_event_ids: StdMutex<HashSet<MessageId>>,
        events: broadcast::Sender<EventEnvelope>,
        initial_events: StdMutex<Option<broadcast::Receiver<EventEnvelope>>>,
        closed: CancellationToken,
    }

    impl Client {
        pub async fn connect_default() -> Result<Self, ClientError> {
            Self::connect_with_support("stein-client", ProtocolSupport::V1).await
        }

        pub async fn connect_with_support(
            client_name: impl Into<String>,
            protocol_support: ProtocolSupport,
        ) -> Result<Self, ClientError> {
            Self::connect_with_identity(client_name, Component::CoreCli, protocol_support).await
        }

        pub async fn connect_with_identity(
            client_name: impl Into<String>,
            origin: Component,
            protocol_support: ProtocolSupport,
        ) -> Result<Self, ClientError> {
            let pipe_name = default_pipe_name()?;
            Self::connect_named_pipe(
                client_name,
                origin,
                protocol_support,
                pipe_name,
                PipeAdmission::Diagnostic,
            )
            .await
        }

        /// Explicit non-production compatibility hook for the retained Phase 1
        /// harness. It does not prove broker admission and is unavailable from
        /// normal builds.
        #[cfg(feature = "private-client-test-harness")]
        pub async fn connect_private_capability_bound_for_test(
            client_name: impl Into<String>,
            origin: Component,
            protocol_support: ProtocolSupport,
            endpoint: &crate::PrivateTestEndpoint,
        ) -> Result<Self, ClientError> {
            Self::connect_named_pipe(
                client_name,
                origin,
                protocol_support,
                endpoint.pipe_name().to_owned(),
                PipeAdmission::PrivateCapabilityBoundForTest,
            )
            .await
        }

        /// Opens a production private session over an already connected broker
        /// pipe. The opaque proof can only be minted after kernel verification
        /// of the exact packaged AppContainer server and is rechecked against
        /// this owned handle before the first byte and after SessionOpened.
        pub async fn connect_private_brokered(
            client_name: impl Into<String>,
            origin: Component,
            protocol_support: ProtocolSupport,
            pipe: NamedPipeClient,
            authority: PackageServerConnectionAuthority,
        ) -> Result<Self, ClientError> {
            Self::connect_owned_pipe(
                client_name,
                origin,
                protocol_support,
                pipe,
                PipeAdmission::PrivateBroker(authority),
            )
            .await
        }

        async fn connect_named_pipe(
            client_name: impl Into<String>,
            origin: Component,
            protocol_support: ProtocolSupport,
            pipe_name: String,
            admission: PipeAdmission,
        ) -> Result<Self, ClientError> {
            if !matches!(
                origin,
                Component::CoreCli | Component::DesktopClient | Component::TestFixture
            ) {
                return Err(ClientError::Handshake(
                    "the requested component cannot act as a protocol client".into(),
                ));
            }
            validate_protocol_support(protocol_support)?;
            let pipe = connect_pipe(&pipe_name, CONNECT_TIMEOUT).await?;
            Self::connect_owned_pipe(client_name, origin, protocol_support, pipe, admission).await
        }

        async fn connect_owned_pipe(
            client_name: impl Into<String>,
            origin: Component,
            protocol_support: ProtocolSupport,
            mut pipe: NamedPipeClient,
            admission: PipeAdmission,
        ) -> Result<Self, ClientError> {
            if !matches!(
                origin,
                Component::CoreCli | Component::DesktopClient | Component::TestFixture
            ) {
                return Err(ClientError::Handshake(
                    "the requested component cannot act as a protocol client".into(),
                ));
            }
            validate_protocol_support(protocol_support)?;
            if !admission.is_current_for(&pipe, StdInstant::now()) {
                return Err(ClientError::PrivateBrokerAdmission);
            }
            let assurance = admission.assurance();
            let hello = ClientHello {
                client_instance_id: ClientInstanceId::new_v7(),
                client_name: client_name.into(),
                client_build_id: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_support,
                max_frame_bytes: crate::MAX_FRAME_BYTES as u32,
                capabilities: Vec::new(),
            };
            write_frame(&mut pipe, &ClientMessage::OpenSession(hello.clone())).await?;

            let opened = match timeout(CONNECT_TIMEOUT, read_frame::<_, ServerMessage>(&mut pipe))
                .await
                .map_err(|_| ClientError::Timeout)??
            {
                ServerMessage::SessionOpened(opened) => opened,
                ServerMessage::Fatal(fatal) => {
                    return Err(ClientError::Handshake(fatal.error.summary));
                }
                _ => {
                    return Err(ClientError::Handshake(
                        "server did not return SessionOpened".into(),
                    ));
                }
            };
            validate_session_opened(&hello, &opened, assurance)?;

            if !admission.is_current_for(&pipe, StdInstant::now()) {
                return Err(ClientError::PrivateBrokerAdmission);
            }

            let (mut reader, mut writer) = split(pipe);

            let (writer_tx, mut writer_rx) = mpsc::channel::<ClientMessage>(64);
            // Retain the channel's first receiver until the caller subscribes.
            // Otherwise an event after the handshake snapshot but before the
            // first subscribe_events call would be silently discarded.
            let (events, initial_events) = broadcast::channel(128);
            let closed = CancellationToken::new();
            let inner = Arc::new(ClientInner {
                snapshot: RwLock::new(opened.snapshot.clone()),
                session: opened,
                assurance,
                origin,
                writer: writer_tx,
                pending: Mutex::new(HashMap::new()),
                cancellation_waiters: Mutex::new(HashMap::new()),
                terminal_failure: StdMutex::new(None),
                applied_event_ids: StdMutex::new(HashSet::new()),
                events,
                initial_events: StdMutex::new(Some(initial_events)),
                closed: closed.clone(),
            });

            let writer_inner = inner.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        () = writer_inner.closed.cancelled() => break,
                        message = writer_rx.recv() => {
                            let Some(message) = message else { break };
                            if write_frame(&mut writer, &message).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                terminate(&writer_inner, PendingFailure::Closed).await;
            });

            let reader_inner = inner.clone();
            tokio::spawn(async move {
                let failure = loop {
                    let incoming = tokio::select! {
                        biased;
                        () = reader_inner.closed.cancelled() => break PendingFailure::Closed,
                        incoming = read_frame::<_, ServerMessage>(&mut reader) => incoming,
                    };
                    match incoming {
                        Ok(ServerMessage::Response(response)) => {
                            if let Some(waiter) = reader_inner
                                .pending
                                .lock()
                                .await
                                .remove(&response.request_id)
                            {
                                let _ = waiter.send(Ok(response));
                            }
                        }
                        Ok(ServerMessage::Event(event)) => {
                            match apply_event_with_ids(
                                &reader_inner.snapshot,
                                &reader_inner.session,
                                reader_inner.assurance,
                                &reader_inner.applied_event_ids,
                                &event,
                            )
                            .await
                            {
                                EventApplication::Applied => {
                                    let _ = reader_inner.events.send(event);
                                }
                                EventApplication::AlreadyCovered => {}
                                EventApplication::Gap => break PendingFailure::EventGap,
                            }
                        }
                        Ok(ServerMessage::EventGap(_)) => {
                            break PendingFailure::EventGap;
                        }
                        Ok(ServerMessage::Fatal(_)) => {
                            break PendingFailure::Closed;
                        }
                        Ok(ServerMessage::CancelAcknowledged(acknowledged)) => {
                            let waiter = reader_inner
                                .cancellation_waiters
                                .lock()
                                .await
                                .remove(&acknowledged.cancellation_id);
                            if let Some(waiter) = waiter {
                                if waiter.target_request_id != acknowledged.target_request_id
                                    || waiter.correlation_id != acknowledged.correlation_id
                                    || waiter.causation_id != acknowledged.causation_id
                                    || acknowledged.actor.kind != ActorKind::CoreDaemon
                                    || acknowledged.actor.actor_id.as_uuid()
                                        != reader_inner.session.daemon_instance_id.as_uuid()
                                {
                                    let _ = waiter.sender.send(Err(PendingFailure::Closed));
                                    break PendingFailure::Closed;
                                }
                                let _ = waiter.sender.send(Ok(acknowledged.status));
                            }
                        }
                        Ok(ServerMessage::SessionOpened(_)) => {
                            break PendingFailure::Closed;
                        }
                        Err(_) => break PendingFailure::Closed,
                    }
                };
                terminate(&reader_inner, failure).await;
            });

            Ok(Self {
                owner: Arc::new(ClientOwner { inner }),
            })
        }

        #[must_use]
        pub fn session(&self) -> &SessionOpened {
            &self.owner.inner.session
        }

        #[must_use]
        pub fn assurance(&self) -> ClientAssurance {
            self.owner.inner.assurance
        }

        pub async fn cached_snapshot(&self) -> ClientSnapshot {
            self.owner.inner.snapshot.read().await.clone()
        }

        pub async fn open_subscription(&self) -> Result<ClientSubscription, ClientError> {
            let inner = &self.owner.inner;
            if inner.closed.is_cancelled() {
                return Err(terminal_client_error(inner));
            }
            if !matches!(inner.assurance, ClientAssurance::PrivateCapabilityBound) {
                return Err(ClientError::PrivateCapabilityRequired);
            }

            // Holding the snapshot read lock prevents event application until
            // the new receiver exists. An event already applied but not yet
            // broadcast can be duplicated, never missed; the cursor resolves it.
            let snapshot = inner.snapshot.read().await;
            let events = inner.events.subscribe();
            let snapshot = snapshot.clone();
            inner
                .initial_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            Ok(ClientSubscription { snapshot, events })
        }

        /// Legacy receiver-only API retained for Phase 1 callers. Diagnostic
        /// sessions receive an already-closed receiver and therefore cannot
        /// wait on or observe a private event source. New code should use
        /// `open_subscription` so the assurance error and atomic snapshot are
        /// explicit.
        pub fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
            if !matches!(
                self.owner.inner.assurance,
                ClientAssurance::PrivateCapabilityBound
            ) {
                let (sender, receiver) = broadcast::channel(1);
                drop(sender);
                return receiver;
            }
            self.owner
                .inner
                .initial_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_else(|| self.owner.inner.events.subscribe())
        }

        pub async fn next_event(&self) -> Result<EventEnvelope, ClientError> {
            let inner = &self.owner.inner;
            if !matches!(inner.assurance, ClientAssurance::PrivateCapabilityBound) {
                return Err(ClientError::PrivateCapabilityRequired);
            }
            let mut events = self.subscribe_events();
            tokio::select! {
                biased;
                () = inner.closed.cancelled() => Err(terminal_client_error(inner)),
                result = events.recv() => result.map_err(|_| ClientError::EventGap),
            }
        }

        pub async fn get_client_snapshot(&self) -> Result<ClientSnapshot, ClientError> {
            let body = self
                .request(
                    RequestBody::GetSnapshot(GetSnapshotRequest::default()),
                    None,
                    None,
                )
                .await?;
            match body {
                ResponseBody::GetSnapshot(value) => {
                    merge_snapshot(&self.owner.inner, value.snapshot).await
                }
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_runtime_status(&self) -> Result<GetRuntimeStatusResponse, ClientError> {
            match self
                .request(
                    RequestBody::GetRuntimeStatus(GetRuntimeStatusRequest::default()),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::GetRuntimeStatus(value) => Ok(value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_capability_health(
            &self,
        ) -> Result<GetCapabilityHealthResponse, ClientError> {
            match self
                .request(
                    RequestBody::GetCapabilityHealth(GetCapabilityHealthRequest::default()),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::GetCapabilityHealth(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn create_goal(
            &self,
            input: CreateGoalRequest,
        ) -> Result<CreateGoalResponse, ClientError> {
            self.create_goal_idempotent(input, IdempotencyKey::new_v7())
                .await
        }

        pub async fn create_goal_idempotent(
            &self,
            input: CreateGoalRequest,
            idempotency_key: IdempotencyKey,
        ) -> Result<CreateGoalResponse, ClientError> {
            match self
                .request(RequestBody::CreateGoal(input), Some(idempotency_key), None)
                .await?
            {
                ResponseBody::CreateGoal(value) => Ok(value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn update_goal(
            &self,
            input: UpdateGoalRequest,
        ) -> Result<UpdateGoalResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::UpdateGoal(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn complete_goal(
            &self,
            input: CompleteGoalRequest,
        ) -> Result<CompleteGoalResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::CompleteGoal(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn abandon_goal(
            &self,
            input: AbandonGoalRequest,
        ) -> Result<AbandonGoalResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::AbandonGoal(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn delete_goal(
            &self,
            input: DeleteGoalRequest,
        ) -> Result<DeleteGoalResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::DeleteGoal(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn approve_model_route(
            &self,
            input: ApproveModelRouteRequest,
            idempotency_key: IdempotencyKey,
        ) -> Result<ApproveModelRouteResponse, ClientError> {
            match self
                .request(input.into(), Some(idempotency_key), None)
                .await?
            {
                ResponseBody::ApproveModelRoute(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn grant_session_permission(
            &self,
            input: GrantSessionPermissionRequest,
            idempotency_key: IdempotencyKey,
        ) -> Result<GrantSessionPermissionResponse, ClientError> {
            match self
                .request(input.into(), Some(idempotency_key), None)
                .await?
            {
                ResponseBody::GrantSessionPermission(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn revoke_permission(
            &self,
            input: RevokePermissionRequest,
        ) -> Result<RevokePermissionResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::RevokePermission(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn start_focus_session(
            &self,
            input: StartFocusSessionRequest,
            idempotency_key: IdempotencyKey,
        ) -> Result<StartFocusSessionResponse, ClientError> {
            match self
                .request(input.into(), Some(idempotency_key), None)
                .await?
            {
                ResponseBody::StartFocusSession(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn set_interventions_muted(
            &self,
            input: SetInterventionsMutedRequest,
        ) -> Result<SetInterventionsMutedResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::SetInterventionsMuted(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn end_focus_session(
            &self,
            input: EndFocusSessionRequest,
        ) -> Result<EndFocusSessionResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::EndFocusSession(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn record_intervention_feedback(
            &self,
            input: RecordInterventionFeedbackRequest,
        ) -> Result<RecordInterventionFeedbackResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::RecordInterventionFeedback(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn register_selected_resource(
            &self,
            input: RegisterSelectedResourceRequest,
            idempotency_key: IdempotencyKey,
        ) -> Result<RegisterSelectedResourceResponse, ClientError> {
            match self
                .request(input.into(), Some(idempotency_key), None)
                .await?
            {
                ResponseBody::RegisterSelectedResource(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn remove_selected_resource(
            &self,
            input: RemoveSelectedResourceRequest,
        ) -> Result<RemoveSelectedResourceResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::RemoveSelectedResource(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn update_user_preferences(
            &self,
            input: UpdateUserPreferencesRequest,
        ) -> Result<UpdateUserPreferencesResponse, ClientError> {
            match self.request(input.into(), None, None).await? {
                ResponseBody::UpdateUserPreferences(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_goal(
            &self,
            input: GetGoalRequest,
        ) -> Result<GetGoalResponse, ClientError> {
            match self
                .request(RequestBody::GetGoal(input), None, None)
                .await?
            {
                ResponseBody::GetGoal(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_focus_session_view(
            &self,
            input: GetFocusSessionViewRequest,
        ) -> Result<GetFocusSessionViewResponse, ClientError> {
            match self
                .request(RequestBody::GetFocusSessionView(input), None, None)
                .await?
            {
                ResponseBody::GetFocusSessionView(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_permission_view(
            &self,
            input: GetPermissionViewRequest,
        ) -> Result<GetPermissionViewResponse, ClientError> {
            match self
                .request(RequestBody::GetPermissionView(input), None, None)
                .await?
            {
                ResponseBody::GetPermissionView(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_intervention_history(
            &self,
            input: GetInterventionHistoryRequest,
        ) -> Result<GetInterventionHistoryResponse, ClientError> {
            match self
                .request(RequestBody::GetInterventionHistory(input), None, None)
                .await?
            {
                ResponseBody::GetInterventionHistory(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn explain_intervention(
            &self,
            input: ExplainInterventionRequest,
        ) -> Result<ExplainInterventionResponse, ClientError> {
            match self
                .request(RequestBody::ExplainIntervention(input), None, None)
                .await?
            {
                ResponseBody::ExplainIntervention(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_stein_identity(&self) -> Result<GetSteinIdentityResponse, ClientError> {
            match self
                .request(
                    RequestBody::GetSteinIdentity(GetSteinIdentityRequest {}),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::GetSteinIdentity(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_user_preferences(
            &self,
        ) -> Result<GetUserPreferencesResponse, ClientError> {
            match self
                .request(
                    RequestBody::GetUserPreferences(GetUserPreferencesRequest {}),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::GetUserPreferences(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_effective_policy(
            &self,
        ) -> Result<GetEffectivePolicyResponse, ClientError> {
            match self
                .request(
                    RequestBody::GetEffectivePolicy(GetEffectivePolicyRequest {}),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::GetEffectivePolicy(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn get_selected_resources(
            &self,
        ) -> Result<GetSelectedResourcesResponse, ClientError> {
            match self
                .request(
                    RequestBody::GetSelectedResources(GetSelectedResourcesRequest {}),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::GetSelectedResources(value) => Ok(*value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        pub async fn delay_echo(
            &self,
            delay_ms: u64,
            text: impl Into<String>,
            cancel: Option<CancellationToken>,
        ) -> Result<DelayEchoResponse, ClientError> {
            let cancellation_id = cancel.as_ref().map(|_| CancellationId::new_v7());
            let request = RequestBody::DelayEcho(DelayEchoRequest {
                delay_ms,
                text: text.into(),
            });
            self.request(request, None, cancellation_id.zip(cancel))
                .await
                .and_then(|body| {
                    if let ResponseBody::DelayEcho(value) = body {
                        Ok(value)
                    } else {
                        Err(ClientError::UnexpectedResponse)
                    }
                })
        }

        pub async fn shutdown(
            &self,
            reason: ShutdownReason,
        ) -> Result<ShutdownResponse, ClientError> {
            match self
                .request(
                    RequestBody::Shutdown(ShutdownRequest { reason }),
                    None,
                    None,
                )
                .await?
            {
                ResponseBody::Shutdown(value) => Ok(value),
                _ => Err(ClientError::UnexpectedResponse),
            }
        }

        async fn request(
            &self,
            body: RequestBody,
            idempotency_key: Option<IdempotencyKey>,
            cancellation: Option<(CancellationId, CancellationToken)>,
        ) -> Result<ResponseBody, ClientError> {
            let inner = &self.owner.inner;
            if inner.closed.is_cancelled() {
                return Err(terminal_client_error(inner));
            }
            let request_kind = body.kind();
            let required = body.minimum_protocol_version();
            let negotiated = inner.session.protocol_version;
            if !version_at_least(negotiated, required) {
                return Err(ClientError::UnsupportedProtocol {
                    required,
                    negotiated,
                });
            }
            if !request_allowed(inner.assurance, request_kind) {
                return Err(ClientError::PrivateCapabilityRequired);
            }
            let sensitivity = request_sensitivity(request_kind, negotiated);
            let retention = request_kind.retention();
            let mut metadata = RequestMetadata::new(inner.origin, sensitivity, retention);
            metadata.deadline_at = Some(UtcTimestamp::from_datetime(
                time::OffsetDateTime::now_utc()
                    + time::Duration::try_from(REQUEST_TIMEOUT)
                        .expect("the fixed client timeout fits the wire clock"),
            ));
            metadata.idempotency_key = idempotency_key;
            metadata.cancellation_id = cancellation.as_ref().map(|(id, _)| *id);
            let envelope = RequestEnvelope::new(metadata, body);
            let request_id = envelope.request_id;
            let request_message_id = envelope.metadata.message_id;
            let correlation_id = envelope.metadata.correlation_id;
            let (send, mut receive) = oneshot::channel();
            inner.pending.lock().await.insert(request_id, send);
            match timeout(
                REQUEST_TIMEOUT,
                inner.writer.send(ClientMessage::Request(envelope)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    inner.pending.lock().await.remove(&request_id);
                    return Err(ClientError::Closed);
                }
                Err(_) => {
                    inner.pending.lock().await.remove(&request_id);
                    return Err(ClientError::Timeout);
                }
            }

            let response = if let Some((cancellation_id, token)) = cancellation {
                tokio::select! {
                    biased;
                    result = &mut receive => resolve_pending(result)?,
                    () = token.cancelled() => {
                        self.confirm_cancellation(
                            request_id,
                            cancellation_id,
                            correlation_id,
                            &mut receive,
                        ).await?
                    },
                    () = tokio::time::sleep(REQUEST_TIMEOUT) => {
                        inner.pending.lock().await.remove(&request_id);
                        return Err(ClientError::Timeout);
                    }
                }
            } else {
                match timeout(REQUEST_TIMEOUT, &mut receive).await {
                    Ok(result) => resolve_pending(result)?,
                    Err(_) => {
                        inner.pending.lock().await.remove(&request_id);
                        return Err(ClientError::Timeout);
                    }
                }
            };

            if response.request_id != request_id
                || response.metadata.schema_version != stein_protocol::SCHEMA_VERSION_V1
                || response.metadata.causation_id != request_message_id
                || response.metadata.correlation_id != correlation_id
                || response.metadata.origin != Component::CoreDaemon
                || response.metadata.actor != inner.session.authenticated_actor
                || response.metadata.sensitivity != sensitivity
                || response.metadata.retention != retention
            {
                terminate(inner, PendingFailure::Closed).await;
                return Err(ClientError::UnexpectedResponse);
            }
            match response.outcome {
                ResponseOutcome::Success(body)
                    if body.kind() == request_kind
                        && version_at_least(negotiated, body.minimum_protocol_version()) =>
                {
                    Ok(body)
                }
                ResponseOutcome::Success(_) => {
                    terminate(inner, PendingFailure::Closed).await;
                    Err(ClientError::UnexpectedResponse)
                }
                ResponseOutcome::Error(error) if error.code == ErrorCode::Cancelled => {
                    Err(ClientError::Cancelled)
                }
                ResponseOutcome::Error(error) => Err(ClientError::Request(error)),
            }
        }

        async fn confirm_cancellation(
            &self,
            request_id: RequestId,
            cancellation_id: CancellationId,
            correlation_id: stein_protocol::CorrelationId,
            receive: &mut oneshot::Receiver<PendingResult>,
        ) -> Result<ResponseEnvelope, ClientError> {
            let inner = &self.owner.inner;
            let cancel_message_id = stein_protocol::MessageId::new_v7();
            let cancel = ClientMessage::Cancel(CancelRequest {
                message_id: cancel_message_id,
                issued_at: UtcTimestamp::now(),
                correlation_id,
                origin: inner.origin,
                target_request_id: request_id,
                cancellation_id,
            });
            let (acknowledge, acknowledged) = oneshot::channel();
            let replaced = inner.cancellation_waiters.lock().await.insert(
                cancellation_id,
                CancellationWaiter {
                    target_request_id: request_id,
                    correlation_id,
                    causation_id: cancel_message_id,
                    sender: acknowledge,
                },
            );
            if replaced.is_some() {
                inner.pending.lock().await.remove(&request_id);
                return Err(ClientError::UnexpectedResponse);
            }

            let deadline = Instant::now() + CANCELLATION_CONFIRM_TIMEOUT;
            match timeout_at(deadline, inner.writer.send(cancel)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    inner
                        .cancellation_waiters
                        .lock()
                        .await
                        .remove(&cancellation_id);
                    inner.pending.lock().await.remove(&request_id);
                    return Err(ClientError::Closed);
                }
                Err(_) => {
                    inner
                        .cancellation_waiters
                        .lock()
                        .await
                        .remove(&cancellation_id);
                    inner.pending.lock().await.remove(&request_id);
                    return Err(ClientError::CancellationUnconfirmed);
                }
            }

            let confirmation = timeout_at(deadline, async {
                tokio::try_join!(async { resolve_pending(receive.await) }, async {
                    acknowledged
                        .await
                        .map_err(|_| ClientError::Closed)?
                        .map_err(PendingFailure::into_client_error)
                })
            })
            .await;

            inner
                .cancellation_waiters
                .lock()
                .await
                .remove(&cancellation_id);
            match confirmation {
                Ok(Ok((response, _status))) => Ok(response),
                Ok(Err(error)) => {
                    inner.pending.lock().await.remove(&request_id);
                    Err(error)
                }
                Err(_) => {
                    inner.pending.lock().await.remove(&request_id);
                    Err(ClientError::CancellationUnconfirmed)
                }
            }
        }
    }

    fn resolve_pending(
        result: Result<PendingResult, oneshot::error::RecvError>,
    ) -> Result<ResponseEnvelope, ClientError> {
        result
            .map_err(|_| ClientError::Closed)?
            .map_err(PendingFailure::into_client_error)
    }

    async fn terminate(inner: &ClientInner, failure: PendingFailure) {
        let failure = record_terminal_failure(inner, failure);
        inner.closed.cancel();
        let pending = std::mem::take(&mut *inner.pending.lock().await);
        for (_, waiter) in pending {
            let _ = waiter.send(Err(failure));
        }
        let cancellations = std::mem::take(&mut *inner.cancellation_waiters.lock().await);
        for (_, waiter) in cancellations {
            let _ = waiter.sender.send(Err(failure));
        }
    }

    fn record_terminal_failure(inner: &ClientInner, failure: PendingFailure) -> PendingFailure {
        let mut terminal = inner
            .terminal_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if terminal.is_none() || failure == PendingFailure::EventGap {
            *terminal = Some(failure);
        }
        terminal.unwrap_or(PendingFailure::Closed)
    }

    fn terminal_client_error(inner: &ClientInner) -> ClientError {
        inner
            .terminal_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .unwrap_or(PendingFailure::Closed)
            .into_client_error()
    }

    const fn version_at_least(negotiated: ProtocolVersion, required: ProtocolVersion) -> bool {
        negotiated.major == required.major && negotiated.minor >= required.minor
    }

    fn validate_protocol_support(support: ProtocolSupport) -> Result<(), ClientError> {
        if support.minimum_minor > support.maximum_minor
            || support.major != ProtocolSupport::V1.major
            || support.maximum_minor > ProtocolSupport::V1.maximum_minor
        {
            return Err(ClientError::Handshake(
                "the requested protocol range exceeds this client's implemented versions".into(),
            ));
        }
        Ok(())
    }

    const fn request_allowed(assurance: ClientAssurance, kind: RequestKind) -> bool {
        match assurance {
            ClientAssurance::PrivateCapabilityBound => true,
            ClientAssurance::Diagnostic => matches!(
                kind,
                RequestKind::GetRuntimeStatus | RequestKind::GetCapabilityHealth
            ),
            ClientAssurance::NativeEmergencyControl => false,
        }
    }

    const fn request_sensitivity(
        kind: RequestKind,
        negotiated: ProtocolVersion,
    ) -> SensitivityClass {
        if matches!(kind, RequestKind::GetSnapshot)
            && negotiated.major == ProtocolVersion::V1_0.major
            && negotiated.minor == ProtocolVersion::V1_0.minor
        {
            // Preserve the protocol 1.0 wire classification. Protocol 1.1
            // tightened the authoritative private snapshot to Restricted.
            SensitivityClass::Personal
        } else {
            kind.sensitivity()
        }
    }

    async fn merge_snapshot(
        inner: &ClientInner,
        incoming: ClientSnapshot,
    ) -> Result<ClientSnapshot, ClientError> {
        if !snapshot_is_consistent(&inner.session, inner.assurance, &incoming) {
            terminate(inner, PendingFailure::Closed).await;
            return Err(ClientError::UnexpectedResponse);
        }

        let mut current = inner.snapshot.write().await;
        if incoming.cursor.sequence > current.cursor.sequence
            || (incoming.cursor.sequence == current.cursor.sequence
                && incoming.as_of > current.as_of)
        {
            *current = incoming;
        }
        Ok(current.clone())
    }

    fn validate_session_opened(
        hello: &ClientHello,
        opened: &SessionOpened,
        assurance: ClientAssurance,
    ) -> Result<(), ClientError> {
        let version = opened.protocol_version;
        if validate_protocol_support(hello.protocol_support).is_err()
            || !ProtocolSupport::V1.supports(version)
            || version.major != hello.protocol_support.major
            || version.minor < hello.protocol_support.minimum_minor
            || version.minor > hello.protocol_support.maximum_minor
        {
            return Err(ClientError::Handshake(
                "server selected a protocol version outside the advertised range".into(),
            ));
        }
        if opened.server_build_id.trim().is_empty() {
            return Err(ClientError::Handshake(
                "server returned an empty build identifier".into(),
            ));
        }
        if opened.max_frame_bytes == 0
            || opened.max_frame_bytes > hello.max_frame_bytes
            || opened.max_frame_bytes as usize > crate::MAX_FRAME_BYTES
        {
            return Err(ClientError::Handshake(
                "server returned an invalid frame-size limit".into(),
            ));
        }
        if opened.daemon_instance_id.as_uuid().is_nil()
            || opened.authenticated_actor.actor_id.as_uuid().is_nil()
            || opened.authenticated_actor.kind != ActorKind::LocalOsUser
        {
            return Err(ClientError::Handshake(
                "server returned an invalid authenticated session identity".into(),
            ));
        }
        if opened.capabilities != opened.snapshot.capabilities
            || !snapshot_is_consistent(opened, assurance, &opened.snapshot)
        {
            return Err(ClientError::Handshake(
                "server returned an inconsistent authoritative snapshot".into(),
            ));
        }
        Ok(())
    }

    fn snapshot_is_consistent(
        session: &SessionOpened,
        assurance: ClientAssurance,
        snapshot: &ClientSnapshot,
    ) -> bool {
        if snapshot.snapshot_id.as_uuid().is_nil()
            || snapshot.cursor.daemon_instance_id != session.daemon_instance_id
            || snapshot.runtime.daemon_instance_id != session.daemon_instance_id
            || snapshot.runtime.protocol_version != session.protocol_version
            || snapshot.runtime.started_at > snapshot.runtime.observed_at
            || snapshot.runtime.observed_at > snapshot.as_of
        {
            return false;
        }

        if !matches!(assurance, ClientAssurance::PrivateCapabilityBound)
            && (snapshot.cursor.sequence != 0
                || !snapshot.goals.is_empty()
                || snapshot.phase2.is_some())
        {
            return false;
        }
        if !version_at_least(session.protocol_version, ProtocolVersion::V1_1)
            && snapshot.phase2.is_some()
        {
            return false;
        }
        if matches!(assurance, ClientAssurance::PrivateCapabilityBound)
            && version_at_least(session.protocol_version, ProtocolVersion::V1_1)
            && snapshot.phase2.is_none()
        {
            return false;
        }

        let capabilities_are_consistent =
            snapshot
                .capabilities
                .iter()
                .enumerate()
                .all(|(index, health)| {
                    health.schema_version == stein_protocol::SCHEMA_VERSION_V1
                        && capability_supported(health.capability, session.protocol_version)
                        && match health.state {
                            HealthState::Healthy => health.unavailable_reason.is_none(),
                            HealthState::Unavailable => health.unavailable_reason.is_some(),
                            HealthState::Degraded => true,
                        }
                        && !snapshot.capabilities[..index]
                            .iter()
                            .any(|earlier| earlier.capability == health.capability)
                });
        if !capabilities_are_consistent {
            return false;
        }

        if !snapshot.goals.iter().enumerate().all(|(index, goal)| {
            !goal.goal_id.as_uuid().is_nil()
                && goal.owner_id == session.authenticated_actor.actor_id
                && goal.revision > 0
                && goal.created_at <= goal.updated_at
                && goal.updated_at <= snapshot.as_of
                && !snapshot.goals[..index]
                    .iter()
                    .any(|earlier| earlier.goal_id == goal.goal_id)
        }) {
            return false;
        }

        snapshot
            .phase2
            .as_deref()
            .is_none_or(|phase2| phase2_snapshot_is_consistent(session, snapshot, phase2))
    }

    async fn apply_event_with_ids(
        snapshot: &RwLock<ClientSnapshot>,
        session: &SessionOpened,
        assurance: ClientAssurance,
        applied_event_ids: &StdMutex<HashSet<MessageId>>,
        event: &EventEnvelope,
    ) -> EventApplication {
        let mut current = snapshot.write().await;
        if event.cursor.daemon_instance_id != current.cursor.daemon_instance_id {
            return EventApplication::Gap;
        }
        if event.cursor.sequence <= current.cursor.sequence {
            // A concurrently completed authoritative GetSnapshot can cover an
            // event before the reader observes that event frame. It is stale,
            // not a continuity gap, and must not be published twice.
            if !event_header_is_consistent(session, assurance, &current, event)
                || record_event_identity(applied_event_ids, event.metadata.message_id).is_none()
            {
                return EventApplication::Gap;
            }
            return EventApplication::AlreadyCovered;
        }
        if event.cursor.sequence != current.cursor.sequence.saturating_add(1) {
            return EventApplication::Gap;
        }
        if !event_is_consistent(session, assurance, &current, event) {
            return EventApplication::Gap;
        }
        let Some(event_is_new) =
            record_event_identity(applied_event_ids, event.metadata.message_id)
        else {
            return EventApplication::Gap;
        };
        current.cursor = event.cursor;
        current.as_of = event.metadata.occurred_at;
        if !event_is_new {
            return EventApplication::AlreadyCovered;
        }
        match &event.event {
            ViewEvent::GoalViewChanged(change) => {
                if let Some(goal) = current
                    .goals
                    .iter_mut()
                    .find(|goal| goal.goal_id == change.goal.goal_id)
                {
                    *goal = change.goal.clone();
                } else {
                    current.goals.push(change.goal.clone());
                }
            }
            ViewEvent::RuntimeStatusChanged(RuntimeStatusChanged { runtime }) => {
                current.runtime = runtime.clone();
            }
            ViewEvent::FocusSessionViewChanged(change) => {
                let phase2 = current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state");
                if let Some(focus_session) = phase2
                    .focus_sessions
                    .iter_mut()
                    .find(|value| value.focus_session_id == change.focus_session.focus_session_id)
                {
                    *focus_session = change.focus_session.clone();
                } else {
                    phase2.focus_sessions.push(change.focus_session.clone());
                }
            }
            ViewEvent::CaptureStateChanged(change) => {
                let phase2 = current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state");
                if let Some(capture) = phase2
                    .capture_states
                    .iter_mut()
                    .find(|value| value.focus_session_id == change.capture.focus_session_id)
                {
                    *capture = change.capture.clone();
                } else {
                    phase2.capture_states.push(change.capture.clone());
                }
            }
            ViewEvent::CapabilityHealthChanged(change) => {
                if let Some(capability) = current
                    .capabilities
                    .iter_mut()
                    .find(|value| value.capability == change.capability.capability)
                {
                    *capability = change.capability.clone();
                } else {
                    current.capabilities.push(change.capability.clone());
                }
            }
            ViewEvent::DeliveryChannelViewChanged(change) => {
                let phase2 = current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state");
                if let Some(channel) = phase2
                    .delivery_channels
                    .iter_mut()
                    .find(|value| value.delivery_channel_id == change.channel.delivery_channel_id)
                {
                    *channel = change.channel.clone();
                } else {
                    phase2.delivery_channels.push(change.channel.clone());
                }
            }
            ViewEvent::PermissionViewChanged(change) => {
                let phase2 = current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state");
                if let Some(permission) = phase2
                    .permission_records
                    .iter_mut()
                    .find(|value| permission_records_match(value, &change.permission))
                {
                    *permission = change.permission.clone();
                } else {
                    phase2.permission_records.push(change.permission.clone());
                }
            }
            ViewEvent::InterventionAvailable(change) => {
                upsert_intervention(&mut current, &change.intervention);
            }
            ViewEvent::InterventionViewChanged(change) => {
                upsert_intervention(&mut current, &change.intervention);
            }
            ViewEvent::InterventionHistoryChanged(change) => {
                let history = &mut current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state")
                    .intervention_history;
                history.as_of = event.metadata.occurred_at;
                match change.change {
                    InterventionHistoryChangeKind::Added
                    | InterventionHistoryChangeKind::Updated => {
                        upsert_intervention_entry(
                            &mut history.entries,
                            change
                                .entry
                                .as_ref()
                                .expect("validated history upsert includes an entry"),
                        );
                    }
                    InterventionHistoryChangeKind::Deleted => {
                        history
                            .entries
                            .retain(|entry| entry.intervention_id != change.intervention_id);
                    }
                }
            }
            ViewEvent::GoalDeleted(change) => {
                current
                    .goals
                    .retain(|goal| goal.goal_id != change.tombstone.goal_id);
                if let Some(phase2) = current.phase2.as_deref_mut() {
                    let removed_session_ids: HashSet<_> = phase2
                        .focus_sessions
                        .iter()
                        .filter(|session| session.goal_id == change.tombstone.goal_id)
                        .map(|session| session.focus_session_id)
                        .collect();
                    let removed_resource_ids: HashSet<_> = phase2
                        .permission_records
                        .iter()
                        .filter_map(|record| match record {
                            PermissionRecordView::SessionGrant(grant)
                                if grant.goal_id == change.tombstone.goal_id =>
                            {
                                grant.selected_resource_id
                            }
                            _ => None,
                        })
                        .chain(
                            phase2
                                .focus_sessions
                                .iter()
                                .filter(|session| session.goal_id == change.tombstone.goal_id)
                                .flat_map(|session| session.selected_resource_ids.iter().copied()),
                        )
                        .collect();
                    phase2
                        .focus_sessions
                        .retain(|session| session.goal_id != change.tombstone.goal_id);
                    phase2.permission_records.retain(|record| match record {
                        PermissionRecordView::SessionGrant(grant) => {
                            grant.goal_id != change.tombstone.goal_id
                        }
                        PermissionRecordView::ModelRouteApproval(_) => true,
                    });
                    phase2
                        .capture_states
                        .retain(|capture| !removed_session_ids.contains(&capture.focus_session_id));
                    phase2
                        .intervention_history
                        .entries
                        .retain(|entry| entry.goal_id != change.tombstone.goal_id);
                    phase2.selected_resources.retain(|resource| {
                        !removed_resource_ids.contains(&resource.selected_resource_id)
                            || phase2.permission_records.iter().any(|record| match record {
                                PermissionRecordView::SessionGrant(grant) => {
                                    grant.selected_resource_id
                                        == Some(resource.selected_resource_id)
                                }
                                PermissionRecordView::ModelRouteApproval(_) => false,
                            })
                            || phase2.focus_sessions.iter().any(|session| {
                                session
                                    .selected_resource_ids
                                    .contains(&resource.selected_resource_id)
                            })
                    });
                }
            }
            ViewEvent::SelectedResourceViewChanged(change) => {
                let resources = &mut current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state")
                    .selected_resources;
                if let Some(resource) = &change.resource {
                    if let Some(current) = resources
                        .iter_mut()
                        .find(|value| value.selected_resource_id == resource.selected_resource_id)
                    {
                        *current = resource.clone();
                    } else {
                        resources.push(resource.clone());
                    }
                } else if let Some(tombstone) = &change.tombstone {
                    resources.retain(|resource| {
                        resource.selected_resource_id != tombstone.selected_resource_id
                    });
                }
            }
            ViewEvent::UserPreferencesViewChanged(change) => {
                let phase2 = current
                    .phase2
                    .as_deref_mut()
                    .expect("validated Phase 2 event requires Phase 2 snapshot state");
                phase2.user_preferences = Some(change.preferences.clone());
                phase2.effective_policy = Some(change.effective_policy.clone());
            }
        }
        EventApplication::Applied
    }

    #[cfg(test)]
    async fn apply_event(
        snapshot: &RwLock<ClientSnapshot>,
        session: &SessionOpened,
        assurance: ClientAssurance,
        event: &EventEnvelope,
    ) -> EventApplication {
        apply_event_with_ids(
            snapshot,
            session,
            assurance,
            &StdMutex::new(HashSet::new()),
            event,
        )
        .await
    }

    fn event_is_consistent(
        session: &SessionOpened,
        assurance: ClientAssurance,
        current: &ClientSnapshot,
        event: &EventEnvelope,
    ) -> bool {
        if !event_header_is_consistent(session, assurance, current, event)
            || event.metadata.occurred_at < current.as_of
        {
            return false;
        }

        match &event.event {
            ViewEvent::GoalViewChanged(change) => {
                event.metadata.actor == session.authenticated_actor
                    && event.metadata.actor.kind == ActorKind::LocalOsUser
                    && event
                        .metadata
                        .causation_id
                        .is_some_and(|id| !id.as_uuid().is_nil())
                    && change.goal.owner_id == event.metadata.actor.actor_id
                    && change.goal.revision > 0
                    && change.goal.created_at <= change.goal.updated_at
                    && change.goal.updated_at <= event.metadata.occurred_at
                    && goal_change_matches_state(
                        change.change,
                        change.goal.state,
                        change.goal.revision,
                    )
                    && current
                        .goals
                        .iter()
                        .find(|goal| goal.goal_id == change.goal.goal_id)
                        .is_none_or(|goal| goal.revision <= change.goal.revision)
            }
            ViewEvent::RuntimeStatusChanged(RuntimeStatusChanged { runtime }) => {
                event.metadata.actor.kind == ActorKind::CoreDaemon
                    && event.metadata.actor.actor_id.as_uuid()
                        == session.daemon_instance_id.as_uuid()
                    && runtime.daemon_instance_id == session.daemon_instance_id
                    && runtime.daemon_instance_id == event.cursor.daemon_instance_id
                    && runtime.protocol_version == session.protocol_version
                    && runtime.protocol_version == current.runtime.protocol_version
                    && runtime.build_id == current.runtime.build_id
                    && runtime.started_at <= runtime.observed_at
                    && runtime.observed_at <= event.metadata.occurred_at
            }
            ViewEvent::FocusSessionViewChanged(change) => {
                focus_session_is_consistent(&change.focus_session, event.metadata.occurred_at)
                    && focus_change_matches_state(
                        change.change,
                        change.focus_session.state,
                        change.focus_session.interventions_muted,
                    )
                    && focus_session_relations_are_consistent(current, &change.focus_session)
                    && current.phase2.as_deref().is_some_and(|phase2| {
                        phase2
                            .focus_sessions
                            .iter()
                            .find(|session| {
                                session.focus_session_id == change.focus_session.focus_session_id
                            })
                            .is_none_or(|session| session.revision <= change.focus_session.revision)
                    })
            }
            ViewEvent::CaptureStateChanged(change) => {
                capture_state_is_consistent(&change.capture, event.metadata.occurred_at)
                    && capture_relations_are_consistent(current, &change.capture)
                    && current.phase2.as_deref().is_some_and(|phase2| {
                        phase2
                            .capture_states
                            .iter()
                            .find(|capture| {
                                capture.focus_session_id == change.capture.focus_session_id
                            })
                            .is_none_or(|capture| capture.revision <= change.capture.revision)
                    })
            }
            ViewEvent::CapabilityHealthChanged(change) => {
                capability_health_is_consistent(&change.capability)
            }
            ViewEvent::DeliveryChannelViewChanged(change) => {
                !change.channel.delivery_channel_id.as_uuid().is_nil()
                    && change.channel.observed_at <= event.metadata.occurred_at
                    && current.phase2.as_deref().is_some_and(|phase2| {
                        phase2
                            .delivery_channels
                            .iter()
                            .find(|channel| {
                                channel.delivery_channel_id == change.channel.delivery_channel_id
                            })
                            .is_none_or(|channel| channel.observed_at <= change.channel.observed_at)
                    })
            }
            ViewEvent::PermissionViewChanged(change) => {
                permission_record_is_consistent(
                    session,
                    &change.permission,
                    event.metadata.occurred_at,
                ) && permission_change_matches_state(change.change, &change.permission)
                    && permission_relations_are_consistent(current, &change.permission)
                    && current.phase2.as_deref().is_some_and(|phase2| {
                        phase2
                            .permission_records
                            .iter()
                            .find(|record| permission_records_match(record, &change.permission))
                            .is_none_or(|record| {
                                permission_record_revision(record)
                                    <= permission_record_revision(&change.permission)
                            })
                    })
            }
            ViewEvent::InterventionAvailable(change) => {
                intervention_is_consistent(&change.intervention, event.metadata.occurred_at)
                    && intervention_is_available(&change.intervention)
                    && intervention_relations_are_consistent(current, &change.intervention)
                    && intervention_revision_not_regressed(current, &change.intervention)
            }
            ViewEvent::InterventionViewChanged(change) => {
                intervention_is_consistent(&change.intervention, event.metadata.occurred_at)
                    && intervention_relations_are_consistent(current, &change.intervention)
                    && intervention_revision_not_regressed(current, &change.intervention)
            }
            ViewEvent::InterventionHistoryChanged(change) => match change.change {
                InterventionHistoryChangeKind::Added | InterventionHistoryChangeKind::Updated => {
                    change.entry.as_ref().is_some_and(|entry| {
                        entry.intervention_id == change.intervention_id
                            && intervention_is_consistent(entry, event.metadata.occurred_at)
                            && intervention_relations_are_consistent(current, entry)
                            && intervention_revision_not_regressed(current, entry)
                    })
                }
                InterventionHistoryChangeKind::Deleted => {
                    !change.intervention_id.as_uuid().is_nil() && change.entry.is_none()
                }
            },
            ViewEvent::GoalDeleted(change) => {
                event.metadata.actor == session.authenticated_actor
                    && event.metadata.actor.kind == ActorKind::LocalOsUser
                    && change.tombstone.deleted_revision > 0
                    && change.tombstone.deleted_at <= event.metadata.occurred_at
                    && current.goals.iter().any(|goal| {
                        goal.goal_id == change.tombstone.goal_id
                            && goal.revision == change.tombstone.deleted_revision
                    })
            }
            ViewEvent::SelectedResourceViewChanged(change) => {
                let valid_resource = change.resource.as_ref().is_some_and(|resource| {
                    resource.revision.is_some_and(|revision| revision > 0)
                        && resource
                            .created_at
                            .is_some_and(|created| created <= event.metadata.occurred_at)
                });
                let valid_tombstone = change.tombstone.as_ref().is_some_and(|tombstone| {
                    tombstone.deleted_revision > 0
                        && tombstone.deleted_at <= event.metadata.occurred_at
                });
                matches!(
                    change.change,
                    stein_protocol::SelectedResourceChangeKind::Registered
                ) && valid_resource
                    && change.tombstone.is_none()
                    || matches!(
                        change.change,
                        stein_protocol::SelectedResourceChangeKind::Removed
                    ) && valid_tombstone
                        && change.resource.is_none()
            }
            ViewEvent::UserPreferencesViewChanged(change) => {
                change.preferences.schema_version == 1
                    && change.preferences.revision > 0
                    && change.effective_policy.schema_version == 1
                    && change.effective_policy.user_preferences_revision
                        == change.preferences.revision
            }
        }
    }

    fn event_header_is_consistent(
        session: &SessionOpened,
        assurance: ClientAssurance,
        current: &ClientSnapshot,
        event: &EventEnvelope,
    ) -> bool {
        let kind = event.event.kind();
        matches!(assurance, ClientAssurance::PrivateCapabilityBound)
            && version_at_least(session.protocol_version, kind.minimum_protocol_version())
            && event.metadata.schema_version == stein_protocol::SCHEMA_VERSION_V1
            && !event.metadata.message_id.as_uuid().is_nil()
            && !event.metadata.correlation_id.as_uuid().is_nil()
            && !event.metadata.actor.actor_id.as_uuid().is_nil()
            && event.metadata.origin == Component::CoreApplication
            && event.metadata.sensitivity == kind.sensitivity()
            && event.metadata.retention == kind.retention()
            && event_actor_is_bound(session, &event.metadata.actor)
            && (!version_at_least(kind.minimum_protocol_version(), ProtocolVersion::V1_1)
                || current.phase2.is_some())
    }

    /// Returns `Some(true)` for a new identity, `Some(false)` for a duplicate,
    /// and `None` when the bounded connection-local deduplication set is full.
    /// Exhaustion forces an authoritative reconnect instead of weakening the
    /// duplicate-event guarantee or growing memory without a bound.
    fn record_event_identity(
        applied_event_ids: &StdMutex<HashSet<MessageId>>,
        message_id: MessageId,
    ) -> Option<bool> {
        let mut applied = applied_event_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if applied.contains(&message_id) {
            Some(false)
        } else if applied.len() >= MAX_APPLIED_EVENT_IDENTITIES {
            None
        } else {
            applied.insert(message_id);
            Some(true)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum PermissionRecordKey {
        SessionGrant(PermissionGrantId),
        ModelRouteApproval(ModelRouteApprovalId),
    }

    fn phase2_snapshot_is_consistent(
        session: &SessionOpened,
        snapshot: &ClientSnapshot,
        phase2: &Phase2Snapshot,
    ) -> bool {
        let supports_v1_2 = version_at_least(session.protocol_version, ProtocolVersion::V1_2);
        if supports_v1_2 {
            let Some(device_id) = phase2.current_device_id else {
                return false;
            };
            let Some(identity) = phase2.stein_identity.as_ref() else {
                return false;
            };
            let Some(preferences) = phase2.user_preferences.as_ref() else {
                return false;
            };
            let Some(policy) = phase2.effective_policy.as_ref() else {
                return false;
            };
            if device_id.as_uuid().is_nil()
                || identity.owner_id != session.authenticated_actor.actor_id
                || identity.schema_version != 1
                || identity.revision == 0
                || identity.provenance.recorded_at > snapshot.as_of
                || preferences.owner_id != session.authenticated_actor.actor_id
                || preferences.schema_version != 1
                || preferences.revision == 0
                || preferences.provenance.recorded_at > snapshot.as_of
                || policy.schema_version != 1
                || policy.user_preferences_revision != preferences.revision
            {
                return false;
            }
        } else if phase2.current_device_id.is_some()
            || phase2.stein_identity.is_some()
            || phase2.user_preferences.is_some()
            || phase2.effective_policy.is_some()
        {
            return false;
        }
        let mut selected_resources = HashSet::new();
        if !phase2.selected_resources.iter().all(|resource| {
            !resource.selected_resource_id.as_uuid().is_nil()
                && !resource.display_name.trim().is_empty()
                && if supports_v1_2 {
                    resource.revision.is_some_and(|revision| revision > 0)
                        && resource
                            .created_at
                            .is_some_and(|created| created <= snapshot.as_of)
                } else {
                    resource.revision.is_none() && resource.created_at.is_none()
                }
                && selected_resources.insert(resource.selected_resource_id)
        }) {
            return false;
        }

        let mut permissions = HashSet::new();
        if !phase2.permission_records.iter().all(|record| {
            permission_record_is_consistent(session, record, snapshot.as_of)
                && permissions.insert(permission_record_key(record))
        }) {
            return false;
        }

        let mut focus_sessions = HashSet::new();
        if !phase2.focus_sessions.iter().all(|focus_session| {
            focus_session_is_consistent(focus_session, snapshot.as_of)
                && focus_sessions.insert(focus_session.focus_session_id)
        }) {
            return false;
        }

        let mut capture_states = HashSet::new();
        if !phase2.capture_states.iter().all(|capture| {
            capture_state_is_consistent(capture, snapshot.as_of)
                && capture_states.insert(capture.focus_session_id)
        }) {
            return false;
        }

        let mut delivery_channels = HashSet::new();
        if !phase2.delivery_channels.iter().all(|channel| {
            !channel.delivery_channel_id.as_uuid().is_nil()
                && channel.observed_at <= snapshot.as_of
                && delivery_channels.insert(channel.delivery_channel_id)
        }) {
            return false;
        }

        if phase2.intervention_history.as_of > snapshot.as_of {
            return false;
        }
        if !phase2
            .permission_records
            .iter()
            .all(|record| permission_relations_are_consistent(snapshot, record))
            || !phase2
                .focus_sessions
                .iter()
                .all(|focus| focus_session_relations_are_consistent(snapshot, focus))
            || !phase2
                .capture_states
                .iter()
                .all(|capture| capture_relations_are_consistent(snapshot, capture))
        {
            return false;
        }
        let mut interventions = HashSet::new();
        phase2.intervention_history.entries.iter().all(|entry| {
            intervention_is_consistent(entry, phase2.intervention_history.as_of)
                && intervention_relations_are_consistent(snapshot, entry)
                && interventions.insert(entry.intervention_id)
        })
    }

    fn capability_health_is_consistent(health: &CapabilityHealth) -> bool {
        health.schema_version == stein_protocol::SCHEMA_VERSION_V1
            && match health.state {
                HealthState::Healthy => health.unavailable_reason.is_none(),
                HealthState::Unavailable => health.unavailable_reason.is_some(),
                HealthState::Degraded => true,
            }
    }

    const fn goal_change_matches_state(
        change: GoalChangeKind,
        state: GoalState,
        revision: u64,
    ) -> bool {
        match change {
            GoalChangeKind::Created => {
                revision == 1 && matches!(state, GoalState::Draft | GoalState::Active)
            }
            GoalChangeKind::Updated => matches!(state, GoalState::Draft | GoalState::Active),
            GoalChangeKind::Completed => matches!(state, GoalState::Completed),
            GoalChangeKind::Abandoned => matches!(state, GoalState::Abandoned),
        }
    }

    const fn focus_change_matches_state(
        change: FocusSessionChangeKind,
        state: FocusSessionState,
        interventions_muted: bool,
    ) -> bool {
        match change {
            FocusSessionChangeKind::Requested => {
                matches!(
                    state,
                    FocusSessionState::Requested | FocusSessionState::Starting
                )
            }
            FocusSessionChangeKind::Started | FocusSessionChangeKind::Recovered => {
                matches!(state, FocusSessionState::Active)
            }
            FocusSessionChangeKind::Muted => {
                interventions_muted
                    && !matches!(state, FocusSessionState::Ended | FocusSessionState::Failed)
            }
            FocusSessionChangeKind::Unmuted => {
                !interventions_muted
                    && !matches!(state, FocusSessionState::Ended | FocusSessionState::Failed)
            }
            FocusSessionChangeKind::RecoveryStarted => {
                matches!(state, FocusSessionState::Recovering)
            }
            FocusSessionChangeKind::Stopping => matches!(state, FocusSessionState::Stopping),
            FocusSessionChangeKind::Ended => matches!(state, FocusSessionState::Ended),
            FocusSessionChangeKind::Failed => matches!(state, FocusSessionState::Failed),
        }
    }

    const fn permission_change_matches_state(
        change: PermissionChangeKind,
        record: &PermissionRecordView,
    ) -> bool {
        match record {
            PermissionRecordView::SessionGrant(grant) => match change {
                PermissionChangeKind::Granted => matches!(grant.state, PermissionState::Active),
                PermissionChangeKind::Updated => true,
                PermissionChangeKind::Revoked => matches!(grant.state, PermissionState::Revoked),
                PermissionChangeKind::Expired => matches!(grant.state, PermissionState::Expired),
            },
            PermissionRecordView::ModelRouteApproval(approval) => match change {
                PermissionChangeKind::Granted => {
                    matches!(approval.state, ModelRouteApprovalState::Active)
                }
                PermissionChangeKind::Updated => true,
                PermissionChangeKind::Revoked => {
                    matches!(approval.state, ModelRouteApprovalState::Revoked)
                }
                PermissionChangeKind::Expired => {
                    matches!(approval.state, ModelRouteApprovalState::Expired)
                }
            },
        }
    }

    fn intervention_is_available(intervention: &InterventionView) -> bool {
        intervention
            .user_visible_text
            .as_deref()
            .is_some_and(|text| !text.trim().is_empty())
            && matches!(
                intervention.state,
                InterventionState::Allowed
                    | InterventionState::Queued
                    | InterventionState::Delivering
                    | InterventionState::AcceptedByChannel
                    | InterventionState::DeliveryUnknown
            )
    }

    fn focus_session_is_consistent(
        focus_session: &FocusSessionView,
        boundary: UtcTimestamp,
    ) -> bool {
        !focus_session.focus_session_id.as_uuid().is_nil()
            && !focus_session.goal_id.as_uuid().is_nil()
            && !focus_session.model_route_approval_id.as_uuid().is_nil()
            && focus_session.revision > 0
            && focus_session.goal_revision > 0
            && focus_session.created_at <= focus_session.updated_at
            && focus_session.updated_at <= boundary
            && focus_session
                .started_at
                .is_none_or(|started| started >= focus_session.created_at && started <= boundary)
            && focus_session
                .ended_at
                .is_none_or(|ended| ended >= focus_session.created_at && ended <= boundary)
            && unique_non_nil(
                focus_session
                    .permission_grant_ids
                    .iter()
                    .map(|id| *id.as_uuid()),
            )
            && unique_non_nil(
                focus_session
                    .selected_resource_ids
                    .iter()
                    .map(|id| *id.as_uuid()),
            )
    }

    fn capture_state_is_consistent(capture: &CaptureStateView, boundary: UtcTimestamp) -> bool {
        if capture.focus_session_id.as_uuid().is_nil()
            || capture.revision == 0
            || capture.updated_at > boundary
        {
            return false;
        }
        let mut categories = HashSet::new();
        if !capture
            .active_categories
            .iter()
            .all(|category| categories.insert(*category))
        {
            return false;
        }
        let mut sources = HashSet::new();
        capture.sources.iter().all(|source| {
            !source.observation_source_id.as_uuid().is_nil()
                && source
                    .selected_resource_id
                    .is_none_or(|id| !id.as_uuid().is_nil())
                && source
                    .last_complete_at
                    .is_none_or(|completed| completed <= boundary)
                && sources.insert(source.observation_source_id)
        })
    }

    fn permission_record_key(record: &PermissionRecordView) -> PermissionRecordKey {
        match record {
            PermissionRecordView::SessionGrant(grant) => {
                PermissionRecordKey::SessionGrant(grant.permission_grant_id)
            }
            PermissionRecordView::ModelRouteApproval(approval) => {
                PermissionRecordKey::ModelRouteApproval(approval.model_route_approval_id)
            }
        }
    }

    fn permission_records_match(left: &PermissionRecordView, right: &PermissionRecordView) -> bool {
        permission_record_key(left) == permission_record_key(right)
    }

    const fn permission_record_revision(record: &PermissionRecordView) -> u64 {
        match record {
            PermissionRecordView::SessionGrant(grant) => grant.revision,
            PermissionRecordView::ModelRouteApproval(approval) => approval.revision,
        }
    }

    fn permission_record_is_consistent(
        session: &SessionOpened,
        record: &PermissionRecordView,
        boundary: UtcTimestamp,
    ) -> bool {
        match record {
            PermissionRecordView::SessionGrant(grant) => {
                !grant.permission_grant_id.as_uuid().is_nil()
                    && !grant.requested_by_client.as_uuid().is_nil()
                    && !grant.device_id.as_uuid().is_nil()
                    && !grant.goal_id.as_uuid().is_nil()
                    && grant
                        .focus_session_id
                        .is_none_or(|id| !id.as_uuid().is_nil())
                    && grant
                        .selected_resource_id
                        .is_none_or(|id| !id.as_uuid().is_nil())
                    && grant.owner_id == session.authenticated_actor.actor_id
                    && grant.revision > 0
                    && !grant.purpose.trim().is_empty()
                    && !grant.consent_copy_version.trim().is_empty()
                    && grant.effective_at <= grant.expires_at
                    && grant.effective_at <= boundary
                    && grant
                        .revoked_at
                        .is_none_or(|revoked| revoked >= grant.effective_at && revoked <= boundary)
                    && grant.revoked_at.is_some() == grant.revocation_reason.is_some()
                    && grant.sensitivity == SensitivityClass::Sensitive
                    && grant.retention == RetentionClass::DurableUntilExpiry
            }
            PermissionRecordView::ModelRouteApproval(approval) => {
                let mut categories = HashSet::new();
                !approval.model_route_approval_id.as_uuid().is_nil()
                    && approval.owner_id == session.authenticated_actor.actor_id
                    && approval.revision > 0
                    && !approval.route.provider_id.trim().is_empty()
                    && !approval.route.route_id.trim().is_empty()
                    && !approval.account_profile.trim().is_empty()
                    && !approval.purpose.trim().is_empty()
                    && !approval.disclosure_version.trim().is_empty()
                    && approval.maximum_request_tokens > 0
                    && !approval.allowed_data_categories.is_empty()
                    && approval
                        .allowed_data_categories
                        .iter()
                        .all(|category| categories.insert(*category))
                    && approval.effective_at <= boundary
                    && approval
                        .expires_at
                        .is_none_or(|expires| expires >= approval.effective_at)
                    && approval.revoked_at.is_none_or(|revoked| {
                        revoked >= approval.effective_at && revoked <= boundary
                    })
            }
        }
    }

    fn intervention_is_consistent(intervention: &InterventionView, boundary: UtcTimestamp) -> bool {
        let mut reasons = HashSet::new();
        !intervention.intervention_id.as_uuid().is_nil()
            && !intervention.focus_session_id.as_uuid().is_nil()
            && !intervention.goal_id.as_uuid().is_nil()
            && intervention
                .delivery_channel_id
                .is_none_or(|id| !id.as_uuid().is_nil())
            && intervention.revision > 0
            && intervention.candidate_revision > 0
            && intervention.created_at <= intervention.updated_at
            && intervention.updated_at <= boundary
            && intervention.created_at <= intervention.expires_at
            && !intervention.reason_codes.is_empty()
            && intervention
                .reason_codes
                .iter()
                .all(|reason| reasons.insert(*reason))
            && intervention.sensitivity == SensitivityClass::Personal
            && intervention.retention == RetentionClass::BoundedAudit
    }

    fn intervention_revision_not_regressed(
        snapshot: &ClientSnapshot,
        intervention: &InterventionView,
    ) -> bool {
        snapshot.phase2.as_deref().is_some_and(|phase2| {
            phase2
                .intervention_history
                .entries
                .iter()
                .find(|entry| entry.intervention_id == intervention.intervention_id)
                .is_none_or(|entry| entry.revision <= intervention.revision)
        })
    }

    fn permission_relations_are_consistent(
        snapshot: &ClientSnapshot,
        record: &PermissionRecordView,
    ) -> bool {
        let PermissionRecordView::SessionGrant(grant) = record else {
            return true;
        };
        snapshot
            .goals
            .iter()
            .any(|goal| goal.goal_id == grant.goal_id)
            && grant.selected_resource_id.is_none_or(|resource_id| {
                snapshot.phase2.as_deref().is_some_and(|phase2| {
                    phase2
                        .selected_resources
                        .iter()
                        .any(|resource| resource.selected_resource_id == resource_id)
                })
            })
            && grant.focus_session_id.is_none_or(|focus_session_id| {
                snapshot.phase2.as_deref().is_some_and(|phase2| {
                    phase2
                        .focus_sessions
                        .iter()
                        .any(|focus| focus.focus_session_id == focus_session_id)
                })
            })
    }

    fn focus_session_relations_are_consistent(
        snapshot: &ClientSnapshot,
        focus: &FocusSessionView,
    ) -> bool {
        snapshot
            .goals
            .iter()
            .any(|goal| goal.goal_id == focus.goal_id)
            && snapshot.phase2.as_deref().is_some_and(|phase2| {
                phase2.permission_records.iter().any(|record| {
                    matches!(
                        record,
                        PermissionRecordView::ModelRouteApproval(approval)
                            if approval.model_route_approval_id == focus.model_route_approval_id
                    )
                }) && focus.permission_grant_ids.iter().all(|grant_id| {
                    phase2.permission_records.iter().any(|record| {
                        matches!(
                            record,
                            PermissionRecordView::SessionGrant(grant)
                                if grant.permission_grant_id == *grant_id
                        )
                    })
                }) && focus.selected_resource_ids.iter().all(|resource_id| {
                    phase2
                        .selected_resources
                        .iter()
                        .any(|resource| resource.selected_resource_id == *resource_id)
                })
            })
    }

    fn capture_relations_are_consistent(
        snapshot: &ClientSnapshot,
        capture: &CaptureStateView,
    ) -> bool {
        snapshot.phase2.as_deref().is_some_and(|phase2| {
            phase2
                .focus_sessions
                .iter()
                .any(|focus| focus.focus_session_id == capture.focus_session_id)
                && capture.sources.iter().all(|source| {
                    source.selected_resource_id.is_none_or(|resource_id| {
                        phase2
                            .selected_resources
                            .iter()
                            .any(|resource| resource.selected_resource_id == resource_id)
                    })
                })
        })
    }

    fn intervention_relations_are_consistent(
        snapshot: &ClientSnapshot,
        intervention: &InterventionView,
    ) -> bool {
        snapshot
            .goals
            .iter()
            .any(|goal| goal.goal_id == intervention.goal_id)
            && snapshot.phase2.as_deref().is_some_and(|phase2| {
                phase2
                    .focus_sessions
                    .iter()
                    .any(|focus| focus.focus_session_id == intervention.focus_session_id)
                    && intervention.delivery_channel_id.is_none_or(|channel_id| {
                        phase2
                            .delivery_channels
                            .iter()
                            .any(|channel| channel.delivery_channel_id == channel_id)
                    })
            })
    }

    fn unique_non_nil(mut values: impl Iterator<Item = uuid::Uuid>) -> bool {
        let mut seen = HashSet::new();
        values.all(|value| !value.is_nil() && seen.insert(value))
    }

    fn event_actor_is_bound(session: &SessionOpened, actor: &ActorReference) -> bool {
        match actor.kind {
            ActorKind::LocalOsUser => actor == &session.authenticated_actor,
            ActorKind::CoreDaemon => {
                actor.actor_id.as_uuid() == session.daemon_instance_id.as_uuid()
            }
            ActorKind::System => !actor.actor_id.as_uuid().is_nil(),
            ActorKind::Client => false,
        }
    }

    fn upsert_intervention(snapshot: &mut ClientSnapshot, intervention: &InterventionView) {
        let as_of = snapshot.as_of;
        let history = &mut snapshot
            .phase2
            .as_deref_mut()
            .expect("validated Phase 2 event requires Phase 2 snapshot state")
            .intervention_history;
        history.as_of = as_of;
        upsert_intervention_entry(&mut history.entries, intervention);
    }

    fn upsert_intervention_entry(
        entries: &mut Vec<InterventionView>,
        intervention: &InterventionView,
    ) {
        if let Some(existing) = entries
            .iter_mut()
            .find(|entry| entry.intervention_id == intervention.intervention_id)
        {
            *existing = intervention.clone();
        } else {
            entries.push(intervention.clone());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn requested_focus_event_accepts_the_persisted_starting_state() {
            assert!(focus_change_matches_state(
                FocusSessionChangeKind::Requested,
                FocusSessionState::Requested,
                false,
            ));
            assert!(focus_change_matches_state(
                FocusSessionChangeKind::Requested,
                FocusSessionState::Starting,
                false,
            ));
            assert!(!focus_change_matches_state(
                FocusSessionChangeKind::Requested,
                FocusSessionState::Active,
                false,
            ));
        }

        fn fixture_session() -> (ClientHello, SessionOpened) {
            let client: ClientMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/client-open-session.json"
            ))
            .expect("client fixture must decode");
            let server: ServerMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/server-session-opened.json"
            ))
            .expect("server fixture must decode");
            let ClientMessage::OpenSession(hello) = client else {
                panic!("fixture must be OpenSession");
            };
            let ServerMessage::SessionOpened(opened) = server else {
                panic!("fixture must be SessionOpened");
            };
            (hello, opened)
        }

        fn fixture_inner(
            session: SessionOpened,
        ) -> (Arc<ClientInner>, mpsc::Receiver<ClientMessage>) {
            fixture_inner_with_assurance(session, ClientAssurance::PrivateCapabilityBound)
        }

        fn fixture_inner_with_assurance(
            session: SessionOpened,
            assurance: ClientAssurance,
        ) -> (Arc<ClientInner>, mpsc::Receiver<ClientMessage>) {
            let (writer, messages) = mpsc::channel(4);
            let (events, initial_events) = broadcast::channel(4);
            let inner = Arc::new(ClientInner {
                snapshot: RwLock::new(session.snapshot.clone()),
                session,
                assurance,
                origin: Component::TestFixture,
                writer,
                pending: Mutex::new(HashMap::new()),
                cancellation_waiters: Mutex::new(HashMap::new()),
                terminal_failure: StdMutex::new(None),
                applied_event_ids: StdMutex::new(HashSet::new()),
                events,
                initial_events: StdMutex::new(Some(initial_events)),
                closed: CancellationToken::new(),
            });
            (inner, messages)
        }

        fn fixture_phase2_session() -> (ClientHello, SessionOpened) {
            let client: ClientMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/client-open-session-v1-1.json"
            ))
            .expect("Phase 2 client fixture must decode");
            let server: ServerMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/server-session-opened-v1-1.json"
            ))
            .expect("Phase 2 server fixture must decode");
            let ClientMessage::OpenSession(hello) = client else {
                panic!("fixture must be OpenSession");
            };
            let ServerMessage::SessionOpened(opened) = server else {
                panic!("fixture must be SessionOpened");
            };
            (hello, opened)
        }

        fn fixture_phase2_session_v1_2() -> SessionOpened {
            let (_, mut session) = fixture_phase2_session();
            let responses: Vec<ResponseBody> = serde_json::from_str(include_str!(
                "../../../contracts/v1/phase2-response-bodies.json"
            ))
            .expect("Phase 2 response fixtures must decode");
            let phase2 = session
                .snapshot
                .phase2
                .as_deref_mut()
                .expect("Phase 2 snapshot must exist");
            phase2.current_device_id = phase2.permission_records.iter().find_map(|record| {
                if let PermissionRecordView::SessionGrant(grant) = record {
                    Some(grant.device_id)
                } else {
                    None
                }
            });
            for response in responses {
                match response {
                    ResponseBody::GetSteinIdentity(response) => {
                        phase2.stein_identity = Some(response.identity);
                    }
                    ResponseBody::GetUserPreferences(response) => {
                        phase2.user_preferences = Some(response.preferences);
                    }
                    ResponseBody::GetEffectivePolicy(response) => {
                        phase2.effective_policy = Some(response.effective_policy);
                    }
                    ResponseBody::GetSelectedResources(response) => {
                        phase2.selected_resources = response.resources;
                    }
                    _ => {}
                }
            }
            session.protocol_version = ProtocolVersion::V1_2;
            session.snapshot.runtime.protocol_version = ProtocolVersion::V1_2;
            session.snapshot.as_of = serde_json::from_str("\"2026-08-19T15:00:00Z\"").unwrap();
            session
                .snapshot
                .goals
                .first_mut()
                .expect("Phase 2 snapshot must include its goal")
                .revision = 3;
            session
        }

        fn fixture_phase2_request(kind: RequestKind) -> RequestBody {
            let requests: Vec<RequestBody> = serde_json::from_str(include_str!(
                "../../../contracts/v1/phase2-request-bodies.json"
            ))
            .expect("Phase 2 request fixtures must decode");
            requests
                .into_iter()
                .find(|request| request.kind() == kind)
                .expect("every Phase 2 request kind has a golden fixture")
        }

        fn phase2_envelope(session: &SessionOpened, event: ViewEvent) -> EventEnvelope {
            let occurred_at: UtcTimestamp =
                serde_json::from_str("\"2026-08-19T15:00:00Z\"").unwrap();
            EventEnvelope {
                cursor: session.snapshot.cursor.next(),
                metadata: stein_protocol::EventMetadata {
                    message_id: MessageId::new_v7(),
                    schema_version: stein_protocol::SCHEMA_VERSION_V1,
                    occurred_at,
                    correlation_id: stein_protocol::CorrelationId::new_v7(),
                    causation_id: Some(MessageId::new_v7()),
                    actor: session.authenticated_actor.clone(),
                    origin: Component::CoreApplication,
                    sensitivity: event.kind().sensitivity(),
                    retention: event.kind().retention(),
                    trace_context: None,
                },
                event,
            }
        }

        #[test]
        fn validates_authoritative_handshake_and_rejects_inconsistent_basics() {
            let (hello, opened) = fixture_session();
            validate_session_opened(&hello, &opened, ClientAssurance::PrivateCapabilityBound)
                .expect("golden handshake must be valid");

            let mut invalid_limit = opened.clone();
            invalid_limit.max_frame_bytes = 0;
            assert!(
                validate_session_opened(
                    &hello,
                    &invalid_limit,
                    ClientAssurance::PrivateCapabilityBound,
                )
                .is_err()
            );

            let mut duplicate = opened.clone();
            let repeated = duplicate.snapshot.capabilities[0].clone();
            duplicate.snapshot.capabilities.push(repeated.clone());
            duplicate.capabilities.push(repeated);
            assert!(
                validate_session_opened(
                    &hello,
                    &duplicate,
                    ClientAssurance::PrivateCapabilityBound,
                )
                .is_err()
            );

            let mut wrong_daemon = opened;
            wrong_daemon.snapshot.cursor.daemon_instance_id =
                stein_protocol::DaemonInstanceId::new_v7();
            assert!(
                validate_session_opened(
                    &hello,
                    &wrong_daemon,
                    ClientAssurance::PrivateCapabilityBound,
                )
                .is_err()
            );
        }

        #[test]
        fn client_protocol_advertisement_cannot_exceed_implemented_minor_versions() {
            validate_protocol_support(ProtocolSupport::V1)
                .expect("the complete implemented range is valid");
            validate_protocol_support(ProtocolSupport::V1_0)
                .expect("an exact legacy range is valid");
            validate_protocol_support(ProtocolSupport::V1_1)
                .expect("an exact current range is valid");

            assert!(
                validate_protocol_support(ProtocolSupport {
                    major: ProtocolSupport::V1.major,
                    minimum_minor: 0,
                    maximum_minor: ProtocolSupport::V1.maximum_minor + 1,
                })
                .is_err()
            );
            assert!(
                validate_protocol_support(ProtocolSupport {
                    major: ProtocolSupport::V1.major + 1,
                    minimum_minor: 0,
                    maximum_minor: 0,
                })
                .is_err()
            );
            assert!(
                validate_protocol_support(ProtocolSupport {
                    major: ProtocolSupport::V1.major,
                    minimum_minor: 1,
                    maximum_minor: 0,
                })
                .is_err()
            );
        }

        #[test]
        fn validates_phase2_snapshots_and_rejects_them_for_diagnostic_or_v1_0_sessions() {
            let (hello, opened) = fixture_phase2_session();
            validate_session_opened(&hello, &opened, ClientAssurance::PrivateCapabilityBound)
                .expect("the authoritative Phase 2 fixture is internally consistent");

            assert!(
                validate_session_opened(&hello, &opened, ClientAssurance::Diagnostic).is_err(),
                "a diagnostic handshake must never accept private snapshot state"
            );

            let mut redacted = opened.clone();
            redacted.snapshot.goals.clear();
            redacted.snapshot.phase2 = None;
            redacted.snapshot.cursor.sequence = 0;
            validate_session_opened(&hello, &redacted, ClientAssurance::Diagnostic)
                .expect("content-free protocol 1.1 snapshot is valid for diagnostics");

            let mut missing_phase2 = opened.clone();
            missing_phase2.snapshot.phase2 = None;
            assert!(
                validate_session_opened(
                    &hello,
                    &missing_phase2,
                    ClientAssurance::PrivateCapabilityBound,
                )
                .is_err(),
                "a private protocol 1.1 snapshot must carry authoritative Phase 2 state"
            );

            let mut legacy = opened;
            legacy.protocol_version = ProtocolVersion::V1_0;
            legacy.snapshot.runtime.protocol_version = ProtocolVersion::V1_0;
            assert!(
                !snapshot_is_consistent(
                    &legacy,
                    ClientAssurance::PrivateCapabilityBound,
                    &legacy.snapshot,
                ),
                "protocol 1.0 must reject an additive Phase 2 snapshot"
            );
        }

        #[test]
        fn protocol_1_0_snapshots_reject_capabilities_introduced_in_1_1() {
            let (hello, mut opened) = fixture_session();
            let health = CapabilityHealth {
                capability: stein_protocol::CapabilityId::FocusSessions,
                schema_version: stein_protocol::SCHEMA_VERSION_V1,
                state: HealthState::Healthy,
                unavailable_reason: None,
            };
            opened.capabilities.push(health.clone());
            opened.snapshot.capabilities.push(health);

            assert!(
                validate_session_opened(&hello, &opened, ClientAssurance::PrivateCapabilityBound)
                    .is_err()
            );
        }

        #[test]
        fn phase2_snapshots_reject_dangling_private_references() {
            let (_, session) = fixture_phase2_session();
            let mut dangling_goal = session.snapshot.clone();
            dangling_goal.phase2.as_deref_mut().unwrap().focus_sessions[0].goal_id =
                stein_protocol::GoalId::new_v7();
            assert!(!snapshot_is_consistent(
                &session,
                ClientAssurance::PrivateCapabilityBound,
                &dangling_goal,
            ));

            let mut dangling_resource = session.snapshot.clone();
            dangling_resource
                .phase2
                .as_deref_mut()
                .unwrap()
                .capture_states[0]
                .sources[0]
                .selected_resource_id = Some(stein_protocol::SelectedResourceId::new_v7());
            assert!(!snapshot_is_consistent(
                &session,
                ClientAssurance::PrivateCapabilityBound,
                &dangling_resource,
            ));
        }

        #[test]
        fn request_classification_and_protocol_minima_are_exhaustive() {
            for kind in RequestKind::ALL {
                assert_eq!(
                    request_sensitivity(kind, ProtocolVersion::V1_1),
                    kind.sensitivity()
                );
                assert_eq!(
                    request_allowed(ClientAssurance::Diagnostic, kind),
                    matches!(
                        kind,
                        RequestKind::GetRuntimeStatus | RequestKind::GetCapabilityHealth
                    )
                );
                assert!(request_allowed(
                    ClientAssurance::PrivateCapabilityBound,
                    kind
                ));
            }
            assert_eq!(
                request_sensitivity(RequestKind::GetSnapshot, ProtocolVersion::V1_0),
                SensitivityClass::Personal
            );
        }

        #[tokio::test]
        async fn diagnostic_client_rejects_private_requests_before_the_writer_queue() {
            let (_, session) = fixture_session();
            let (inner, mut messages) =
                fixture_inner_with_assurance(session, ClientAssurance::Diagnostic);
            let client = Client {
                owner: Arc::new(ClientOwner { inner }),
            };

            assert!(matches!(
                client.get_client_snapshot().await,
                Err(ClientError::PrivateCapabilityRequired)
            ));
            assert!(messages.try_recv().is_err());
        }

        #[tokio::test]
        async fn phase2_client_methods_preserve_revision_and_idempotency_metadata() {
            let (_, session) = fixture_phase2_session();
            let (inner, mut messages) = fixture_inner(session);
            let client = Client {
                owner: Arc::new(ClientOwner {
                    inner: inner.clone(),
                }),
            };
            let update = fixture_phase2_request(RequestKind::UpdateGoal);
            let RequestBody::UpdateGoal(update) = update else {
                panic!("fixture must be UpdateGoal");
            };
            let expected_update = update.clone();
            let update_client = client.clone();
            let update_task = tokio::spawn(async move { update_client.update_goal(*update).await });
            let update_message = messages.recv().await.expect("update request queued");
            let ClientMessage::Request(update_message) = update_message else {
                panic!("expected request message");
            };
            assert_eq!(
                update_message.body,
                RequestBody::UpdateGoal(expected_update)
            );
            assert_eq!(
                update_message.metadata.sensitivity,
                SensitivityClass::Personal
            );
            assert!(update_message.metadata.idempotency_key.is_none());
            update_task.abort();
            let _ = update_task.await;

            let start = fixture_phase2_request(RequestKind::StartFocusSession);
            let RequestBody::StartFocusSession(start) = start else {
                panic!("fixture must be StartFocusSession");
            };
            let expected_start = start.clone();
            let key = IdempotencyKey::new_v7();
            let start_client = client;
            let start_task =
                tokio::spawn(async move { start_client.start_focus_session(*start, key).await });
            let start_message = messages.recv().await.expect("start request queued");
            let ClientMessage::Request(start_message) = start_message else {
                panic!("expected request message");
            };
            assert_eq!(
                start_message.body,
                RequestBody::StartFocusSession(expected_start)
            );
            assert_eq!(start_message.metadata.idempotency_key, Some(key));
            assert_eq!(
                start_message.metadata.sensitivity,
                SensitivityClass::Restricted
            );
            start_task.abort();
            let _ = start_task.await;
        }

        #[tokio::test]
        async fn phase2_methods_fail_locally_when_only_protocol_1_0_was_negotiated() {
            let (_, session) = fixture_session();
            let (inner, mut messages) = fixture_inner(session);
            let update = fixture_phase2_request(RequestKind::UpdateGoal);
            let RequestBody::UpdateGoal(update) = update else {
                panic!("fixture must be UpdateGoal");
            };
            let client = Client {
                owner: Arc::new(ClientOwner { inner }),
            };

            assert!(matches!(
                client.update_goal(*update).await,
                Err(ClientError::UnsupportedProtocol {
                    required: ProtocolVersion::V1_1,
                    negotiated: ProtocolVersion::V1_0,
                })
            ));
            assert!(messages.try_recv().is_err());
        }

        #[tokio::test]
        async fn open_subscription_pairs_a_snapshot_with_a_no_gap_receiver() {
            let (_, session) = fixture_phase2_session();
            let (inner, _messages) = fixture_inner(session.clone());
            let client = Client {
                owner: Arc::new(ClientOwner {
                    inner: inner.clone(),
                }),
            };
            let mut subscription = client
                .open_subscription()
                .await
                .expect("private client may subscribe");
            assert_eq!(subscription.snapshot, session.snapshot);

            let message: ServerMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/server-focus-session-event.json"
            ))
            .expect("event fixture must decode");
            let ServerMessage::Event(event) = message else {
                panic!("fixture must be Event");
            };
            inner.events.send(event.clone()).unwrap();
            assert_eq!(subscription.events.recv().await.unwrap(), event);

            let (diagnostic_inner, _messages) =
                fixture_inner_with_assurance(session, ClientAssurance::Diagnostic);
            let diagnostic = Client {
                owner: Arc::new(ClientOwner {
                    inner: diagnostic_inner,
                }),
            };
            assert!(matches!(
                diagnostic.open_subscription().await,
                Err(ClientError::PrivateCapabilityRequired)
            ));
        }

        #[tokio::test]
        async fn every_phase2_view_event_applies_to_the_authoritative_cache() {
            let session = fixture_phase2_session_v1_2();
            let events: Vec<ViewEvent> = serde_json::from_str(include_str!(
                "../../../contracts/v1/phase2-view-events.json"
            ))
            .expect("Phase 2 event fixture must decode");
            let fixture_kinds = events.iter().map(ViewEvent::kind).collect::<HashSet<_>>();
            let phase2_kinds = stein_protocol::ViewEventKind::ALL
                .into_iter()
                .filter(|kind| {
                    !version_at_least(ProtocolVersion::V1_0, kind.minimum_protocol_version())
                })
                .collect::<HashSet<_>>();
            assert_eq!(fixture_kinds, phase2_kinds);

            for event in events {
                let snapshot = RwLock::new(session.snapshot.clone());
                let envelope = phase2_envelope(&session, event);
                let kind = envelope.event.kind();

                assert_eq!(
                    apply_event(
                        &snapshot,
                        &session,
                        ClientAssurance::PrivateCapabilityBound,
                        &envelope,
                    )
                    .await,
                    EventApplication::Applied,
                    "{kind:?} fixture did not apply"
                );
                let applied = snapshot.read().await;
                assert_eq!(applied.cursor, envelope.cursor);
                assert!(snapshot_is_consistent(
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &applied,
                ));
            }
        }

        #[tokio::test]
        async fn contradictory_event_tags_and_states_require_a_reconnect() {
            let (_, phase2_session) = fixture_phase2_session();
            let events: Vec<ViewEvent> = serde_json::from_str(include_str!(
                "../../../contracts/v1/phase2-view-events.json"
            ))
            .expect("Phase 2 event fixture must decode");

            let mut focus = events
                .iter()
                .find(|event| matches!(event, ViewEvent::FocusSessionViewChanged(_)))
                .unwrap()
                .clone();
            let ViewEvent::FocusSessionViewChanged(change) = &mut focus else {
                unreachable!()
            };
            change.change = FocusSessionChangeKind::Ended;

            let mut permission = events
                .iter()
                .find(|event| matches!(event, ViewEvent::PermissionViewChanged(_)))
                .unwrap()
                .clone();
            let ViewEvent::PermissionViewChanged(change) = &mut permission else {
                unreachable!()
            };
            change.change = PermissionChangeKind::Revoked;

            let mut available = events
                .iter()
                .find(|event| matches!(event, ViewEvent::InterventionAvailable(_)))
                .unwrap()
                .clone();
            let ViewEvent::InterventionAvailable(change) = &mut available else {
                unreachable!()
            };
            change.intervention.state = InterventionState::Denied;

            for event in [focus, permission, available] {
                assert_eq!(
                    apply_event(
                        &RwLock::new(phase2_session.snapshot.clone()),
                        &phase2_session,
                        ClientAssurance::PrivateCapabilityBound,
                        &phase2_envelope(&phase2_session, event),
                    )
                    .await,
                    EventApplication::Gap,
                );
            }

            let (_, legacy_session) = fixture_session();
            let message: ServerMessage =
                serde_json::from_str(include_str!("../../../contracts/v1/server-goal-event.json"))
                    .expect("event fixture must decode");
            let ServerMessage::Event(mut event) = message else {
                panic!("fixture must be Event");
            };
            let ViewEvent::GoalViewChanged(change) = &mut event.event else {
                panic!("fixture must be GoalViewChanged");
            };
            change.change = GoalChangeKind::Completed;
            assert_eq!(
                apply_event(
                    &RwLock::new(legacy_session.snapshot.clone()),
                    &legacy_session,
                    ClientAssurance::PrivateCapabilityBound,
                    &event,
                )
                .await,
                EventApplication::Gap,
            );
        }

        #[tokio::test]
        async fn intervention_history_delete_removes_the_cached_entry() {
            let (_, session) = fixture_phase2_session();
            let intervention_id = session
                .snapshot
                .phase2
                .as_deref()
                .unwrap()
                .intervention_history
                .entries[0]
                .intervention_id;
            let occurred_at: UtcTimestamp =
                serde_json::from_str("\"2026-08-19T15:00:00Z\"").unwrap();
            let envelope = EventEnvelope {
                cursor: session.snapshot.cursor.next(),
                metadata: stein_protocol::EventMetadata {
                    message_id: stein_protocol::MessageId::new_v7(),
                    schema_version: stein_protocol::SCHEMA_VERSION_V1,
                    occurred_at,
                    correlation_id: stein_protocol::CorrelationId::new_v7(),
                    causation_id: Some(stein_protocol::MessageId::new_v7()),
                    actor: session.authenticated_actor.clone(),
                    origin: Component::CoreApplication,
                    sensitivity: SensitivityClass::Personal,
                    retention: RetentionClass::Runtime,
                    trace_context: None,
                },
                event: ViewEvent::InterventionHistoryChanged(
                    stein_protocol::InterventionHistoryChanged {
                        change: InterventionHistoryChangeKind::Deleted,
                        intervention_id,
                        entry: None,
                    },
                ),
            };
            let snapshot = RwLock::new(session.snapshot.clone());
            assert_eq!(
                apply_event(
                    &snapshot,
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &envelope,
                )
                .await,
                EventApplication::Applied
            );
            assert!(
                snapshot
                    .read()
                    .await
                    .phase2
                    .as_deref()
                    .unwrap()
                    .intervention_history
                    .entries
                    .is_empty()
            );
        }

        #[test]
        fn only_the_last_client_handle_closes_the_connection() {
            let (_, session) = fixture_session();
            let (inner, _messages) = fixture_inner(session);
            let first = Client {
                owner: Arc::new(ClientOwner {
                    inner: inner.clone(),
                }),
            };
            let second = first.clone();

            drop(first);
            assert!(!inner.closed.is_cancelled());
            drop(second);
            assert!(inner.closed.is_cancelled());
        }

        #[tokio::test]
        async fn terminal_paths_fail_every_pending_waiter_with_the_same_reason() {
            let (_, session) = fixture_session();
            let (inner, _messages) = fixture_inner(session);
            let request_id = RequestId::new_v7();
            let cancellation_id = CancellationId::new_v7();
            let (response_send, response_receive) = oneshot::channel();
            let (cancel_send, cancel_receive) = oneshot::channel();
            inner.pending.lock().await.insert(request_id, response_send);
            inner.cancellation_waiters.lock().await.insert(
                cancellation_id,
                CancellationWaiter {
                    target_request_id: request_id,
                    correlation_id: stein_protocol::CorrelationId::new_v7(),
                    causation_id: stein_protocol::MessageId::new_v7(),
                    sender: cancel_send,
                },
            );

            terminate(&inner, PendingFailure::EventGap).await;

            assert_eq!(
                response_receive.await.expect("response waiter notified"),
                Err(PendingFailure::EventGap)
            );
            assert_eq!(
                cancel_receive.await.expect("cancel waiter notified"),
                Err(PendingFailure::EventGap)
            );
            assert!(inner.pending.lock().await.is_empty());
            assert!(inner.cancellation_waiters.lock().await.is_empty());
            assert!(matches!(
                terminal_client_error(&inner),
                ClientError::EventGap
            ));
        }

        #[tokio::test]
        async fn phase2_source_fixture_phase1_regression_requires_confirmed_client_cancellation() {
            async fn begin_cancelled_request(
                client: Client,
                messages: &mut mpsc::Receiver<ClientMessage>,
                cancellation: &CancellationToken,
            ) -> (
                tokio::task::JoinHandle<Result<DelayEchoResponse, ClientError>>,
                RequestEnvelope,
                CancelRequest,
            ) {
                let request_cancellation = cancellation.clone();
                let request = tokio::spawn(async move {
                    client
                        .delay_echo(3_000, "synthetic", Some(request_cancellation))
                        .await
                });
                let ClientMessage::Request(envelope) = messages
                    .recv()
                    .await
                    .expect("delay request must enter the writer queue")
                else {
                    panic!("expected delay request");
                };
                cancellation.cancel();
                let ClientMessage::Cancel(cancel) = messages
                    .recv()
                    .await
                    .expect("cancellation must enter the writer queue")
                else {
                    panic!("expected cancellation request");
                };
                assert_eq!(cancel.target_request_id, envelope.request_id);
                assert_eq!(
                    Some(cancel.cancellation_id),
                    envelope.metadata.cancellation_id
                );
                assert_eq!(cancel.correlation_id, envelope.metadata.correlation_id);
                (request, envelope, cancel)
            }

            fn terminal_cancelled_response(
                request: &RequestEnvelope,
                actor: ActorReference,
            ) -> ResponseEnvelope {
                ResponseEnvelope {
                    request_id: request.request_id,
                    metadata: stein_protocol::ResponseMetadata::for_request(
                        &request.metadata,
                        actor,
                    ),
                    outcome: ResponseOutcome::Error(PublicError {
                        code: ErrorCode::Cancelled,
                        category: stein_protocol::ErrorCategory::Cancelled,
                        summary: "The synthetic request was cancelled.".into(),
                        retryable: false,
                        correlation_id: request.metadata.correlation_id,
                        details: None,
                    }),
                }
            }

            async fn send_matching_acknowledgement(inner: &ClientInner, cancel: &CancelRequest) {
                let waiter = inner
                    .cancellation_waiters
                    .lock()
                    .await
                    .remove(&cancel.cancellation_id)
                    .expect("matching cancellation waiter");
                assert_eq!(waiter.target_request_id, cancel.target_request_id);
                assert_eq!(waiter.correlation_id, cancel.correlation_id);
                assert_eq!(waiter.causation_id, cancel.message_id);
                waiter
                    .sender
                    .send(Ok(CancellationStatus::CancellationRequested))
                    .expect("client must still await the acknowledgement");
            }

            async fn send_terminal_response(
                inner: &ClientInner,
                session: &SessionOpened,
                request: &RequestEnvelope,
            ) {
                inner
                    .pending
                    .lock()
                    .await
                    .remove(&request.request_id)
                    .expect("matching response waiter")
                    .send(Ok(terminal_cancelled_response(
                        request,
                        session.authenticated_actor.clone(),
                    )))
                    .expect("client must still await the terminal response");
            }

            let (_, session) = fixture_session();
            let (inner, mut messages) = fixture_inner(session.clone());
            let client = Client {
                owner: Arc::new(ClientOwner {
                    inner: inner.clone(),
                }),
            };

            let cancellation = CancellationToken::new();
            let (response_first, request, cancel) =
                begin_cancelled_request(client.clone(), &mut messages, &cancellation).await;
            send_terminal_response(&inner, &session, &request).await;
            tokio::task::yield_now().await;
            assert!(
                !response_first.is_finished(),
                "a terminal cancelled response alone must not report cancellation"
            );
            send_matching_acknowledgement(&inner, &cancel).await;
            assert!(matches!(
                response_first.await.expect("request task must finish"),
                Err(ClientError::Cancelled)
            ));

            let cancellation = CancellationToken::new();
            let (acknowledgement_first, request, cancel) =
                begin_cancelled_request(client, &mut messages, &cancellation).await;
            send_matching_acknowledgement(&inner, &cancel).await;
            tokio::task::yield_now().await;
            assert!(
                !acknowledgement_first.is_finished(),
                "a matching acknowledgement alone must not report cancellation"
            );
            send_terminal_response(&inner, &session, &request).await;
            assert!(matches!(
                acknowledgement_first
                    .await
                    .expect("request task must finish"),
                Err(ClientError::Cancelled)
            ));
        }

        #[tokio::test]
        async fn an_older_snapshot_cannot_overwrite_later_applied_state() {
            let (_, session) = fixture_session();
            let (inner, _messages) = fixture_inner(session.clone());
            let original_sequence = session.snapshot.cursor.sequence;
            let mut newer = session.snapshot.clone();
            newer.cursor.sequence = original_sequence + 2;
            inner.snapshot.write().await.clone_from(&newer);

            let mut stale = session.snapshot;
            stale.cursor.sequence = original_sequence + 1;
            let returned = merge_snapshot(&inner, stale)
                .await
                .expect("stale but consistent snapshot is ignored");

            assert_eq!(returned.cursor.sequence, original_sequence + 2);
            assert_eq!(
                inner.snapshot.read().await.cursor.sequence,
                original_sequence + 2
            );
        }

        #[tokio::test]
        async fn equal_cursor_snapshots_cannot_regress_by_as_of() {
            let (_, session) = fixture_session();
            let (inner, _messages) = fixture_inner(session.clone());
            let event: ServerMessage =
                serde_json::from_str(include_str!("../../../contracts/v1/server-goal-event.json"))
                    .expect("event fixture must decode");
            let ServerMessage::Event(event) = event else {
                panic!("fixture must be Event");
            };

            let mut newer = session.snapshot.clone();
            newer.as_of = event.metadata.occurred_at;
            let returned = merge_snapshot(&inner, newer.clone())
                .await
                .expect("newer same-cursor snapshot is accepted");
            assert_eq!(returned.as_of, newer.as_of);

            let returned = merge_snapshot(&inner, session.snapshot)
                .await
                .expect("older same-cursor snapshot is ignored");
            assert_eq!(returned.as_of, newer.as_of);
        }

        #[tokio::test]
        async fn snapshot_covered_events_are_not_misclassified_as_gaps() {
            let (_, session) = fixture_session();
            let event: ServerMessage =
                serde_json::from_str(include_str!("../../../contracts/v1/server-goal-event.json"))
                    .expect("event fixture must decode");
            let ServerMessage::Event(event) = event else {
                panic!("fixture must be Event");
            };
            let mut snapshot = session.snapshot.clone();
            snapshot.cursor = event.cursor;
            let snapshot = RwLock::new(snapshot);

            assert_eq!(
                apply_event(
                    &snapshot,
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &event,
                )
                .await,
                EventApplication::AlreadyCovered
            );

            let mut skipped = event;
            skipped.cursor.sequence += 2;
            assert_eq!(
                apply_event(
                    &snapshot,
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &skipped,
                )
                .await,
                EventApplication::Gap
            );
        }

        #[tokio::test]
        async fn message_identity_deduplicates_replay_after_snapshot_coverage() {
            let (_, session) = fixture_session();
            let message: ServerMessage =
                serde_json::from_str(include_str!("../../../contracts/v1/server-goal-event.json"))
                    .expect("event fixture must decode");
            let ServerMessage::Event(event) = message else {
                panic!("fixture must be Event");
            };
            let mut current = session.snapshot.clone();
            current.cursor = event.cursor;
            current.as_of = event.metadata.occurred_at;
            let snapshot = RwLock::new(current);
            let identities = StdMutex::new(HashSet::new());

            assert_eq!(
                apply_event_with_ids(
                    &snapshot,
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &identities,
                    &event,
                )
                .await,
                EventApplication::AlreadyCovered,
            );

            let mut replay = event;
            replay.cursor = replay.cursor.next();
            replay.metadata.occurred_at = UtcTimestamp::from_datetime(
                replay.metadata.occurred_at.as_datetime() + time::Duration::seconds(1),
            );
            assert_eq!(
                apply_event_with_ids(
                    &snapshot,
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &identities,
                    &replay,
                )
                .await,
                EventApplication::AlreadyCovered,
            );
            let current = snapshot.read().await;
            assert_eq!(current.cursor, replay.cursor);
            assert!(current.goals.is_empty(), "the replay was not applied twice");
        }

        #[test]
        fn bounded_event_identity_tracking_fails_closed_at_capacity() {
            let identities = StdMutex::new(HashSet::new());
            for _ in 0..MAX_APPLIED_EVENT_IDENTITIES {
                assert_eq!(
                    record_event_identity(&identities, MessageId::new_v7()),
                    Some(true),
                );
            }
            assert_eq!(
                record_event_identity(&identities, MessageId::new_v7()),
                None,
                "capacity exhaustion forces an authoritative reconnect",
            );
        }

        #[tokio::test]
        async fn unsupported_or_inconsistent_events_require_an_authoritative_reconnect() {
            let (_, session) = fixture_session();
            let message: ServerMessage =
                serde_json::from_str(include_str!("../../../contracts/v1/server-goal-event.json"))
                    .expect("event fixture must decode");
            let ServerMessage::Event(event) = message else {
                panic!("fixture must be Event");
            };

            let mut unsupported_schema = event.clone();
            unsupported_schema.metadata.schema_version += 1;
            assert_eq!(
                apply_event(
                    &RwLock::new(session.snapshot.clone()),
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &unsupported_schema,
                )
                .await,
                EventApplication::Gap
            );

            let mut wrong_origin = event.clone();
            wrong_origin.metadata.origin = Component::CoreDaemon;
            assert_eq!(
                apply_event(
                    &RwLock::new(session.snapshot.clone()),
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &wrong_origin,
                )
                .await,
                EventApplication::Gap
            );

            let mut wrong_actor = event.clone();
            wrong_actor.metadata.actor.kind = ActorKind::CoreDaemon;
            assert_eq!(
                apply_event(
                    &RwLock::new(session.snapshot.clone()),
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &wrong_actor,
                )
                .await,
                EventApplication::Gap
            );

            let mut missing_causation = event.clone();
            missing_causation.metadata.causation_id = None;
            assert_eq!(
                apply_event(
                    &RwLock::new(session.snapshot.clone()),
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &missing_causation,
                )
                .await,
                EventApplication::Gap
            );

            let mut wrong_classification = event;
            wrong_classification.metadata.sensitivity = SensitivityClass::Operational;
            assert_eq!(
                apply_event(
                    &RwLock::new(session.snapshot.clone()),
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &wrong_classification,
                )
                .await,
                EventApplication::Gap
            );

            let mut regressed_time = wrong_classification;
            regressed_time.metadata.sensitivity = SensitivityClass::Personal;
            regressed_time.metadata.occurred_at = UtcTimestamp::from_datetime(
                session.snapshot.as_of.as_datetime() - time::Duration::seconds(1),
            );
            assert_eq!(
                apply_event(
                    &RwLock::new(session.snapshot.clone()),
                    &session,
                    ClientAssurance::PrivateCapabilityBound,
                    &regressed_time,
                )
                .await,
                EventApplication::Gap,
            );
        }

        #[tokio::test]
        async fn production_requests_carry_payload_sensitivity_and_a_wire_deadline() {
            let (_, session) = fixture_session();
            let (inner, mut messages) = fixture_inner(session);
            let client = Client {
                owner: Arc::new(ClientOwner { inner }),
            };
            let request = tokio::spawn(async move { client.get_client_snapshot().await });
            let message = timeout(Duration::from_secs(1), messages.recv())
                .await
                .expect("request should be queued")
                .expect("request channel should remain open");
            let ClientMessage::Request(request_message) = message else {
                panic!("expected a request message");
            };
            assert_eq!(
                request_message.metadata.sensitivity,
                SensitivityClass::Personal
            );
            let deadline = request_message
                .metadata
                .deadline_at
                .expect("production requests must carry a wire deadline");
            assert!(deadline > request_message.metadata.issued_at);
            assert!(
                deadline.as_datetime() - request_message.metadata.issued_at.as_datetime()
                    <= time::Duration::seconds(11)
            );
            request.abort();
            let _ = request.await;
        }

        #[tokio::test]
        async fn first_subscriber_receives_events_buffered_since_the_handshake() {
            let (_, session) = fixture_session();
            let (inner, _messages) = fixture_inner(session);
            let message: ServerMessage =
                serde_json::from_str(include_str!("../../../contracts/v1/server-goal-event.json"))
                    .expect("event fixture must decode");
            let ServerMessage::Event(event) = message else {
                panic!("fixture must be Event");
            };
            inner
                .events
                .send(event.clone())
                .expect("the retained initial receiver keeps the event channel live");
            let client = Client {
                owner: Arc::new(ClientOwner { inner }),
            };

            let mut receiver = client.subscribe_events();
            assert_eq!(receiver.recv().await.expect("buffered event"), event);
        }

        #[tokio::test]
        async fn legacy_diagnostic_event_receiver_is_closed_without_a_private_source() {
            let (_, session) = fixture_session();
            let (inner, _messages) =
                fixture_inner_with_assurance(session, ClientAssurance::Diagnostic);
            let client = Client {
                owner: Arc::new(ClientOwner { inner }),
            };

            assert!(matches!(
                client.subscribe_events().recv().await,
                Err(broadcast::error::RecvError::Closed),
            ));
        }
    }
}

#[cfg(not(windows))]
mod implementation {
    use stein_core::ClientAssurance;
    use stein_protocol::{
        AbandonGoalRequest, AbandonGoalResponse, ApproveModelRouteRequest,
        ApproveModelRouteResponse, ClientSnapshot, CompleteGoalRequest, CompleteGoalResponse,
        Component, CreateGoalRequest, CreateGoalResponse, DelayEchoResponse, DeleteGoalRequest,
        DeleteGoalResponse, EndFocusSessionRequest, EndFocusSessionResponse, EventEnvelope,
        ExplainInterventionRequest, ExplainInterventionResponse, GetCapabilityHealthResponse,
        GetEffectivePolicyResponse, GetFocusSessionViewRequest, GetFocusSessionViewResponse,
        GetGoalRequest, GetGoalResponse, GetInterventionHistoryRequest,
        GetInterventionHistoryResponse, GetPermissionViewRequest, GetPermissionViewResponse,
        GetRuntimeStatusResponse, GetSelectedResourcesResponse, GetSteinIdentityResponse,
        GetUserPreferencesResponse, GrantSessionPermissionRequest, GrantSessionPermissionResponse,
        IdempotencyKey, ProtocolSupport, RecordInterventionFeedbackRequest,
        RecordInterventionFeedbackResponse, RegisterSelectedResourceRequest,
        RegisterSelectedResourceResponse, RemoveSelectedResourceRequest,
        RemoveSelectedResourceResponse, RevokePermissionRequest, RevokePermissionResponse,
        SessionOpened, SetInterventionsMutedRequest, SetInterventionsMutedResponse, ShutdownReason,
        ShutdownResponse, StartFocusSessionRequest, StartFocusSessionResponse, UpdateGoalRequest,
        UpdateGoalResponse, UpdateUserPreferencesRequest, UpdateUserPreferencesResponse,
    };
    use thiserror::Error;
    use tokio::sync::broadcast;
    use tokio_util::sync::CancellationToken;

    #[derive(Debug, Error)]
    pub enum ClientError {
        #[error("the Phase 1 native client is implemented on Windows first")]
        Unsupported,
    }

    #[derive(Clone)]
    pub struct Client;

    pub struct ClientSubscription {
        pub snapshot: ClientSnapshot,
        pub events: broadcast::Receiver<EventEnvelope>,
    }

    impl Client {
        pub async fn connect_default() -> Result<Self, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn connect_with_support(
            _client_name: impl Into<String>,
            _protocol_support: ProtocolSupport,
        ) -> Result<Self, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn connect_with_identity(
            _client_name: impl Into<String>,
            _origin: Component,
            _protocol_support: ProtocolSupport,
        ) -> Result<Self, ClientError> {
            Err(ClientError::Unsupported)
        }
        #[cfg(feature = "private-client-test-harness")]
        pub async fn connect_private_capability_bound_for_test(
            _client_name: impl Into<String>,
            _origin: Component,
            _protocol_support: ProtocolSupport,
            _endpoint: &crate::PrivateTestEndpoint,
        ) -> Result<Self, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub fn session(&self) -> &SessionOpened {
            unreachable!("unsupported platform")
        }
        pub fn assurance(&self) -> ClientAssurance {
            unreachable!("unsupported platform")
        }
        pub async fn cached_snapshot(&self) -> ClientSnapshot {
            unreachable!("unsupported platform")
        }
        pub async fn open_subscription(&self) -> Result<ClientSubscription, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
            unreachable!("unsupported platform")
        }
        pub async fn next_event(&self) -> Result<EventEnvelope, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_client_snapshot(&self) -> Result<ClientSnapshot, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_runtime_status(&self) -> Result<GetRuntimeStatusResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_capability_health(
            &self,
        ) -> Result<GetCapabilityHealthResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn create_goal(
            &self,
            _input: CreateGoalRequest,
        ) -> Result<CreateGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn create_goal_idempotent(
            &self,
            _input: CreateGoalRequest,
            _idempotency_key: IdempotencyKey,
        ) -> Result<CreateGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn update_goal(
            &self,
            _input: UpdateGoalRequest,
        ) -> Result<UpdateGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn complete_goal(
            &self,
            _input: CompleteGoalRequest,
        ) -> Result<CompleteGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn abandon_goal(
            &self,
            _input: AbandonGoalRequest,
        ) -> Result<AbandonGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn delete_goal(
            &self,
            _input: DeleteGoalRequest,
        ) -> Result<DeleteGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn approve_model_route(
            &self,
            _input: ApproveModelRouteRequest,
            _idempotency_key: IdempotencyKey,
        ) -> Result<ApproveModelRouteResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn grant_session_permission(
            &self,
            _input: GrantSessionPermissionRequest,
            _idempotency_key: IdempotencyKey,
        ) -> Result<GrantSessionPermissionResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn revoke_permission(
            &self,
            _input: RevokePermissionRequest,
        ) -> Result<RevokePermissionResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn start_focus_session(
            &self,
            _input: StartFocusSessionRequest,
            _idempotency_key: IdempotencyKey,
        ) -> Result<StartFocusSessionResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn set_interventions_muted(
            &self,
            _input: SetInterventionsMutedRequest,
        ) -> Result<SetInterventionsMutedResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn end_focus_session(
            &self,
            _input: EndFocusSessionRequest,
        ) -> Result<EndFocusSessionResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn record_intervention_feedback(
            &self,
            _input: RecordInterventionFeedbackRequest,
        ) -> Result<RecordInterventionFeedbackResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn register_selected_resource(
            &self,
            _input: RegisterSelectedResourceRequest,
            _idempotency_key: IdempotencyKey,
        ) -> Result<RegisterSelectedResourceResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn remove_selected_resource(
            &self,
            _input: RemoveSelectedResourceRequest,
        ) -> Result<RemoveSelectedResourceResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn update_user_preferences(
            &self,
            _input: UpdateUserPreferencesRequest,
        ) -> Result<UpdateUserPreferencesResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_goal(
            &self,
            _input: GetGoalRequest,
        ) -> Result<GetGoalResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_focus_session_view(
            &self,
            _input: GetFocusSessionViewRequest,
        ) -> Result<GetFocusSessionViewResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_permission_view(
            &self,
            _input: GetPermissionViewRequest,
        ) -> Result<GetPermissionViewResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_intervention_history(
            &self,
            _input: GetInterventionHistoryRequest,
        ) -> Result<GetInterventionHistoryResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn explain_intervention(
            &self,
            _input: ExplainInterventionRequest,
        ) -> Result<ExplainInterventionResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_stein_identity(&self) -> Result<GetSteinIdentityResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_user_preferences(
            &self,
        ) -> Result<GetUserPreferencesResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_effective_policy(
            &self,
        ) -> Result<GetEffectivePolicyResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn get_selected_resources(
            &self,
        ) -> Result<GetSelectedResourcesResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn delay_echo(
            &self,
            _delay_ms: u64,
            _text: impl Into<String>,
            _cancel: Option<CancellationToken>,
        ) -> Result<DelayEchoResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
        pub async fn shutdown(
            &self,
            _reason: ShutdownReason,
        ) -> Result<ShutdownResponse, ClientError> {
            Err(ClientError::Unsupported)
        }
    }
}

pub use implementation::{Client, ClientError, ClientSubscription};
