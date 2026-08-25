#[cfg(windows)]
mod implementation {
    use std::{
        collections::{HashMap, VecDeque},
        io,
        os::windows::io::{AsRawHandle, BorrowedHandle},
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        time::{Duration, Instant as StdInstant},
    };

    use stein_broker_windows::{
        BROKER_APPLICATION_ID, CORE_PRIVATE_PIPE, ConnectionAuthority, ExpectedPackageIdentity,
        PRODUCTION_PACKAGE_NAME, PackagePeerClass, admit_named_pipe_peer,
    };
    use stein_core::{
        ClientAssurance, CoreRuntime, EventStreamError, ProtocolRequestContext,
        ProtocolSubscription,
    };
    use stein_protocol::{
        ActorId, ActorKind, ActorReference, CancelAcknowledged, CancellationId, CancellationStatus,
        ClientHello, ClientMessage, ClientSnapshot, CompatibilityErrorDetails, Component,
        ErrorCategory, ErrorCode, ErrorDetails, EventCursor, EventEnvelope, EventGap,
        EventGapAction, EventGapReason, EventMetadata, FatalFrame, FatalReason,
        GetRuntimeStatusRequest, MessageId, ProtocolSupport, ProtocolVersion, PublicError,
        RequestBody, RequestEnvelope, RequestId, RequestKind, RequestMetadata, ResponseBody,
        ResponseEnvelope, ResponseMetadata, ResponseOutcome, RetentionClass, SensitivityClass,
        ServerMessage, SessionOpened, SnapshotId, UtcTimestamp, ViewEvent, negotiate_protocol,
    };
    use thiserror::Error;
    use tokio::{
        io::{AsyncWrite, split},
        sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
        task::JoinSet,
        time::{Instant, timeout},
    };
    use tokio_util::sync::CancellationToken;
    use tracing::{info, warn};
    use uuid::Uuid;

    use crate::{
        MAX_FRAME_BYTES, capability_supported,
        codec::{read_frame, write_frame},
        default_pipe_name,
        windows::{
            create_pipe_server, create_private_pipe_server, ensure_pipe_client_is_current_user,
        },
    };

    const OUTBOUND_QUEUE_TIMEOUT: Duration = Duration::from_secs(2);
    const OUTBOUND_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

    /// Exact production broker identity embedded by the trusted signed CORE
    /// build. Debug output never reveals the pinned PFN or AUMID.
    #[derive(Clone)]
    pub struct PrivateServerIdentity {
        owner_sid: String,
        expected: ExpectedPackageIdentity,
    }

    impl std::fmt::Debug for PrivateServerIdentity {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("PrivateServerIdentity([redacted])")
        }
    }

    impl PrivateServerIdentity {
        pub fn production(
            package_family_name: impl Into<String>,
            broker_aumid: impl Into<String>,
        ) -> Result<Self, ServerError> {
            let package_family_name = package_family_name.into();
            let broker_aumid = broker_aumid.into();
            validate_production_identity(&package_family_name, &broker_aumid)?;
            let owner_sid = crate::current_user_sid()?;
            let expected =
                ExpectedPackageIdentity::new(owner_sid.clone(), package_family_name, broker_aumid)
                    .map_err(|_| ServerError::InvalidPrivateIdentity)?;
            Ok(Self {
                owner_sid,
                expected,
            })
        }
    }

    fn validate_production_identity(
        package_family_name: &str,
        broker_aumid: &str,
    ) -> Result<(), ServerError> {
        let publisher_id = package_family_name
            .strip_prefix(PRODUCTION_PACKAGE_NAME)
            .and_then(|suffix| suffix.strip_prefix('_'))
            .ok_or(ServerError::InvalidPrivateIdentity)?;
        if publisher_id.len() != 13
            || !publisher_id.bytes().all(|byte| {
                byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'a'..=b'h' | b'j'..=b'k' | b'm'..=b'n' | b'p'..=b't' | b'v'..=b'z'
                    )
            })
            || broker_aumid != format!("{package_family_name}!{BROKER_APPLICATION_ID}")
        {
            return Err(ServerError::InvalidPrivateIdentity);
        }
        Ok(())
    }

    /// Connection assurance is native transport state. No ClientHello field
    /// can create or upgrade it.
    #[derive(Debug)]
    enum SessionAdmission {
        Diagnostic,
        #[cfg(any(test, feature = "private-client-test-harness"))]
        PrivateCapabilityBoundForTest,
        ProductionPrivate {
            authority: ConnectionAuthority,
            daemon_instance: [u8; 16],
        },
    }

    #[derive(Debug)]
    struct AcceptedPeer {
        sid: String,
        admission: SessionAdmission,
    }

    impl SessionAdmission {
        const fn assurance(&self) -> ClientAssurance {
            match self {
                Self::Diagnostic => ClientAssurance::Diagnostic,
                #[cfg(any(test, feature = "private-client-test-harness"))]
                Self::PrivateCapabilityBoundForTest => ClientAssurance::PrivateCapabilityBound,
                Self::ProductionPrivate { .. } => ClientAssurance::PrivateCapabilityBound,
            }
        }

        fn current_for_open_session(
            &self,
            pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
            now: StdInstant,
        ) -> bool {
            match self {
                Self::Diagnostic => true,
                #[cfg(any(test, feature = "private-client-test-harness"))]
                Self::PrivateCapabilityBoundForTest => true,
                Self::ProductionPrivate {
                    authority,
                    daemon_instance,
                } => authority.is_current_for(borrowed_handle(pipe), daemon_instance, now),
            }
        }
    }

    enum ListenerAdmission {
        Diagnostic,
        #[cfg(feature = "private-client-test-harness")]
        PrivateCapabilityBoundForTest,
        ProductionPrivate {
            identity: PrivateServerIdentity,
            daemon_instance: [u8; 16],
        },
    }

    impl ListenerAdmission {
        fn create_listener(
            &self,
            pipe_name: &str,
            first_instance: bool,
        ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
            match self {
                Self::Diagnostic => create_pipe_server(pipe_name, first_instance),
                #[cfg(feature = "private-client-test-harness")]
                Self::PrivateCapabilityBoundForTest => {
                    create_pipe_server(pipe_name, first_instance)
                }
                Self::ProductionPrivate { identity, .. } => {
                    create_private_pipe_server(pipe_name, first_instance, &identity.expected)
                }
            }
        }

        fn admit(
            &self,
            pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
            handshake_timeout: Duration,
        ) -> io::Result<AcceptedPeer> {
            match self {
                Self::Diagnostic => Ok(AcceptedPeer {
                    sid: ensure_pipe_client_is_current_user(pipe)?,
                    admission: SessionAdmission::Diagnostic,
                }),
                #[cfg(feature = "private-client-test-harness")]
                Self::PrivateCapabilityBoundForTest => Ok(AcceptedPeer {
                    sid: ensure_pipe_client_is_current_user(pipe)?,
                    admission: SessionAdmission::PrivateCapabilityBoundForTest,
                }),
                Self::ProductionPrivate {
                    identity,
                    daemon_instance,
                } => {
                    let expires_at = StdInstant::now()
                        .checked_add(handshake_timeout)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "private admission deadline is invalid",
                            )
                        })?;
                    let authority = admit_named_pipe_peer(
                        borrowed_handle(pipe),
                        &identity.expected,
                        PackagePeerClass::AppContainerBroker,
                        *daemon_instance,
                        expires_at,
                    )
                    .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
                    Ok(AcceptedPeer {
                        sid: identity.owner_sid.clone(),
                        admission: SessionAdmission::ProductionPrivate {
                            authority,
                            daemon_instance: *daemon_instance,
                        },
                    })
                }
            }
        }
    }

    fn borrowed_handle(
        pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> BorrowedHandle<'_> {
        // SAFETY: this borrow cannot outlive the referenced Tokio pipe and does
        // not transfer ownership of its native handle.
        unsafe { BorrowedHandle::borrow_raw(pipe.as_raw_handle()) }
    }

    #[derive(Clone, Debug)]
    pub struct ServerConfig {
        pub maximum_connections: usize,
        pub maximum_in_flight_per_connection: usize,
        pub maximum_requests_per_window: usize,
        pub request_rate_window: Duration,
        pub handshake_timeout: Duration,
        pub idle_timeout: Duration,
        pub shutdown_grace: Duration,
    }

    impl Default for ServerConfig {
        fn default() -> Self {
            Self {
                maximum_connections: 8,
                maximum_in_flight_per_connection: 16,
                maximum_requests_per_window: 120,
                request_rate_window: Duration::from_secs(10),
                handshake_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(5 * 60),
                shutdown_grace: Duration::from_secs(1),
            }
        }
    }

    #[derive(Debug, Error)]
    pub enum ServerError {
        #[error("failed to create or accept the protected local pipe: {0}")]
        Transport(#[from] io::Error),
        #[error("server configuration is invalid: {0}")]
        InvalidConfig(&'static str),
        #[error("the production private broker identity is invalid")]
        InvalidPrivateIdentity,
    }

    pub async fn run_server(core: CoreRuntime, config: ServerConfig) -> Result<(), ServerError> {
        run_server_with_admission(
            core,
            config,
            ListenerAdmission::Diagnostic,
            default_pipe_name()?,
        )
        .await
    }

    pub async fn run_private_server(
        core: CoreRuntime,
        config: ServerConfig,
        identity: PrivateServerIdentity,
    ) -> Result<(), ServerError> {
        let daemon_instance = *core.runtime_status().daemon_instance_id.as_bytes();
        run_server_with_admission(
            core,
            config,
            ListenerAdmission::ProductionPrivate {
                identity,
                daemon_instance,
            },
            CORE_PRIVATE_PIPE.to_owned(),
        )
        .await
    }

    /// Explicit non-production compatibility hook for the retained Phase 1
    /// harness. Production private sessions require OS-authenticated broker
    /// admission and cannot select assurance through protocol payloads.
    #[cfg(feature = "private-client-test-harness")]
    pub async fn run_private_capability_bound_test_server(
        core: CoreRuntime,
        config: ServerConfig,
        endpoint: &crate::PrivateTestEndpoint,
    ) -> Result<(), ServerError> {
        run_server_with_admission(
            core,
            config,
            ListenerAdmission::PrivateCapabilityBoundForTest,
            endpoint.pipe_name().to_owned(),
        )
        .await
    }

    async fn run_server_with_admission(
        core: CoreRuntime,
        config: ServerConfig,
        admission: ListenerAdmission,
        pipe_name: String,
    ) -> Result<(), ServerError> {
        validate_config(&config)?;
        let shutdown = core.shutdown_token();
        let stop_sessions = CancellationToken::new();
        let connections = Arc::new(Semaphore::new(config.maximum_connections));
        let active_connections = Arc::new(AtomicU32::new(0));
        let mut sessions = JoinSet::new();
        let mut listener = admission.create_listener(&pipe_name, true)?;
        info!("protected named-pipe endpoint ready");

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                completed = sessions.join_next(), if !sessions.is_empty() => {
                    match completed {
                        Some(Ok(Ok(()))) | None => {}
                        Some(Ok(Err(error))) => {
                            warn!(error = %error, "client session ended with an error");
                        }
                        Some(Err(error)) => {
                            warn!(error = %error, "client session task ended unexpectedly");
                        }
                    }
                }
                result = listener.connect() => {
                    result?;
                    let connected = listener;
                    listener = admission.create_listener(&pipe_name, false)?;
                    let Some(permit) = try_admit_connection(&connections) else {
                        warn!("connection rejected at configured limit");
                        drop(connected);
                        continue;
                    };
                    let peer = match admission.admit(&connected, config.handshake_timeout) {
                        Ok(peer) => peer,
                        Err(error) => {
                            warn!(error = %error, "named-pipe peer identity rejected");
                            drop(connected);
                            continue;
                        }
                    };
                    let core = core.clone();
                    let config = config.clone();
                    let active = active_connections.clone();
                    let stop = stop_sessions.clone();
                    sessions.spawn(handle_connection(
                        connected,
                        core,
                        config,
                        active,
                        permit,
                        peer,
                        stop,
                    ));
                }
            }
        }

        drop(listener);
        stop_sessions.cancel();
        let sessions_drained = timeout(config.shutdown_grace.saturating_mul(4), async {
            while let Some(completed) = sessions.join_next().await {
                match completed {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        warn!(error = %error, "client session ended with an error");
                    }
                    Err(error) => {
                        warn!(error = %error, "client session task ended unexpectedly");
                    }
                }
            }
        })
        .await
        .is_ok();
        if !sessions_drained {
            warn!("client sessions exceeded the shutdown deadline; aborting them");
            sessions.abort_all();
            while sessions.join_next().await.is_some() {}
        }
        info!("local protocol server stopped");
        Ok(())
    }

    fn try_admit_connection(connections: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
        connections.clone().try_acquire_owned().ok()
    }

    fn validate_config(config: &ServerConfig) -> Result<(), ServerError> {
        if config.maximum_connections == 0 {
            return Err(ServerError::InvalidConfig(
                "maximum_connections must be positive",
            ));
        }
        if config.maximum_in_flight_per_connection == 0 {
            return Err(ServerError::InvalidConfig(
                "maximum_in_flight_per_connection must be positive",
            ));
        }
        if config.maximum_requests_per_window == 0 {
            return Err(ServerError::InvalidConfig(
                "maximum_requests_per_window must be positive",
            ));
        }
        if config.handshake_timeout.is_zero() {
            return Err(ServerError::InvalidConfig(
                "handshake_timeout must be positive",
            ));
        }
        Ok(())
    }

    struct ActiveConnectionGuard {
        counter: Arc<AtomicU32>,
        _permit: OwnedSemaphorePermit,
    }

    impl ActiveConnectionGuard {
        fn new(counter: Arc<AtomicU32>, permit: OwnedSemaphorePermit) -> Self {
            counter.fetch_add(1, Ordering::SeqCst);
            Self {
                counter,
                _permit: permit,
            }
        }
    }

    impl Drop for ActiveConnectionGuard {
        fn drop(&mut self) {
            self.counter.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct InFlightRequest {
        cancellation_id: Option<CancellationId>,
        token: CancellationToken,
    }

    async fn handle_connection(
        mut pipe: tokio::net::windows::named_pipe::NamedPipeServer,
        core: CoreRuntime,
        config: ServerConfig,
        active_connections: Arc<AtomicU32>,
        permit: OwnedSemaphorePermit,
        peer: AcceptedPeer,
        stop: CancellationToken,
    ) -> io::Result<()> {
        let _connection = ActiveConnectionGuard::new(active_connections.clone(), permit);
        let AcceptedPeer { sid, admission } = peer;
        let assurance = admission.assurance();
        if !admission.current_for_open_session(&pipe, StdInstant::now()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private connection admission expired",
            ));
        }
        let actor_id = ActorId::from_uuid(Uuid::new_v5(&Uuid::NAMESPACE_OID, sid.as_bytes()));
        let session_actor = ActorReference {
            // Diagnostic sessions must not expose the stable per-user actor
            // identifier. Their actor is intentionally connection-scoped.
            actor_id: if matches!(assurance, ClientAssurance::Diagnostic) {
                ActorId::new_v7()
            } else {
                actor_id
            },
            kind: ActorKind::LocalOsUser,
        };
        let daemon_actor = ActorReference {
            actor_id: ActorId::from_uuid(core.runtime_status().daemon_instance_id),
            kind: ActorKind::CoreDaemon,
        };
        let hello_result = tokio::select! {
            biased;
            () = stop.cancelled() => return Ok(()),
            result = timeout(
                config.handshake_timeout,
                read_frame::<_, ClientMessage>(&mut pipe),
            ) => result,
        };
        let hello_message = match hello_result {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "handshake timed out",
                ));
            }
        };

        let hello = match hello_message {
            ClientMessage::OpenSession(hello) => hello,
            _ => {
                let _ = write_frame(
                    &mut pipe,
                    &fatal(
                        FatalReason::HandshakeRequired,
                        ErrorCode::Unauthenticated,
                        ErrorCategory::Unauthenticated,
                        "OpenSession must be the first protocol message.",
                    ),
                )
                .await;
                return Ok(());
            }
        };

        if let Err(summary) = validate_client_hello(&hello) {
            let _ = write_frame(
                &mut pipe,
                &fatal(
                    FatalReason::HandshakeRequired,
                    ErrorCode::InvalidArgument,
                    ErrorCategory::InvalidArgument,
                    summary,
                ),
            )
            .await;
            return Ok(());
        }

        let negotiated = match negotiate_protocol(hello.protocol_support, ProtocolSupport::V1) {
            Ok(version) => version,
            Err(_) => {
                let mut message = fatal(
                    FatalReason::IncompatibleProtocol,
                    ErrorCode::IncompatibleProtocol,
                    ErrorCategory::IncompatibleVersion,
                    "The client and CORE do not share a compatible protocol version.",
                );
                if let ServerMessage::Fatal(frame) = &mut message {
                    frame.error.details =
                        Some(ErrorDetails::Compatibility(CompatibilityErrorDetails {
                            client_support: hello.protocol_support,
                            server_support: ProtocolSupport::V1,
                        }));
                }
                let _ = write_frame(&mut pipe, &message).await;
                return Ok(());
            }
        };

        // Native authority is a connection property, not a hello field. Check
        // the exact still-connected handle again after the bounded OpenSession
        // read and before any private snapshot or request dispatch.
        if !admission.current_for_open_session(&pipe, StdInstant::now()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private connection admission expired",
            ));
        }

        let (mut reader, writer) = split(pipe);

        let connection_count = active_connections.load(Ordering::SeqCst);
        let (snapshot, subscription) =
            open_session_state(&core, actor_id, assurance, negotiated, connection_count).await?;
        let opened = ServerMessage::SessionOpened(SessionOpened {
            protocol_version: negotiated,
            server_build_id: env!("CARGO_PKG_VERSION").to_owned(),
            daemon_instance_id: snapshot.runtime.daemon_instance_id,
            authenticated_actor: session_actor.clone(),
            max_frame_bytes: MAX_FRAME_BYTES as u32,
            capabilities: snapshot.capabilities.clone(),
            snapshot,
        });

        let connection_end = stop.child_token();
        let (outgoing, outgoing_rx) = mpsc::channel::<ServerMessage>(128);
        let mut writer_task =
            tokio::spawn(writer_loop(writer, outgoing_rx, connection_end.clone()));
        if !send_until_closed(&outgoing, opened, &connection_end).await {
            connection_end.cancel();
            drop(outgoing);
            if timeout(config.shutdown_grace, &mut writer_task)
                .await
                .is_err()
            {
                writer_task.abort();
                let _ = writer_task.await;
            }
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer stopped during session opening",
            ));
        }

        let event_task = subscription.map(|subscription| {
            tokio::spawn(event_loop(
                subscription,
                outgoing.clone(),
                negotiated,
                connection_end.clone(),
            ))
        });
        let in_flight = Arc::new(Mutex::new(HashMap::<RequestId, InFlightRequest>::new()));
        let request_slots = Arc::new(Semaphore::new(config.maximum_in_flight_per_connection));
        let mut request_tasks = JoinSet::new();
        let mut request_times = VecDeque::<Instant>::new();
        let mut terminal_error = None;

        loop {
            while let Some(result) = request_tasks.try_join_next() {
                if let Err(error) = result {
                    warn!(error = %error, "request task ended unexpectedly");
                }
            }

            let incoming = tokio::select! {
                biased;
                () = connection_end.cancelled() => break,
                incoming = timeout(
                    config.idle_timeout,
                    read_frame::<_, ClientMessage>(&mut reader),
                ) => incoming,
            };
            let message = match incoming {
                Ok(Ok(message)) => message,
                Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Ok(Err(error)) => {
                    terminal_error = Some(error);
                    break;
                }
                Err(_) => break,
            };
            match message {
                ClientMessage::Request(request) => {
                    if let Err(error) = validate_request_admission(&request, assurance, negotiated)
                    {
                        let response = error_response(&request, session_actor.clone(), error);
                        if !send_until_closed(&outgoing, response, &connection_end).await {
                            break;
                        }
                        continue;
                    }

                    let now = Instant::now();
                    while request_times.front().is_some_and(|earliest| {
                        now.duration_since(*earliest) > config.request_rate_window
                    }) {
                        request_times.pop_front();
                    }
                    if request_times.len() >= config.maximum_requests_per_window {
                        let response = error_response(
                            &request,
                            session_actor.clone(),
                            PublicError {
                                code: ErrorCode::RateLimited,
                                category: ErrorCategory::Unavailable,
                                summary: "The connection exceeded its request-rate limit.".into(),
                                retryable: true,
                                correlation_id: request.metadata.correlation_id,
                                details: None,
                            },
                        );
                        if !send_until_closed(&outgoing, response, &connection_end).await {
                            break;
                        }
                        continue;
                    }
                    request_times.push_back(now);

                    if in_flight.lock().await.contains_key(&request.request_id) {
                        let response = error_response(
                            &request,
                            session_actor.clone(),
                            PublicError {
                                code: ErrorCode::Conflict,
                                category: ErrorCategory::Conflict,
                                summary: "The request identifier is already in flight.".into(),
                                retryable: false,
                                correlation_id: request.metadata.correlation_id,
                                details: None,
                            },
                        );
                        if !send_until_closed(&outgoing, response, &connection_end).await {
                            break;
                        }
                        continue;
                    }

                    let Ok(slot) = request_slots.clone().try_acquire_owned() else {
                        let response = error_response(
                            &request,
                            session_actor.clone(),
                            PublicError {
                                code: ErrorCode::RateLimited,
                                category: ErrorCategory::Unavailable,
                                summary: "Too many requests are already in flight.".into(),
                                retryable: true,
                                correlation_id: request.metadata.correlation_id,
                                details: None,
                            },
                        );
                        if !send_until_closed(&outgoing, response, &connection_end).await {
                            break;
                        }
                        continue;
                    };

                    let cancellation = CancellationToken::new();
                    in_flight.lock().await.insert(
                        request.request_id,
                        InFlightRequest {
                            cancellation_id: request.metadata.cancellation_id,
                            token: cancellation.clone(),
                        },
                    );
                    let core = core.clone();
                    let outgoing = outgoing.clone();
                    let in_flight = in_flight.clone();
                    let response_actor = session_actor.clone();
                    let active_connections = active_connections.clone();
                    let request_connection_end = connection_end.clone();
                    let request_context = ProtocolRequestContext {
                        actor: actor_id,
                        client_id: hello.client_instance_id,
                        assurance,
                        negotiated_version: negotiated,
                    };
                    request_tasks.spawn(async move {
                        let _slot = slot;
                        execute_request(
                            core,
                            request_context,
                            response_actor,
                            request,
                            active_connections,
                            cancellation,
                            outgoing,
                            in_flight,
                            request_connection_end,
                            negotiated,
                        )
                        .await;
                    });
                }
                ClientMessage::Cancel(cancel)
                    if matches!(assurance, ClientAssurance::PrivateCapabilityBound) =>
                {
                    let status = {
                        let in_flight = in_flight.lock().await;
                        request_cancellation(
                            &in_flight,
                            cancel.target_request_id,
                            cancel.cancellation_id,
                        )
                    };
                    let acknowledged = ServerMessage::CancelAcknowledged(CancelAcknowledged {
                        message_id: MessageId::new_v7(),
                        issued_at: UtcTimestamp::now(),
                        correlation_id: cancel.correlation_id,
                        causation_id: cancel.message_id,
                        actor: daemon_actor.clone(),
                        target_request_id: cancel.target_request_id,
                        cancellation_id: cancel.cancellation_id,
                        status,
                    });
                    if !send_until_closed(&outgoing, acknowledged, &connection_end).await {
                        break;
                    }
                }
                ClientMessage::Cancel(_) => {
                    let _ = send_until_closed(
                        &outgoing,
                        fatal(
                            FatalReason::AuthenticationFailed,
                            ErrorCode::PermissionDenied,
                            ErrorCategory::PermissionDenied,
                            "This connection is not admitted for private protocol operations.",
                        ),
                        &connection_end,
                    )
                    .await;
                    break;
                }
                ClientMessage::OpenSession(_) => {
                    let _ = send_until_closed(
                        &outgoing,
                        fatal(
                            FatalReason::HandshakeRequired,
                            ErrorCode::InvalidArgument,
                            ErrorCategory::InvalidArgument,
                            "A protocol session is already open.",
                        ),
                        &connection_end,
                    )
                    .await;
                    break;
                }
            }
        }

        connection_end.cancel();
        for request in in_flight.lock().await.values() {
            request.token.cancel();
        }

        if let Some(mut event_task) = event_task
            && timeout(config.shutdown_grace, &mut event_task)
                .await
                .is_err()
        {
            event_task.abort();
            let _ = event_task.await;
        }

        let requests_finished = timeout(config.shutdown_grace, async {
            while let Some(result) = request_tasks.join_next().await {
                if let Err(error) = result {
                    warn!(error = %error, "request task ended unexpectedly");
                }
            }
        })
        .await
        .is_ok();
        if !requests_finished {
            request_tasks.abort_all();
            while request_tasks.join_next().await.is_some() {}
        }
        in_flight.lock().await.clear();

        drop(outgoing);
        if timeout(config.shutdown_grace, &mut writer_task)
            .await
            .is_err()
        {
            writer_task.abort();
            let _ = writer_task.await;
        }

        if let Some(error) = terminal_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_request(
        core: CoreRuntime,
        request_context: ProtocolRequestContext,
        response_actor: ActorReference,
        request: RequestEnvelope,
        active_connections: Arc<AtomicU32>,
        cancellation: CancellationToken,
        outgoing: mpsc::Sender<ServerMessage>,
        in_flight: Arc<Mutex<HashMap<RequestId, InFlightRequest>>>,
        connection_end: CancellationToken,
        negotiated: ProtocolVersion,
    ) {
        let mut result = core
            .handle_protocol_request_with_context(
                request_context,
                &request,
                active_connections.load(Ordering::SeqCst),
                cancellation,
            )
            .await;
        if let Ok(body) = &mut result {
            normalize_response_for_protocol(body, negotiated);
        }
        let commits_shutdown = accepted_shutdown(&request, &result);
        let response = ServerMessage::Response(ResponseEnvelope {
            request_id: request.request_id,
            metadata: ResponseMetadata::for_request(&request.metadata, response_actor),
            outcome: match result {
                Ok(body) => ResponseOutcome::Success(body),
                Err(error) => ResponseOutcome::Error(error),
            },
        });
        let response_queued = send_until_closed(&outgoing, response, &connection_end).await;
        in_flight.lock().await.remove(&request.request_id);
        if commits_shutdown && response_queued {
            // Commit the process stop only after the acknowledgement is in the
            // connection's ordered writer queue. run_server then stops accept,
            // drains the session writer, and exits.
            core.request_shutdown();
        } else if !response_queued {
            connection_end.cancel();
        }
    }

    async fn open_session_state(
        core: &CoreRuntime,
        actor_id: ActorId,
        assurance: ClientAssurance,
        negotiated: ProtocolVersion,
        active_connections: u32,
    ) -> io::Result<(ClientSnapshot, Option<ProtocolSubscription>)> {
        match assurance {
            ClientAssurance::Diagnostic => {
                let mut metadata = RequestMetadata::new(
                    Component::CoreDaemon,
                    SensitivityClass::Operational,
                    RetentionClass::Runtime,
                );
                metadata.deadline_at = Some(UtcTimestamp::from_datetime(
                    time::OffsetDateTime::now_utc() + time::Duration::seconds(5),
                ));
                let request = RequestEnvelope::new(
                    metadata,
                    RequestBody::GetRuntimeStatus(GetRuntimeStatusRequest::default()),
                );
                let response = core
                    .handle_protocol_request(
                        actor_id,
                        &request,
                        active_connections,
                        CancellationToken::new(),
                    )
                    .await
                    .map_err(|_| io::Error::other("content-free runtime status is unavailable"))?;
                let ResponseBody::GetRuntimeStatus(response) = response else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "runtime returned an unexpected diagnostic response",
                    ));
                };
                let mut snapshot = ClientSnapshot {
                    snapshot_id: SnapshotId::new_v7(),
                    as_of: UtcTimestamp::now(),
                    cursor: EventCursor {
                        daemon_instance_id: response.runtime.daemon_instance_id,
                        sequence: 0,
                    },
                    runtime: response.runtime,
                    capabilities: response.capabilities,
                    goals: Vec::new(),
                    phase2: None,
                };
                normalize_snapshot_for_protocol(&mut snapshot, negotiated);
                Ok((snapshot, None))
            }
            ClientAssurance::PrivateCapabilityBound => {
                let subscription = core
                    .open_protocol_subscription(actor_id, active_connections)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "actor rejected")
                    })?;
                let mut snapshot = subscription.snapshot.clone();
                normalize_snapshot_for_protocol(&mut snapshot, negotiated);
                Ok((snapshot, Some(subscription)))
            }
            ClientAssurance::NativeEmergencyControl => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native emergency authority is not a client protocol admission",
            )),
        }
    }

    fn validate_request_admission(
        request: &RequestEnvelope,
        assurance: ClientAssurance,
        negotiated: ProtocolVersion,
    ) -> Result<(), PublicError> {
        let kind = request.body.kind();
        let required = request.body.minimum_protocol_version();
        if !version_at_least(negotiated, required) {
            return Err(PublicError {
                code: ErrorCode::IncompatibleProtocol,
                category: ErrorCategory::IncompatibleVersion,
                summary: "The request requires a newer negotiated protocol version.".into(),
                retryable: false,
                correlation_id: request.metadata.correlation_id,
                details: Some(ErrorDetails::Compatibility(CompatibilityErrorDetails {
                    client_support: ProtocolSupport::exact(required),
                    server_support: ProtocolSupport::exact(negotiated),
                })),
            });
        }
        if !request_allowed(assurance, kind) {
            return Err(PublicError {
                code: ErrorCode::PermissionDenied,
                category: ErrorCategory::PermissionDenied,
                summary: "This connection is not admitted for private protocol operations.".into(),
                retryable: false,
                correlation_id: request.metadata.correlation_id,
                details: None,
            });
        }
        if request.metadata.sensitivity != request_sensitivity(kind, negotiated)
            || request.metadata.retention != kind.retention()
        {
            return Err(PublicError {
                code: ErrorCode::InvalidArgument,
                category: ErrorCategory::InvalidArgument,
                summary: "The request metadata classification is invalid.".into(),
                retryable: false,
                correlation_id: request.metadata.correlation_id,
                details: None,
            });
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
            SensitivityClass::Personal
        } else {
            kind.sensitivity()
        }
    }

    const fn version_at_least(negotiated: ProtocolVersion, required: ProtocolVersion) -> bool {
        negotiated.major == required.major && negotiated.minor >= required.minor
    }

    fn normalize_snapshot_for_protocol(snapshot: &mut ClientSnapshot, negotiated: ProtocolVersion) {
        snapshot.runtime.protocol_version = negotiated;
        normalize_capabilities_for_protocol(&mut snapshot.capabilities, negotiated);
        if !version_at_least(negotiated, ProtocolVersion::V1_1) {
            snapshot.phase2 = None;
        } else if !version_at_least(negotiated, ProtocolVersion::V1_2)
            && let Some(phase2) = snapshot.phase2.as_deref_mut()
        {
            phase2.current_device_id = None;
            phase2.stein_identity = None;
            phase2.user_preferences = None;
            phase2.effective_policy = None;
            for resource in &mut phase2.selected_resources {
                resource.revision = None;
                resource.created_at = None;
            }
        }
    }

    fn normalize_response_for_protocol(body: &mut ResponseBody, negotiated: ProtocolVersion) {
        match body {
            ResponseBody::GetSnapshot(response) => {
                normalize_snapshot_for_protocol(&mut response.snapshot, negotiated);
            }
            ResponseBody::GetRuntimeStatus(response) => {
                response.runtime.protocol_version = negotiated;
                normalize_capabilities_for_protocol(&mut response.capabilities, negotiated);
            }
            ResponseBody::GetCapabilityHealth(response) => {
                normalize_capabilities_for_protocol(&mut response.capabilities, negotiated);
            }
            _ => {}
        }
    }

    fn normalize_event_for_protocol(event: &mut ViewEvent, negotiated: ProtocolVersion) {
        if let ViewEvent::RuntimeStatusChanged(change) = event {
            change.runtime.protocol_version = negotiated;
        }
    }

    fn normalize_capabilities_for_protocol(
        capabilities: &mut Vec<stein_protocol::CapabilityHealth>,
        negotiated: ProtocolVersion,
    ) {
        capabilities.retain(|health| capability_supported(health.capability, negotiated));
    }

    fn accepted_shutdown(
        request: &RequestEnvelope,
        result: &Result<stein_protocol::ResponseBody, PublicError>,
    ) -> bool {
        matches!(
            (&request.body, result),
            (
                RequestBody::Shutdown(_),
                Ok(stein_protocol::ResponseBody::Shutdown(response))
            ) if response.accepted
        )
    }

    async fn event_loop(
        mut subscription: ProtocolSubscription,
        outgoing: mpsc::Sender<ServerMessage>,
        negotiated: ProtocolVersion,
        connection_end: CancellationToken,
    ) {
        let mut expected = subscription.snapshot.cursor;
        loop {
            let received = tokio::select! {
                biased;
                () = connection_end.cancelled() => break,
                received = subscription.receive() => received,
            };
            match received {
                Ok(mut event) => {
                    if event.cursor.daemon_instance_id != expected.daemon_instance_id
                        || event.cursor.sequence != expected.sequence.saturating_add(1)
                    {
                        close_for_event_gap(
                            &outgoing,
                            ServerMessage::EventGap(EventGap {
                                message_id: MessageId::new_v7(),
                                occurred_at: UtcTimestamp::now(),
                                reason: EventGapReason::SequenceMismatch,
                                expected_cursor: expected.next(),
                                observed_cursor: Some(event.cursor),
                                action: EventGapAction::ReconnectForSnapshot,
                            }),
                            &connection_end,
                        );
                        break;
                    }
                    if !version_at_least(negotiated, event.event.minimum_protocol_version()) {
                        // The cursor is global and cannot skip an event without
                        // creating a false contiguous stream. Close the legacy
                        // session for a new authoritative snapshot instead of
                        // leaking an unknown 1.1 event or lying about continuity.
                        close_for_event_gap(
                            &outgoing,
                            ServerMessage::EventGap(EventGap {
                                message_id: MessageId::new_v7(),
                                occurred_at: UtcTimestamp::now(),
                                reason: EventGapReason::SequenceMismatch,
                                expected_cursor: expected.next(),
                                observed_cursor: Some(event.cursor),
                                action: EventGapAction::ReconnectForSnapshot,
                            }),
                            &connection_end,
                        );
                        break;
                    }
                    expected = event.cursor;
                    normalize_event_for_protocol(&mut event.event, negotiated);
                    let metadata = EventMetadata {
                        message_id: event.message_id,
                        schema_version: stein_protocol::SCHEMA_VERSION_V1,
                        occurred_at: event.occurred_at,
                        correlation_id: event.correlation_id,
                        causation_id: event.causation_id,
                        actor: event.actor,
                        origin: Component::CoreApplication,
                        sensitivity: event.sensitivity,
                        retention: event.retention,
                        trace_context: None,
                    };
                    if !send_until_closed(
                        &outgoing,
                        ServerMessage::Event(EventEnvelope {
                            cursor: event.cursor,
                            metadata,
                            event: event.event,
                        }),
                        &connection_end,
                    )
                    .await
                    {
                        connection_end.cancel();
                        break;
                    }
                }
                Err(EventStreamError::Gap { .. }) => {
                    close_for_event_gap(
                        &outgoing,
                        ServerMessage::EventGap(EventGap {
                            message_id: MessageId::new_v7(),
                            occurred_at: UtcTimestamp::now(),
                            reason: EventGapReason::ConsumerLagged,
                            expected_cursor: expected.next(),
                            observed_cursor: None,
                            action: EventGapAction::ReconnectForSnapshot,
                        }),
                        &connection_end,
                    );
                    break;
                }
                Err(EventStreamError::Closed) => {
                    connection_end.cancel();
                    break;
                }
            }
        }
    }

    async fn send_until_closed(
        outgoing: &mpsc::Sender<ServerMessage>,
        message: ServerMessage,
        connection_end: &CancellationToken,
    ) -> bool {
        tokio::select! {
            biased;
            () = connection_end.cancelled() => false,
            result = timeout(OUTBOUND_QUEUE_TIMEOUT, outgoing.send(message)) => {
                matches!(result, Ok(Ok(())))
            },
        }
    }

    fn close_for_event_gap(
        outgoing: &mpsc::Sender<ServerMessage>,
        message: ServerMessage,
        connection_end: &CancellationToken,
    ) {
        // A diagnostic gap frame is best-effort. Connection termination is the
        // authoritative signal to reconnect, so a saturated client must never
        // be able to block that termination indefinitely.
        let _ = outgoing.try_send(message);
        connection_end.cancel();
    }

    async fn writer_loop<W>(
        mut writer: W,
        mut incoming: mpsc::Receiver<ServerMessage>,
        connection_end: CancellationToken,
    ) where
        W: AsyncWrite + Unpin,
    {
        while let Some(message) = incoming.recv().await {
            if !matches!(
                timeout(OUTBOUND_WRITE_TIMEOUT, write_frame(&mut writer, &message)).await,
                Ok(Ok(()))
            ) {
                connection_end.cancel();
                break;
            }
        }
    }

    fn validate_client_hello(hello: &ClientHello) -> Result<(), &'static str> {
        if hello.client_instance_id.as_uuid().is_nil() {
            return Err("The client instance identifier must not be nil.");
        }
        if hello.client_name.trim().is_empty() || hello.client_name.chars().count() > 100 {
            return Err("The client name must contain between 1 and 100 characters.");
        }
        if hello.client_build_id.trim().is_empty() || hello.client_build_id.chars().count() > 100 {
            return Err("The client build identifier must contain between 1 and 100 characters.");
        }
        if hello.protocol_support.minimum_minor > hello.protocol_support.maximum_minor {
            return Err("The client protocol minor-version range is invalid.");
        }
        if hello.max_frame_bytes < MAX_FRAME_BYTES as u32 {
            return Err("The client frame-size limit is below CORE's required protocol limit.");
        }
        if hello
            .capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| hello.capabilities[..index].contains(capability))
        {
            return Err("The client capability list contains a duplicate.");
        }
        Ok(())
    }

    fn request_cancellation(
        in_flight: &HashMap<RequestId, InFlightRequest>,
        request_id: RequestId,
        cancellation_id: CancellationId,
    ) -> CancellationStatus {
        match in_flight.get(&request_id) {
            Some(request) if request.cancellation_id == Some(cancellation_id) => {
                request.token.cancel();
                CancellationStatus::CancellationRequested
            }
            Some(_) | None => CancellationStatus::RequestNotFound,
        }
    }

    fn error_response(
        request: &RequestEnvelope,
        actor: ActorReference,
        error: PublicError,
    ) -> ServerMessage {
        ServerMessage::Response(ResponseEnvelope {
            request_id: request.request_id,
            metadata: ResponseMetadata::for_request(&request.metadata, actor),
            outcome: ResponseOutcome::Error(error),
        })
    }

    fn fatal(
        reason: FatalReason,
        code: ErrorCode,
        category: ErrorCategory,
        summary: &str,
    ) -> ServerMessage {
        let correlation_id = stein_protocol::CorrelationId::new_v7();
        ServerMessage::Fatal(FatalFrame {
            reason,
            error: PublicError {
                code,
                category,
                summary: summary.to_owned(),
                retryable: false,
                correlation_id,
                details: None,
            },
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use stein_protocol::CapabilityId;
        use tokio::net::windows::named_pipe::ClientOptions;

        fn fixture_hello() -> ClientHello {
            let message: ClientMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/client-open-session.json"
            ))
            .expect("client fixture must decode");
            let ClientMessage::OpenSession(hello) = message else {
                panic!("fixture must be OpenSession");
            };
            hello
        }

        fn request(body: RequestBody, sensitivity: SensitivityClass) -> RequestEnvelope {
            RequestEnvelope::new(
                RequestMetadata::new(Component::TestFixture, sensitivity, RetentionClass::Runtime),
                body,
            )
        }

        #[test]
        fn validates_handshake_identity_limits_and_capability_set() {
            let hello = fixture_hello();
            validate_client_hello(&hello).expect("golden hello must be valid");

            let mut blank_name = hello.clone();
            blank_name.client_name = "  ".into();
            assert!(validate_client_hello(&blank_name).is_err());

            let mut small_frames = hello.clone();
            small_frames.max_frame_bytes = MAX_FRAME_BYTES as u32 - 1;
            assert!(validate_client_hello(&small_frames).is_err());

            let mut invalid_range = hello.clone();
            invalid_range.protocol_support.minimum_minor = 2;
            invalid_range.protocol_support.maximum_minor = 1;
            assert!(validate_client_hello(&invalid_range).is_err());

            let mut duplicate = hello;
            duplicate.capabilities.push(duplicate.capabilities[0]);
            assert!(validate_client_hello(&duplicate).is_err());
        }

        #[test]
        fn named_pipe_admission_is_diagnostic_and_private_test_admission_is_explicit() {
            assert_eq!(
                SessionAdmission::Diagnostic.assurance(),
                ClientAssurance::Diagnostic
            );
            assert_eq!(
                SessionAdmission::PrivateCapabilityBoundForTest.assurance(),
                ClientAssurance::PrivateCapabilityBound
            );
        }

        #[test]
        fn open_session_deadline_must_be_positive() {
            let config = ServerConfig {
                handshake_timeout: Duration::ZERO,
                ..ServerConfig::default()
            };
            assert!(matches!(
                validate_config(&config),
                Err(ServerError::InvalidConfig(
                    "handshake_timeout must be positive"
                ))
            ));
        }

        #[test]
        fn production_private_identity_is_exact_and_never_accepts_development_identity() {
            const PFN: &str = "STEIN.PersonalIntelligence_qrfd6g9swygw6";
            const AUMID: &str = "STEIN.PersonalIntelligence_qrfd6g9swygw6!PrivateBroker";

            let identity = PrivateServerIdentity::production(PFN, AUMID)
                .expect("syntactically exact production identity");
            assert_eq!(format!("{identity:?}"), "PrivateServerIdentity([redacted])");

            for (package_family_name, broker_aumid) in [
                (
                    "STEIN.PersonalIntelligence.Dev_qrfd6g9swygw6",
                    "STEIN.PersonalIntelligence.Dev_qrfd6g9swygw6!PrivateBroker",
                ),
                (PFN, "STEIN.PersonalIntelligence_qrfd6g9swygw6!Desktop"),
                (
                    "STEIN.PersonalIntelligence_QRFD6G9SWYGW6",
                    "STEIN.PersonalIntelligence_QRFD6G9SWYGW6!PrivateBroker",
                ),
                (
                    "STEIN.PersonalIntelligence_qrfd6g9swygw",
                    "STEIN.PersonalIntelligence_qrfd6g9swygw!PrivateBroker",
                ),
            ] {
                assert!(
                    matches!(
                        PrivateServerIdentity::production(package_family_name, broker_aumid),
                        Err(ServerError::InvalidPrivateIdentity)
                    ),
                    "an inexact or development package identity must fail closed"
                );
            }
        }

        #[tokio::test]
        async fn production_listener_rejects_unpacked_peer_before_reading_buffered_frame() {
            const PFN: &str = "STEIN.PersonalIntelligence_qrfd6g9swygw6";
            const AUMID: &str = "STEIN.PersonalIntelligence_qrfd6g9swygw6!PrivateBroker";

            let admission = ListenerAdmission::ProductionPrivate {
                identity: PrivateServerIdentity::production(PFN, AUMID)
                    .expect("syntactically exact production identity"),
                daemon_instance: *Uuid::now_v7().as_bytes(),
            };
            let pipe_name = format!(
                r"\\.\pipe\LOCAL\stein-core-private-adversarial-{}",
                Uuid::now_v7()
            );
            let mut server = admission
                .create_listener(&pipe_name, true)
                .expect("create private listener");
            let mut client = ClientOptions::new()
                .open(&pipe_name)
                .expect("same-user test client can reach the kernel boundary");
            server.connect().await.expect("accept test client");

            write_frame(&mut client, &ClientMessage::OpenSession(fixture_hello()))
                .await
                .expect("buffer a syntactically valid first frame");

            let error = admission
                .admit(&server, Duration::from_secs(5))
                .expect_err("an unpackaged process must not be admitted as the broker");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

            // The exact frame is still waiting in the kernel buffer. Admission
            // inspected only kernel process/token state and never decoded it.
            let buffered = timeout(
                Duration::from_secs(1),
                read_frame::<_, ClientMessage>(&mut server),
            )
            .await
            .expect("buffered frame read deadline")
            .expect("read untouched buffered frame");
            assert!(matches!(buffered, ClientMessage::OpenSession(_)));
        }

        #[cfg(feature = "private-client-test-harness")]
        #[test]
        fn private_test_admission_uses_a_randomized_non_production_endpoint() {
            let first = crate::PrivateTestEndpoint::new().expect("test endpoint");
            let second = crate::PrivateTestEndpoint::new().expect("test endpoint");
            assert_ne!(first, second);
            assert_ne!(first.pipe_name(), default_pipe_name().unwrap());
            assert!(first.pipe_name().contains("stein-core-private-test-"));
        }

        #[test]
        fn diagnostic_allowlist_is_closed_and_exhaustive() {
            for kind in RequestKind::ALL {
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
                assert!(!request_allowed(
                    ClientAssurance::NativeEmergencyControl,
                    kind
                ));
            }
        }

        #[test]
        fn admission_and_protocol_minimum_fail_before_dispatch() {
            let runtime = request(
                RequestBody::GetRuntimeStatus(GetRuntimeStatusRequest::default()),
                SensitivityClass::Operational,
            );
            validate_request_admission(
                &runtime,
                ClientAssurance::Diagnostic,
                ProtocolVersion::V1_0,
            )
            .expect("runtime status is the protocol 1.0 diagnostic query");

            let private = request(
                RequestBody::GetSnapshot(stein_protocol::GetSnapshotRequest::default()),
                SensitivityClass::Personal,
            );
            let error = validate_request_admission(
                &private,
                ClientAssurance::Diagnostic,
                ProtocolVersion::V1_0,
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::PermissionDenied);

            let capability_health = request(
                RequestBody::GetCapabilityHealth(
                    stein_protocol::GetCapabilityHealthRequest::default(),
                ),
                SensitivityClass::Operational,
            );
            let error = validate_request_admission(
                &capability_health,
                ClientAssurance::Diagnostic,
                ProtocolVersion::V1_0,
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::IncompatibleProtocol);

            let wrong_classification = request(
                RequestBody::GetRuntimeStatus(GetRuntimeStatusRequest::default()),
                SensitivityClass::Personal,
            );
            let error = validate_request_admission(
                &wrong_classification,
                ClientAssurance::Diagnostic,
                ProtocolVersion::V1_1,
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }

        #[test]
        fn protocol_1_0_snapshot_normalization_removes_1_1_state_and_capabilities() {
            let message: ServerMessage = serde_json::from_str(include_str!(
                "../../../contracts/v1/server-session-opened-v1-1.json"
            ))
            .expect("Phase 2 session fixture must decode");
            let ServerMessage::SessionOpened(opened) = message else {
                panic!("fixture must be SessionOpened");
            };
            let mut snapshot = opened.snapshot;

            normalize_snapshot_for_protocol(&mut snapshot, ProtocolVersion::V1_0);

            assert_eq!(snapshot.runtime.protocol_version, ProtocolVersion::V1_0);
            assert!(snapshot.phase2.is_none());
            assert!(
                snapshot
                    .capabilities
                    .iter()
                    .all(|health| capability_supported(health.capability, ProtocolVersion::V1_0))
            );
            assert!(
                !snapshot
                    .capabilities
                    .iter()
                    .any(|health| health.capability == CapabilityId::FocusSessions)
            );
        }

        #[test]
        fn protocol_1_0_never_supports_phase2_view_events() {
            let events: Vec<ViewEvent> = serde_json::from_str(include_str!(
                "../../../contracts/v1/phase2-view-events.json"
            ))
            .expect("Phase 2 event fixture must decode");
            assert!(events.iter().all(|event| {
                !version_at_least(ProtocolVersion::V1_0, event.minimum_protocol_version())
            }));
            assert!(events.iter().all(|event| version_at_least(
                ProtocolVersion::CURRENT,
                event.minimum_protocol_version(),
            )));
            assert!(
                events
                    .iter()
                    .any(|event| { event.minimum_protocol_version() == ProtocolVersion::V1_1 })
            );
            assert!(
                events
                    .iter()
                    .any(|event| { event.minimum_protocol_version() == ProtocolVersion::V1_2 })
            );
        }

        #[test]
        fn cancellation_id_must_match_the_target_request() {
            let request_id = RequestId::new_v7();
            let cancellation_id = CancellationId::new_v7();
            let token = CancellationToken::new();
            let mut in_flight = HashMap::new();
            in_flight.insert(
                request_id,
                InFlightRequest {
                    cancellation_id: Some(cancellation_id),
                    token: token.clone(),
                },
            );

            assert_eq!(
                request_cancellation(&in_flight, request_id, CancellationId::new_v7()),
                CancellationStatus::RequestNotFound
            );
            assert!(!token.is_cancelled());
            assert_eq!(
                request_cancellation(&in_flight, request_id, cancellation_id),
                CancellationStatus::CancellationRequested
            );
            assert!(token.is_cancelled());
        }

        #[test]
        fn phase2_source_fixture_phase1_regression_preserves_server_contracts() {
            let negotiated = negotiate_protocol(ProtocolSupport::V1, ProtocolSupport::V1)
                .expect("the retained protocol range must negotiate");
            assert_eq!(negotiated, ProtocolVersion::CURRENT);
            assert!(matches!(
                negotiate_protocol(
                    ProtocolSupport {
                        major: ProtocolSupport::V1.major + 1,
                        minimum_minor: 0,
                        maximum_minor: 0,
                    },
                    ProtocolSupport::V1,
                ),
                Err(stein_protocol::CompatibilityError::MajorVersionMismatch { .. })
            ));

            let config = ServerConfig::default();
            assert_eq!(config.maximum_connections, 8);
            let connections = Arc::new(Semaphore::new(config.maximum_connections));
            let active_connections = Arc::new(AtomicU32::new(0));
            let mut admitted = Vec::with_capacity(config.maximum_connections);
            for _ in 0..config.maximum_connections {
                let permit = try_admit_connection(&connections)
                    .expect("every configured connection slot must admit once");
                admitted.push(ActiveConnectionGuard::new(
                    active_connections.clone(),
                    permit,
                ));
            }
            assert_eq!(
                active_connections.load(Ordering::SeqCst),
                config.maximum_connections as u32
            );
            assert!(
                try_admit_connection(&connections).is_none(),
                "the first connection beyond the configured limit must be rejected"
            );

            drop(admitted.pop().expect("one admitted connection"));
            assert_eq!(
                active_connections.load(Ordering::SeqCst),
                (config.maximum_connections - 1) as u32
            );
            let replacement = ActiveConnectionGuard::new(
                active_connections.clone(),
                try_admit_connection(&connections)
                    .expect("a released connection slot must admit a replacement"),
            );
            assert_eq!(
                active_connections.load(Ordering::SeqCst),
                config.maximum_connections as u32
            );
            drop(replacement);
            drop(admitted);
            assert_eq!(active_connections.load(Ordering::SeqCst), 0);
            assert_eq!(connections.available_permits(), config.maximum_connections);

            let request_id = RequestId::new_v7();
            let cancellation_id = CancellationId::new_v7();
            let cancellation = CancellationToken::new();
            let in_flight = HashMap::from([(
                request_id,
                InFlightRequest {
                    cancellation_id: Some(cancellation_id),
                    token: cancellation.clone(),
                },
            )]);
            assert_eq!(
                request_cancellation(&in_flight, request_id, CancellationId::new_v7()),
                CancellationStatus::RequestNotFound
            );
            assert!(!cancellation.is_cancelled());
            assert_eq!(
                request_cancellation(&in_flight, request_id, cancellation_id),
                CancellationStatus::CancellationRequested
            );
            assert!(cancellation.is_cancelled());
        }

        #[test]
        fn event_gap_termination_is_not_blocked_by_a_full_outbound_queue() {
            let (outgoing, _incoming) = mpsc::channel(1);
            outgoing
                .try_send(fatal(
                    FatalReason::ServerStopping,
                    ErrorCode::Internal,
                    ErrorCategory::Internal,
                    "synthetic queue occupant",
                ))
                .expect("queue starts empty");
            let connection_end = CancellationToken::new();

            close_for_event_gap(
                &outgoing,
                fatal(
                    FatalReason::ServerStopping,
                    ErrorCode::Internal,
                    ErrorCategory::Internal,
                    "synthetic gap frame",
                ),
                &connection_end,
            );

            assert!(connection_end.is_cancelled());
        }

        #[test]
        fn rejected_shutdown_requests_never_commit_process_shutdown() {
            let mut metadata = stein_protocol::RequestMetadata::new(
                Component::TestFixture,
                stein_protocol::SensitivityClass::Operational,
                stein_protocol::RetentionClass::Runtime,
            );
            metadata.schema_version = u16::MAX;
            let request = RequestEnvelope::new(
                metadata,
                RequestBody::Shutdown(stein_protocol::ShutdownRequest {
                    reason: stein_protocol::ShutdownReason::Test,
                }),
            );
            let rejected = Err(PublicError {
                code: ErrorCode::UnsupportedSchema,
                category: ErrorCategory::IncompatibleVersion,
                summary: "synthetic rejection".into(),
                retryable: false,
                correlation_id: request.metadata.correlation_id,
                details: None,
            });
            assert!(!accepted_shutdown(&request, &rejected));

            let accepted = Ok(stein_protocol::ResponseBody::Shutdown(
                stein_protocol::ShutdownResponse {
                    daemon_instance_id: stein_protocol::DaemonInstanceId::new_v7(),
                    accepted: true,
                },
            ));
            assert!(accepted_shutdown(&request, &accepted));
        }
    }
}

#[cfg(not(windows))]
mod implementation {
    use std::time::Duration;

    use stein_core::CoreRuntime;
    use thiserror::Error;

    #[derive(Clone, Debug)]
    pub struct PrivateServerIdentity;

    impl PrivateServerIdentity {
        pub fn production(
            _package_family_name: impl Into<String>,
            _broker_aumid: impl Into<String>,
        ) -> Result<Self, ServerError> {
            Err(ServerError::Unsupported)
        }
    }

    #[derive(Clone, Debug)]
    pub struct ServerConfig {
        pub maximum_connections: usize,
        pub maximum_in_flight_per_connection: usize,
        pub maximum_requests_per_window: usize,
        pub request_rate_window: Duration,
        pub handshake_timeout: Duration,
        pub idle_timeout: Duration,
        pub shutdown_grace: Duration,
    }

    impl Default for ServerConfig {
        fn default() -> Self {
            Self {
                maximum_connections: 8,
                maximum_in_flight_per_connection: 16,
                maximum_requests_per_window: 120,
                request_rate_window: Duration::from_secs(10),
                handshake_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(300),
                shutdown_grace: Duration::from_secs(1),
            }
        }
    }

    #[derive(Debug, Error)]
    pub enum ServerError {
        #[error("the Phase 1 native server is implemented on Windows first")]
        Unsupported,
    }

    pub async fn run_server(_core: CoreRuntime, _config: ServerConfig) -> Result<(), ServerError> {
        Err(ServerError::Unsupported)
    }

    pub async fn run_private_server(
        _core: CoreRuntime,
        _config: ServerConfig,
        _identity: PrivateServerIdentity,
    ) -> Result<(), ServerError> {
        Err(ServerError::Unsupported)
    }

    #[cfg(feature = "private-client-test-harness")]
    pub async fn run_private_capability_bound_test_server(
        _core: CoreRuntime,
        _config: ServerConfig,
        _endpoint: &crate::PrivateTestEndpoint,
    ) -> Result<(), ServerError> {
        Err(ServerError::Unsupported)
    }
}

#[cfg(feature = "private-client-test-harness")]
pub use implementation::run_private_capability_bound_test_server;
pub use implementation::{
    PrivateServerIdentity, ServerConfig, ServerError, run_private_server, run_server,
};
