use std::{collections::BTreeSet, fs, path::PathBuf, str::FromStr};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use stein_protocol::*;

const CLIENT_FIXTURES: &[&str] = &[
    "client-open-session.json",
    "client-open-session-v1-1.json",
    "client-create-goal.json",
    "client-start-focus-session.json",
    "client-get-snapshot.json",
    "client-get-runtime-status.json",
    "client-delay-echo.json",
    "client-shutdown.json",
    "client-cancel.json",
];
const SERVER_FIXTURES: &[&str] = &[
    "server-session-opened.json",
    "server-session-opened-v1-1.json",
    "server-create-goal-response.json",
    "server-start-focus-session-response.json",
    "server-get-snapshot-response.json",
    "server-get-runtime-status-response.json",
    "server-delay-echo-response.json",
    "server-shutdown-response.json",
    "server-goal-event.json",
    "server-focus-session-event.json",
    "server-runtime-status-event.json",
    "server-error-response.json",
    "server-cancel-acknowledged.json",
    "server-event-gap.json",
    "server-fatal.json",
];

const PHASE_2_REQUEST_FIXTURE: &str = "phase2-request-bodies.json";
const PHASE_2_RESPONSE_FIXTURE: &str = "phase2-response-bodies.json";
const PHASE_2_EVENT_FIXTURE: &str = "phase2-view-events.json";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("contracts/v1")
        .join(name)
}

fn fixture_text(name: &str) -> String {
    fs::read_to_string(fixture_path(name)).expect("golden fixture should be readable")
}

fn fixture<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_str(&fixture_text(name)).expect("golden fixture should decode")
}

fn assert_fixture_round_trip<T>(name: &str)
where
    T: Serialize + DeserializeOwned,
{
    let source: Value = serde_json::from_str(&fixture_text(name)).unwrap();
    let typed: T = fixture(name);
    let encoded = serde_json::to_value(typed).unwrap();
    assert_eq!(encoded, source, "fixture {name} drifted");
}

fn assert_json_round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
{
    let encoded = serde_json::to_vec(value).expect("value should encode");
    let decoded: T = serde_json::from_slice(&encoded).expect("value should decode");
    assert_eq!(&decoded, value);
}

#[test]
fn policy_trace_is_additive_and_legacy_decisions_remain_readable() {
    let mut legacy = serde_json::json!({
        "policy_decision_id": "01990000-0000-7000-8000-000000000001",
        "policy_version": "phase2-focus-v1",
        "outcome": "allow",
        "reason_codes": [],
        "authority": [],
        "issued_at": "2026-08-20T10:00:00Z",
        "expires_at": "2026-08-20T10:00:30Z"
    });
    let legacy_decision: PolicyDecisionView = serde_json::from_value(legacy.clone()).unwrap();
    assert!(legacy_decision.policy_trace.is_none());
    assert_eq!(serde_json::to_value(legacy_decision).unwrap(), legacy);

    legacy.as_object_mut().unwrap().insert(
        "policy_trace".to_owned(),
        serde_json::json!({
            "policy_profile_id": "phase2-focus-v1",
            "user_preferences_revision": 7,
            "proposed_input_schema_version": 1,
            "proposed_input_digest": vec![9_u8; 32]
        }),
    );
    let traced: PolicyDecisionView = serde_json::from_value(legacy.clone()).unwrap();
    let trace = traced.policy_trace.as_ref().unwrap();
    assert_eq!(trace.user_preferences_revision, 7);
    assert_eq!(trace.proposed_input_digest, [9; 32]);
    assert_eq!(serde_json::to_value(traced).unwrap(), legacy);
}

#[test]
fn model_request_receipt_is_additive_query_only_and_content_free() {
    let bodies = fixture::<Vec<ResponseBody>>(PHASE_2_RESPONSE_FIXTURE);
    let response = bodies
        .iter()
        .find_map(|body| match body {
            ResponseBody::GetFocusSessionView(response) => Some(response),
            _ => None,
        })
        .expect("focus-session response fixture should exist");
    let receipt = response
        .latest_model_request_receipt
        .as_ref()
        .expect("protocol 1.2 fixture should carry a receipt");
    assert_eq!(
        receipt.focus_session_id,
        response.focus_session.focus_session_id
    );
    assert_eq!(
        receipt.model_route_approval_id,
        response.focus_session.model_route_approval_id
    );
    assert_eq!(receipt.model_route_revision, 1);
    assert_eq!(
        receipt.outcome,
        ModelRequestReceiptOutcome::CompletedStrictCandidate
    );
    assert!(receipt.completed_at.is_some());

    let encoded = serde_json::to_value(receipt).unwrap();
    let keys = encoded
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from([
            "completed_at",
            "focus_session_id",
            "model_route_approval_id",
            "model_route_revision",
            "outcome",
            "request_id",
            "started_at",
        ])
    );

    let mut legacy = serde_json::to_value(
        bodies
            .iter()
            .find(|body| matches!(body, ResponseBody::GetFocusSessionView(_)))
            .unwrap(),
    )
    .unwrap();
    legacy["payload"]
        .as_object_mut()
        .unwrap()
        .remove("latest_model_request_receipt");
    let decoded: ResponseBody = serde_json::from_value(legacy.clone()).unwrap();
    let ResponseBody::GetFocusSessionView(decoded) = decoded else {
        unreachable!();
    };
    assert!(decoded.latest_model_request_receipt.is_none());
    assert_eq!(
        serde_json::to_value(ResponseBody::GetFocusSessionView(decoded)).unwrap(),
        legacy
    );
}

#[test]
fn all_checked_in_fixtures_round_trip_without_shape_changes() {
    for name in CLIENT_FIXTURES {
        let source: Value = serde_json::from_str(&fixture_text(name)).unwrap();
        let typed: ClientMessage = fixture(name);
        let encoded = serde_json::to_value(typed).unwrap();
        assert_eq!(encoded, source, "client fixture {name} drifted");
    }

    for name in SERVER_FIXTURES {
        let source: Value = serde_json::from_str(&fixture_text(name)).unwrap();
        let typed: ServerMessage = fixture(name);
        let encoded = serde_json::to_value(typed).unwrap();
        assert_eq!(encoded, source, "server fixture {name} drifted");
    }

    assert_fixture_round_trip::<Vec<RequestBody>>(PHASE_2_REQUEST_FIXTURE);
    assert_fixture_round_trip::<Vec<ResponseBody>>(PHASE_2_RESPONSE_FIXTURE);
    assert_fixture_round_trip::<Vec<ViewEvent>>(PHASE_2_EVENT_FIXTURE);
}

#[test]
fn golden_fixtures_cover_every_public_request_response_and_event_variant() {
    let client_message_kinds = CLIENT_FIXTURES
        .iter()
        .map(|name| fixture::<ClientMessage>(name).kind())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        client_message_kinds,
        ClientMessageKind::ALL.into_iter().collect::<BTreeSet<_>>()
    );

    let server_message_kinds = SERVER_FIXTURES
        .iter()
        .map(|name| fixture::<ServerMessage>(name).kind())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        server_message_kinds,
        ServerMessageKind::ALL.into_iter().collect::<BTreeSet<_>>()
    );

    let mut request_kinds = BTreeSet::new();
    for name in CLIENT_FIXTURES {
        if let ClientMessage::Request(request) = fixture::<ClientMessage>(name) {
            request_kinds.insert(request.body.kind());
        }
    }
    request_kinds.extend(
        fixture::<Vec<RequestBody>>(PHASE_2_REQUEST_FIXTURE)
            .iter()
            .map(RequestBody::kind),
    );
    assert_eq!(
        request_kinds,
        RequestKind::ALL.into_iter().collect::<BTreeSet<_>>()
    );

    let mut response_kinds = BTreeSet::new();
    for name in SERVER_FIXTURES {
        if let ServerMessage::Response(response) = fixture::<ServerMessage>(name)
            && let ResponseOutcome::Success(body) = response.outcome
        {
            response_kinds.insert(body.kind());
        }
    }
    response_kinds.extend(
        fixture::<Vec<ResponseBody>>(PHASE_2_RESPONSE_FIXTURE)
            .iter()
            .map(ResponseBody::kind),
    );
    assert_eq!(
        response_kinds,
        RequestKind::ALL.into_iter().collect::<BTreeSet<_>>()
    );

    let mut event_kinds = BTreeSet::new();
    for name in SERVER_FIXTURES {
        if let ServerMessage::Event(event) = fixture::<ServerMessage>(name) {
            event_kinds.insert(event.event.kind());
        }
    }
    event_kinds.extend(
        fixture::<Vec<ViewEvent>>(PHASE_2_EVENT_FIXTURE)
            .iter()
            .map(ViewEvent::kind),
    );
    assert_eq!(
        event_kinds,
        ViewEventKind::ALL.into_iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn golden_fixtures_have_the_expected_semantics() {
    let ClientMessage::Request(request) = fixture::<ClientMessage>("client-create-goal.json")
    else {
        panic!("expected request fixture");
    };
    assert_eq!(request.body.kind(), RequestKind::CreateGoal);
    assert!(request.metadata.idempotency_key.is_some());
    assert!(request.metadata.deadline_at.is_some());
    assert!(request.metadata.cancellation_id.is_some());
    let RequestBody::CreateGoal(create) = request.body else {
        unreachable!();
    };
    assert_eq!(create.title, "Synthetic Atlas brief");
    assert!(create.deadline.is_some());

    let ServerMessage::SessionOpened(opened) =
        fixture::<ServerMessage>("server-session-opened.json")
    else {
        panic!("expected session fixture");
    };
    assert_eq!(opened.protocol_version, ProtocolVersion::V1_0);
    assert_eq!(opened.snapshot.cursor.sequence, 4);
    assert_eq!(opened.snapshot.runtime.state, RuntimeState::Ready);
    for capability in [
        CapabilityId::DesktopObservation,
        CapabilityId::ModelReasoning,
        CapabilityId::DurablePersistence,
        CapabilityId::NativeNotification,
        CapabilityId::NativeStatus,
        CapabilityId::EmergencyControl,
        CapabilityId::SecretStore,
    ] {
        let health = opened
            .capabilities
            .iter()
            .find(|health| health.capability == capability)
            .expect("deferred capability must be disclosed");
        assert_eq!(health.state, HealthState::Unavailable);
        assert_eq!(
            health.unavailable_reason,
            Some(CapabilityUnavailableReason::NotImplemented)
        );
    }

    let ServerMessage::Event(event) = fixture::<ServerMessage>("server-goal-event.json") else {
        panic!("expected event fixture");
    };
    assert_eq!(event.cursor.sequence, 5);
    let ViewEvent::GoalViewChanged(changed) = event.event else {
        unreachable!();
    };
    assert_eq!(changed.change, GoalChangeKind::Created);
    assert_eq!(changed.goal.revision, 1);

    let ClientMessage::Request(start) = fixture::<ClientMessage>("client-start-focus-session.json")
    else {
        panic!("expected Phase 2 request fixture");
    };
    assert_eq!(start.body.kind(), RequestKind::StartFocusSession);
    assert_eq!(start.body.minimum_protocol_version(), ProtocolVersion::V1_1);
    assert!(start.body.kind().requires_idempotency_key());
    assert!(start.metadata.idempotency_key.is_some());
    assert!(start.metadata.deadline_at.is_some());
    assert!(start.metadata.cancellation_id.is_some());
    assert_eq!(start.metadata.authority.len(), 1);
    assert_eq!(start.metadata.sensitivity, SensitivityClass::Restricted);

    let ServerMessage::SessionOpened(opened) =
        fixture::<ServerMessage>("server-session-opened-v1-1.json")
    else {
        panic!("expected Phase 2 session fixture");
    };
    assert_eq!(opened.protocol_version, ProtocolVersion::V1_1);
    let phase2 = opened
        .snapshot
        .phase2
        .expect("protocol 1.1 snapshot must carry authoritative Phase 2 state");
    assert_eq!(phase2.focus_sessions.len(), 1);
    assert_eq!(phase2.capture_states.len(), 1);
    assert_eq!(phase2.permission_records.len(), 2);
    assert_eq!(phase2.delivery_channels.len(), 1);
    assert_eq!(phase2.intervention_history.entries.len(), 1);
    let PermissionRecordView::SessionGrant(grant) = &phase2.permission_records[0] else {
        panic!("expected a session grant");
    };
    assert_eq!(grant.retention, RetentionClass::DurableUntilExpiry);
    assert_eq!(
        phase2.intervention_history.entries[0].retention,
        RetentionClass::BoundedAudit
    );
}

#[test]
fn every_client_and_server_variant_round_trips() {
    let open: ClientMessage = fixture("client-open-session.json");
    let create: ClientMessage = fixture("client-create-goal.json");
    let cancel: ClientMessage = fixture("client-cancel.json");
    assert_json_round_trip(&open);
    assert_json_round_trip(&create);
    assert_json_round_trip(&cancel);

    let ClientMessage::Request(base_request) = create else {
        unreachable!();
    };
    for body in [
        RequestBody::GetSnapshot(GetSnapshotRequest::default()),
        RequestBody::GetRuntimeStatus(GetRuntimeStatusRequest::default()),
        RequestBody::DelayEcho(DelayEchoRequest {
            delay_ms: 25,
            text: "synthetic echo".to_owned(),
        }),
        RequestBody::Shutdown(ShutdownRequest {
            reason: ShutdownReason::Test,
        }),
    ] {
        let message = ClientMessage::Request(RequestEnvelope {
            request_id: base_request.request_id,
            metadata: base_request.metadata.clone(),
            body,
        });
        assert_json_round_trip(&message);
    }

    let session: ServerMessage = fixture("server-session-opened.json");
    let success: ServerMessage = fixture("server-create-goal-response.json");
    let event: ServerMessage = fixture("server-goal-event.json");
    let error: ServerMessage = fixture("server-error-response.json");
    let gap: ServerMessage = fixture("server-event-gap.json");
    for message in [&session, &success, &event, &error, &gap] {
        assert_json_round_trip(message);
    }

    let ServerMessage::SessionOpened(opened) = session else {
        unreachable!();
    };
    let ServerMessage::Response(base_response) = success else {
        unreachable!();
    };
    let response_bodies = [
        ResponseBody::GetSnapshot(GetSnapshotResponse {
            snapshot: opened.snapshot.clone(),
        }),
        ResponseBody::GetRuntimeStatus(GetRuntimeStatusResponse {
            runtime: opened.snapshot.runtime.clone(),
            capabilities: opened.capabilities.clone(),
        }),
        ResponseBody::DelayEcho(DelayEchoResponse {
            text: "synthetic echo".to_owned(),
            completed_after_ms: 25,
        }),
        ResponseBody::Shutdown(ShutdownResponse {
            daemon_instance_id: opened.daemon_instance_id,
            accepted: true,
        }),
    ];
    for body in response_bodies {
        assert_json_round_trip(&ServerMessage::Response(ResponseEnvelope {
            request_id: base_response.request_id,
            metadata: base_response.metadata.clone(),
            outcome: ResponseOutcome::Success(body),
        }));
    }

    assert_json_round_trip(&ServerMessage::Event(EventEnvelope {
        cursor: opened.snapshot.cursor.next(),
        metadata: match event {
            ServerMessage::Event(event) => event.metadata,
            _ => unreachable!(),
        },
        event: ViewEvent::RuntimeStatusChanged(RuntimeStatusChanged {
            runtime: opened.snapshot.runtime.clone(),
        }),
    }));

    let ClientMessage::Cancel(cancel) = cancel else {
        unreachable!();
    };
    assert_json_round_trip(&ServerMessage::CancelAcknowledged(CancelAcknowledged {
        message_id: MessageId::new_v7(),
        issued_at: UtcTimestamp::now(),
        correlation_id: cancel.correlation_id,
        causation_id: cancel.message_id,
        actor: opened.authenticated_actor.clone(),
        target_request_id: cancel.target_request_id,
        cancellation_id: cancel.cancellation_id,
        status: CancellationStatus::CancellationRequested,
    }));

    let ServerMessage::Response(error_response) = error else {
        unreachable!();
    };
    let ResponseOutcome::Error(public_error) = error_response.outcome else {
        unreachable!();
    };
    assert_json_round_trip(&ServerMessage::Fatal(FatalFrame {
        reason: FatalReason::MalformedFrame,
        error: public_error,
    }));
}

#[test]
fn framed_codec_round_trips_and_enforces_declared_bounds() {
    let message: ClientMessage = fixture("client-open-session.json");
    let encoded = encode_frame(&message, DEFAULT_MAX_FRAME_BYTES).unwrap();
    let payload = split_complete_frame(&encoded, DEFAULT_MAX_FRAME_BYTES).unwrap();
    assert_eq!(
        decode_client_payload(payload, DEFAULT_MAX_FRAME_BYTES).unwrap(),
        message
    );

    assert!(matches!(
        parse_length_prefix(0_u32.to_le_bytes(), DEFAULT_MAX_FRAME_BYTES),
        Err(WireError::EmptyPayload)
    ));
    assert!(matches!(
        parse_length_prefix(65_u32.to_le_bytes(), 64),
        Err(WireError::FrameTooLarge {
            actual: 65,
            maximum: 64
        })
    ));
    assert!(matches!(
        split_complete_frame(&[1, 2, 3], 64),
        Err(WireError::TruncatedPrefix { actual: 3 })
    ));

    let mut mismatched = 5_u32.to_le_bytes().to_vec();
    mismatched.extend_from_slice(b"{}");
    assert!(matches!(
        split_complete_frame(&mismatched, 64),
        Err(WireError::LengthMismatch {
            declared: 5,
            actual: 2
        })
    ));
}

#[test]
fn protocol_negotiation_is_explicit() {
    let client = ProtocolSupport {
        major: 1,
        minimum_minor: 0,
        maximum_minor: 4,
    };
    let server = ProtocolSupport {
        major: 1,
        minimum_minor: 0,
        maximum_minor: 2,
    };
    assert_eq!(
        negotiate_protocol(client, server).unwrap(),
        ProtocolVersion { major: 1, minor: 2 }
    );

    assert!(matches!(
        negotiate_protocol(
            client,
            ProtocolSupport {
                major: 2,
                minimum_minor: 0,
                maximum_minor: 0
            }
        ),
        Err(CompatibilityError::MajorVersionMismatch { .. })
    ));
    assert!(matches!(
        negotiate_protocol(
            ProtocolSupport {
                major: 1,
                minimum_minor: 3,
                maximum_minor: 4
            },
            ProtocolSupport {
                major: 1,
                minimum_minor: 0,
                maximum_minor: 2
            }
        ),
        Err(CompatibilityError::NoSharedMinorVersion { .. })
    ));
    assert_eq!(
        negotiate_protocol(
            ProtocolSupport {
                major: 1,
                minimum_minor: 2,
                maximum_minor: 1
            },
            ProtocolSupport::V1
        ),
        Err(CompatibilityError::InvalidRange)
    );

    assert_eq!(
        negotiate_protocol(ProtocolSupport::V1_0, ProtocolSupport::V1).unwrap(),
        ProtocolVersion::V1_0
    );
    assert_eq!(
        negotiate_protocol(ProtocolSupport::V1_1, ProtocolSupport::V1).unwrap(),
        ProtocolVersion::V1_1
    );
    assert_eq!(
        negotiate_protocol(ProtocolSupport::V1, ProtocolSupport::V1).unwrap(),
        ProtocolVersion::CURRENT
    );
}

#[test]
fn timestamps_require_explicit_utc_and_serialize_canonically() {
    let timestamp = UtcTimestamp::from_str("2026-08-19T08:00:00Z").unwrap();
    assert_eq!(
        serde_json::to_string(&timestamp).unwrap(),
        "\"2026-08-19T08:00:00Z\""
    );
    assert!(UtcTimestamp::from_str("2026-08-19T09:00:00+01:00").is_err());
}

#[test]
fn additive_fields_are_ignored_but_unknown_variants_fail_closed() {
    let mut hello: Value = serde_json::from_str(&fixture_text("client-open-session.json")).unwrap();
    hello["body"]["unrecognized"] = Value::Bool(true);
    assert!(serde_json::from_value::<ClientMessage>(hello).is_ok());

    let unknown = serde_json::json!({"message_type":"execute_tool","body":{}});
    assert!(serde_json::from_value::<ClientMessage>(unknown).is_err());

    let phase2_requests: Vec<RequestBody> = fixture(PHASE_2_REQUEST_FIXTURE);
    assert!(phase2_requests.iter().all(|request| {
        !ProtocolSupport::V1_0.supports(request.minimum_protocol_version())
            && ProtocolSupport::V1.supports(request.minimum_protocol_version())
    }));
    assert!(
        phase2_requests
            .iter()
            .any(|request| { request.minimum_protocol_version() == ProtocolVersion::V1_1 })
    );
    assert!(
        phase2_requests
            .iter()
            .any(|request| { request.minimum_protocol_version() == ProtocolVersion::V1_2 })
    );

    let phase2_events: Vec<ViewEvent> = fixture(PHASE_2_EVENT_FIXTURE);
    assert!(phase2_events.iter().all(|event| {
        !ProtocolSupport::V1_0.supports(event.minimum_protocol_version())
            && ProtocolSupport::V1.supports(event.minimum_protocol_version())
    }));
    assert!(
        phase2_events
            .iter()
            .any(|event| { event.minimum_protocol_version() == ProtocolVersion::V1_1 })
    );
    assert!(
        phase2_events
            .iter()
            .any(|event| { event.minimum_protocol_version() == ProtocolVersion::V1_2 })
    );

    let unknown_request = serde_json::json!({
        "request_type": "execute_tool",
        "payload": {}
    });
    assert!(serde_json::from_value::<RequestBody>(unknown_request).is_err());

    let unknown_event = serde_json::json!({
        "event_type": "raw_observation_available",
        "payload": {}
    });
    assert!(serde_json::from_value::<ViewEvent>(unknown_event).is_err());
}

#[test]
fn fixtures_and_public_errors_are_privacy_safe() {
    let forbidden = [
        "password",
        "api_key",
        "authorization:",
        "bearer ",
        "sk-",
        "c:\\users\\",
        "/home/",
        "raw_observation",
        "raw_source_artifact",
        "normalized_observation",
        "screen_frame",
        "accessibility_tree",
        "model_prompt",
        "raw_response",
        "chain_of_thought",
        "provider_credential",
        "local_path",
    ];
    for name in CLIENT_FIXTURES
        .iter()
        .chain(SERVER_FIXTURES)
        .copied()
        .chain([
            PHASE_2_REQUEST_FIXTURE,
            PHASE_2_RESPONSE_FIXTURE,
            PHASE_2_EVENT_FIXTURE,
        ])
    {
        let lower = fixture_text(name).to_lowercase();
        for pattern in forbidden {
            assert!(
                !lower.contains(pattern),
                "fixture {name} contains prohibited pattern {pattern}"
            );
        }
    }

    let ServerMessage::Response(response) = fixture::<ServerMessage>("server-error-response.json")
    else {
        unreachable!();
    };
    let ResponseOutcome::Error(error) = response.outcome else {
        unreachable!();
    };
    assert!(!error.summary.contains("Synthetic Atlas brief"));

    let private_input = br#"{"message_type":"request","body":{"private":"DO_NOT_ECHO"}}"#;
    let display = decode_client_payload(private_input, DEFAULT_MAX_FRAME_BYTES)
        .unwrap_err()
        .to_string();
    assert!(!display.contains("DO_NOT_ECHO"));
    assert!(display.contains("line"));
}

#[test]
fn phase2_secrets_protocol_surface_is_closed_and_value_free() {
    let actual_request_kinds = RequestKind::ALL
        .into_iter()
        .map(|kind| {
            serde_json::to_value(kind)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let expected_request_kinds = [
        "abandon_goal",
        "approve_model_route",
        "complete_goal",
        "create_goal",
        "delay_echo",
        "delete_goal",
        "end_focus_session",
        "explain_intervention",
        "get_capability_health",
        "get_effective_policy",
        "get_focus_session_view",
        "get_goal",
        "get_intervention_history",
        "get_permission_view",
        "get_runtime_status",
        "get_selected_resources",
        "get_snapshot",
        "get_stein_identity",
        "get_user_preferences",
        "grant_session_permission",
        "record_intervention_feedback",
        "register_selected_resource",
        "remove_selected_resource",
        "revoke_permission",
        "set_interventions_muted",
        "shutdown",
        "start_focus_session",
        "update_goal",
        "update_user_preferences",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(actual_request_kinds, expected_request_kinds);

    let requests = fixture::<Vec<RequestBody>>(PHASE_2_REQUEST_FIXTURE);
    let RequestBody::ApproveModelRoute(request) = requests
        .iter()
        .find(|request| request.kind() == RequestKind::ApproveModelRoute)
        .expect("model-route approval request fixture")
    else {
        unreachable!();
    };
    let mut request = request.as_ref().clone();
    request.fallback = Some(request.route.clone());
    let ApproveModelRouteRequest {
        route: _,
        account_profile: _,
        allowed_data_categories: _,
        handling: _,
        purpose: _,
        maximum_request_tokens: _,
        fallback: _,
        expires_at: _,
        disclosure_version: _,
    } = &request;
    let encoded_request = serde_json::to_value(request).unwrap();
    let request_fields = encoded_request
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        request_fields,
        BTreeSet::from([
            "account_profile",
            "allowed_data_categories",
            "disclosure_version",
            "expires_at",
            "fallback",
            "handling",
            "maximum_request_tokens",
            "purpose",
            "route",
        ])
    );

    let responses = fixture::<Vec<ResponseBody>>(PHASE_2_RESPONSE_FIXTURE);
    let ResponseBody::ApproveModelRoute(response) = responses
        .iter()
        .find(|response| response.kind() == RequestKind::ApproveModelRoute)
        .expect("model-route approval response fixture")
    else {
        unreachable!();
    };
    let mut approval = response.approval.clone();
    approval.fallback = Some(approval.route.clone());
    approval.revoked_at = Some(approval.effective_at);
    let ModelRouteApprovalView {
        model_route_approval_id: _,
        revision: _,
        owner_id: _,
        route: _,
        account_profile: _,
        allowed_data_categories: _,
        handling: _,
        purpose: _,
        maximum_request_tokens: _,
        fallback: _,
        state: _,
        effective_at: _,
        expires_at: _,
        revoked_at: _,
        disclosure_version: _,
    } = &approval;
    let encoded_response = serde_json::to_value(&approval).unwrap();
    let response_fields = encoded_response
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        response_fields,
        BTreeSet::from([
            "account_profile",
            "allowed_data_categories",
            "disclosure_version",
            "effective_at",
            "expires_at",
            "fallback",
            "handling",
            "maximum_request_tokens",
            "model_route_approval_id",
            "owner_id",
            "purpose",
            "revision",
            "revoked_at",
            "route",
            "state",
        ])
    );
}
