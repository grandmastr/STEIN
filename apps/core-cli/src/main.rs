use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use stein_ipc::{Client, ClientError};
use stein_protocol::{
    Component, CreateGoalRequest, IdempotencyKey, ProtocolSupport, RetentionClass,
    SensitivityClass, ShutdownReason, ViewEvent,
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(
    name = "stein-cli",
    version,
    about = "Non-Tauri STEIN CORE proof client"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Query daemon and capability health.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Fetch an authoritative snapshot.
    Snapshot {
        #[arg(long)]
        json: bool,
    },
    /// Create one in-memory Phase 1 proof goal.
    CreateGoal {
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "The Phase 1 proof is visible.")]
        success: String,
        #[arg(long)]
        json: bool,
    },
    /// Prove command, event, idempotency, disconnect, and reconnect behavior.
    Proof {
        #[arg(long)]
        json: bool,
    },
    /// Attempt a handshake using an explicit protocol major.
    ProtocolCheck {
        #[arg(long)]
        major: u16,
        #[arg(long)]
        json: bool,
    },
    /// Prove a connection-owned request can be cancelled.
    CancellationProof {
        #[arg(long)]
        json: bool,
    },
    /// Saturate the configured connection limit and prove CORE stays healthy.
    ConnectionLimitProof {
        #[arg(long)]
        json: bool,
    },
    /// Prove the same-SID diagnostic endpoint rejects fixed private operations.
    PrivateDenialProof {
        #[arg(long)]
        json: bool,
    },
    /// Prove the packaged toast COM server rejects a fixed wrong AUMID.
    ToastComDenialProof {
        #[arg(long)]
        json: bool,
    },
    /// Ask the daemon to stop cleanly.
    Shutdown {
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::Status { json: compact } => status(compact).await,
        Command::Snapshot { json: compact } => snapshot(compact).await,
        Command::CreateGoal {
            title,
            success,
            json: compact,
        } => create_goal(title, success, compact).await,
        Command::Proof { json: compact } => proof(compact).await,
        Command::ProtocolCheck {
            major,
            json: compact,
        } => protocol_check(major, compact).await,
        Command::CancellationProof { json: compact } => cancellation_proof(compact).await,
        Command::ConnectionLimitProof { json: compact } => connection_limit_proof(compact).await,
        Command::PrivateDenialProof { json: compact } => private_denial_proof(compact).await,
        Command::ToastComDenialProof { json: compact } => toast_com_denial_proof(compact).await,
        Command::Shutdown { timeout_ms } => shutdown(timeout_ms).await,
    }
}

async fn status(compact: bool) -> Result<()> {
    let client = Client::connect_with_support("stein-cli", ProtocolSupport::V1).await?;
    let response = client.get_runtime_status().await?;
    let value = json!({
        "runtime": {
            "health": if matches!(response.runtime.state, stein_protocol::RuntimeState::Ready) { "healthy" } else { "degraded" },
            "state": response.runtime.state,
            "daemonInstanceId": response.runtime.daemon_instance_id,
            "startedAt": response.runtime.started_at,
            "observedAt": response.runtime.observed_at,
            "buildId": response.runtime.build_id,
            "protocolVersion": response.runtime.protocol_version,
            "activeConnections": response.runtime.active_connections,
        },
        "capabilities": response.capabilities,
        "authenticatedActor": client.session().authenticated_actor,
    });
    print_json(&value, compact)
}

async fn snapshot(compact: bool) -> Result<()> {
    let client = Client::connect_with_support("stein-cli", ProtocolSupport::V1).await?;
    let snapshot = client.get_client_snapshot().await?;
    print_json(&serde_json::to_value(snapshot)?, compact)
}

async fn create_goal(title: String, success: String, compact: bool) -> Result<()> {
    let client = Client::connect_with_support("stein-cli", ProtocolSupport::V1).await?;
    let result = client
        .create_goal(CreateGoalRequest {
            title,
            success_statement: success,
            deadline: None,
        })
        .await?;
    print_json(&serde_json::to_value(result)?, compact)
}

async fn proof(compact: bool) -> Result<()> {
    let client = Client::connect_with_support("stein-cli-proof", ProtocolSupport::V1).await?;
    let mut events = client.subscribe_events();
    let key = IdempotencyKey::new_v7();
    let input = CreateGoalRequest {
        title: format!("Morning proof {}", stein_protocol::UtcTimestamp::now()),
        success_statement: "Command, event, and authoritative reconnect all agree.".into(),
        deadline: None,
    };
    let first = client.create_goal_idempotent(input.clone(), key).await?;
    let duplicate = client.create_goal_idempotent(input, key).await?;
    let event = timeout(Duration::from_secs(5), events.recv())
        .await
        .context("timed out waiting for GoalViewChanged")??;
    let event_matches = matches!(
        &event.event,
        ViewEvent::GoalViewChanged(change) if change.goal.goal_id == first.goal.goal_id
    );
    let metadata_matches = event.metadata.actor == client.session().authenticated_actor
        && event.metadata.origin == Component::CoreApplication
        && event.metadata.sensitivity == SensitivityClass::Personal
        && event.metadata.retention == RetentionClass::Runtime
        && event.metadata.causation_id.is_some();
    let prior_instance = client.session().daemon_instance_id;
    drop(client);

    tokio::time::sleep(Duration::from_millis(150)).await;
    let reconnected =
        Client::connect_with_support("stein-cli-proof-reconnect", ProtocolSupport::V1).await?;
    let snapshot = reconnected.get_client_snapshot().await?;
    let restored = snapshot
        .goals
        .iter()
        .any(|goal| goal.goal_id == first.goal.goal_id);
    let same_instance = snapshot.runtime.daemon_instance_id == prior_instance;
    let idempotent = first.goal.goal_id == duplicate.goal.goal_id;
    let passed = event_matches && metadata_matches && restored && same_instance && idempotent;
    let value = json!({
        "passed": passed,
        "goalId": first.goal.goal_id,
        "eventCursor": event.cursor,
        "snapshotCursor": snapshot.cursor,
        "idempotent": idempotent,
        "eventObserved": event_matches,
        "eventMetadataValid": metadata_matches,
        "restoredAfterReconnect": restored,
        "sameDaemonInstance": same_instance,
    });
    print_json(&value, compact)?;
    if !passed {
        bail!("Phase 1 command/event/reconnect proof failed");
    }
    Ok(())
}

async fn protocol_check(major: u16, compact: bool) -> Result<()> {
    let support = ProtocolSupport {
        major,
        minimum_minor: 0,
        maximum_minor: 0,
    };
    match Client::connect_with_support("stein-cli-compatibility", support).await {
        Ok(client) => {
            let value =
                json!({ "accepted": true, "protocolVersion": client.session().protocol_version });
            print_json(&value, compact)
        }
        Err(error) => {
            let value =
                json!({ "accepted": false, "error": error.to_string(), "requestedMajor": major });
            print_json(&value, compact)?;
            Err(error.into())
        }
    }
}

async fn cancellation_proof(compact: bool) -> Result<()> {
    let client =
        Client::connect_with_support("stein-cli-cancellation", ProtocolSupport::V1).await?;
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        trigger.cancel();
    });
    let result = client
        .delay_echo(3_000, "synthetic", Some(cancellation))
        .await;
    let passed = matches!(result, Err(ClientError::Cancelled));
    let value =
        json!({ "passed": passed, "result": if passed { "cancelled" } else { "unexpected" } });
    print_json(&value, compact)?;
    if !passed {
        bail!("cancellation proof failed");
    }
    Ok(())
}

async fn connection_limit_proof(compact: bool) -> Result<()> {
    const CONFIGURED_LIMIT: usize = 8;
    let mut clients = Vec::with_capacity(CONFIGURED_LIMIT);
    for index in 0..CONFIGURED_LIMIT {
        clients.push(
            Client::connect_with_support(format!("stein-cli-limit-{index}"), ProtocolSupport::V1)
                .await
                .with_context(|| format!("connection {index} should fit within the limit"))?,
        );
    }

    let overflow =
        Client::connect_with_support("stein-cli-limit-overflow", ProtocolSupport::V1).await;
    let overflow_rejected = overflow.is_err();
    let overflow_error = overflow.err().map(|error| error.to_string());
    drop(clients);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let health_client =
        Client::connect_with_support("stein-cli-limit-health", ProtocolSupport::V1).await?;
    let runtime = health_client.get_runtime_status().await?;
    let daemon_healthy = matches!(runtime.runtime.state, stein_protocol::RuntimeState::Ready);
    let passed = overflow_rejected && daemon_healthy;
    let value = json!({
        "passed": passed,
        "configuredLimit": CONFIGURED_LIMIT,
        "acceptedConnections": CONFIGURED_LIMIT,
        "overflowRejected": overflow_rejected,
        "overflowError": overflow_error,
        "daemonHealthyAfterRejection": daemon_healthy,
        "daemonInstanceId": runtime.runtime.daemon_instance_id,
    });
    print_json(&value, compact)?;
    if !passed {
        bail!("connection-limit proof failed");
    }
    Ok(())
}

const PRIVATE_DENIAL_FIXTURE_ID: &str = "phase2-private-diagnostic-denial-v1";
const PRIVATE_DENIAL_RUNNER_ID: &str = "stein-cli-private-denial-v1";
const PRIVATE_DENIAL_SUBCHECKS: [&str; 5] = [
    "diagnostic_snapshot_redacted",
    "private_snapshot_denied",
    "private_identity_denied",
    "invalid_private_write_denied",
    "private_cancel_denied",
];

const TOAST_COM_DENIAL_FIXTURE_ID: &str = "phase2-toast-com-denial-v1";
const TOAST_COM_DENIAL_RUNNER_ID: &str = "stein-cli-toast-com-denial-v1";
const TOAST_COM_DENIAL_SUBCHECKS: [&str; 2] = ["packaged_class_activated", "wrong_aumid_denied"];

async fn private_denial_proof(compact: bool) -> Result<()> {
    let failed_subcheck = execute_private_denial_proof().await.err();
    let receipt = private_denial_receipt(failed_subcheck);
    print_json(&receipt, compact)?;
    if failed_subcheck.is_some() {
        bail!("private diagnostic denial proof failed");
    }
    Ok(())
}

fn private_denial_receipt(failed_subcheck: Option<usize>) -> Value {
    denial_receipt(
        PRIVATE_DENIAL_FIXTURE_ID,
        PRIVATE_DENIAL_RUNNER_ID,
        &PRIVATE_DENIAL_SUBCHECKS,
        failed_subcheck,
    )
}

async fn toast_com_denial_proof(compact: bool) -> Result<()> {
    let failed_subcheck = execute_toast_com_denial_proof().await.err();
    let receipt = denial_receipt(
        TOAST_COM_DENIAL_FIXTURE_ID,
        TOAST_COM_DENIAL_RUNNER_ID,
        &TOAST_COM_DENIAL_SUBCHECKS,
        failed_subcheck,
    );
    print_json(&receipt, compact)?;
    if failed_subcheck.is_some() {
        bail!("toast COM denial proof failed");
    }
    Ok(())
}

fn denial_receipt(
    fixture_id: &str,
    runner_id: &str,
    required_subchecks: &[&str],
    failed_subcheck: Option<usize>,
) -> Value {
    let failed_subcheck = match failed_subcheck {
        Some(index) if index < required_subchecks.len() => Some(index),
        Some(_) => Some(0),
        None => None,
    };
    let subchecks: Vec<_> = required_subchecks
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let result = match failed_subcheck {
                None => "pass",
                Some(failed) if index < failed => "pass",
                Some(failed) if index == failed => "fail",
                Some(_) => "not_run",
            };
            json!({ "id": id, "result": result })
        })
        .collect();
    let passed = subchecks
        .iter()
        .filter(|subcheck| subcheck["result"] == "pass")
        .count();
    let failed = subchecks
        .iter()
        .filter(|subcheck| subcheck["result"] == "fail")
        .count();
    let not_run = subchecks
        .iter()
        .filter(|subcheck| subcheck["result"] == "not_run")
        .count();

    json!({
        "schema_version": 1,
        "fixture_id": fixture_id,
        "runner_id": runner_id,
        "result": if failed_subcheck.is_none() { "pass" } else { "fail" },
        "summary": {
            "required": required_subchecks.len(),
            "passed": passed,
            "failed": failed,
            "not_run": not_run,
        },
        "subchecks": subchecks,
    })
}

#[cfg(windows)]
async fn execute_toast_com_denial_proof() -> std::result::Result<(), usize> {
    tokio::task::spawn_blocking(toast_com_denial_windows::execute)
        .await
        .unwrap_or(Err(0))
}

#[cfg(not(windows))]
async fn execute_toast_com_denial_proof() -> std::result::Result<(), usize> {
    Err(0)
}

#[cfg(windows)]
async fn execute_private_denial_proof() -> std::result::Result<(), usize> {
    private_denial_windows::execute().await
}

#[cfg(not(windows))]
async fn execute_private_denial_proof() -> std::result::Result<(), usize> {
    Err(0)
}

#[cfg(windows)]
mod toast_com_denial_windows {
    use windows::{
        Win32::{
            Foundation::E_INVALIDARG,
            System::Com::{
                CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            UI::Notifications::INotificationActivationCallback,
        },
        core::{GUID, PCWSTR},
    };

    const TOAST_ACTIVATOR_CLSID: GUID = GUID::from_u128(0x3db3b5b0_1ba5_49d1_a8f0_cf2b3ea6d781);
    const WRONG_AUMID: &str = "STEIN.Phase2.Invalid_qrfd6g9swygw6!Desktop";
    const SYNTHETIC_ARGUMENT: &str =
        "action=open&intervention=018f0000-0000-7000-8000-000000000901";

    struct ComApartment;

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: this balances the successful initialization on this
            // dedicated blocking thread after all local COM objects drop.
            unsafe { CoUninitialize() };
        }
    }

    pub(super) fn execute() -> std::result::Result<(), usize> {
        // SAFETY: this runs on a new Tokio blocking thread and the guard keeps
        // COM initialized until every interface acquired below is released.
        if unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_err() {
            return Err(0);
        }
        let _apartment = ComApartment;

        // SAFETY: the CLSID is the exact constant declared by the signed STEIN
        // manifest and the requested interface is the Windows toast callback.
        let callback: INotificationActivationCallback =
            unsafe { CoCreateInstance(&TOAST_ACTIVATOR_CLSID, None, CLSCTX_LOCAL_SERVER) }
                .map_err(|_| 0_usize)?;

        let aumid = wide(WRONG_AUMID);
        let argument = wide(SYNTHETIC_ARGUMENT);
        // SAFETY: the owned, terminated UTF-16 buffers remain live throughout
        // the synchronous callback and no user-input records are supplied.
        let result =
            unsafe { callback.Activate(PCWSTR(aumid.as_ptr()), PCWSTR(argument.as_ptr()), &[]) };
        drop(callback);
        match result {
            Err(error) if error.code() == E_INVALIDARG => Ok(()),
            _ => Err(1),
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }
}

#[cfg(windows)]
mod private_denial_windows {
    use std::{io, time::Duration};

    use anyhow::{Context, Result, bail, ensure};
    use stein_ipc::{Client, MAX_FRAME_BYTES, default_pipe_name, read_frame, write_frame};
    use stein_protocol::{
        ActorReference, CancelRequest, CancellationId, ClientHello, ClientInstanceId,
        ClientMessage, Component, CorrelationId, DeleteGoalRequest, ErrorCategory, ErrorCode,
        FatalReason, GetSnapshotRequest, GetSteinIdentityRequest, GoalId, MessageId,
        ProtocolSupport, ProtocolVersion, RequestBody, RequestEnvelope, RequestId, RequestMetadata,
        ResponseOutcome, ServerMessage, UtcTimestamp,
    };
    use tokio::{
        net::windows::named_pipe::{ClientOptions, NamedPipeClient},
        time::{Instant, sleep, timeout},
    };

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const ERROR_PIPE_BUSY: i32 = 231;
    const DENIAL_SUMMARY: &str = "This connection is not admitted for private protocol operations.";

    pub(super) async fn execute() -> std::result::Result<(), usize> {
        let (mut pipe, actor) = open_redacted_diagnostic_session()
            .await
            .map_err(|_| 0_usize)?;

        expect_private_request_denied(
            &mut pipe,
            &actor,
            RequestBody::GetSnapshot(GetSnapshotRequest::default()),
        )
        .await
        .map_err(|_| 1_usize)?;
        expect_private_request_denied(
            &mut pipe,
            &actor,
            RequestBody::GetSteinIdentity(GetSteinIdentityRequest::default()),
        )
        .await
        .map_err(|_| 2_usize)?;
        expect_private_request_denied(
            &mut pipe,
            &actor,
            DeleteGoalRequest {
                goal_id: GoalId::new_v7(),
                // Revisions start at one, so this request cannot delete a real
                // record even if diagnostic admission regresses.
                expected_revision: 0,
            }
            .into(),
        )
        .await
        .map_err(|_| 3_usize)?;
        expect_private_cancel_denied(&mut pipe)
            .await
            .map_err(|_| 4_usize)?;
        Ok(())
    }

    async fn open_redacted_diagnostic_session() -> Result<(NamedPipeClient, ActorReference)> {
        let trusted = Client::connect_with_support(
            "stein-cli-private-denial-preflight",
            ProtocolSupport::V1_2,
        )
        .await
        .context("diagnostic preflight failed")?;
        let expected_daemon = trusted.session().daemon_instance_id;
        let prior_diagnostic_actor = trusted.session().authenticated_actor.actor_id;
        drop(trusted);

        let mut pipe = connect_fixed_diagnostic_pipe().await?;
        let hello = ClientHello {
            client_instance_id: ClientInstanceId::new_v7(),
            client_name: super::PRIVATE_DENIAL_RUNNER_ID.to_owned(),
            client_build_id: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_support: ProtocolSupport::V1_2,
            max_frame_bytes: MAX_FRAME_BYTES as u32,
            capabilities: Vec::new(),
        };
        write_frame(&mut pipe, &ClientMessage::OpenSession(hello))
            .await
            .context("diagnostic handshake write failed")?;
        let message = timeout(IO_TIMEOUT, read_frame::<_, ServerMessage>(&mut pipe))
            .await
            .context("diagnostic handshake timed out")??;
        let ServerMessage::SessionOpened(opened) = message else {
            bail!("diagnostic handshake was not accepted");
        };
        ensure!(opened.protocol_version == ProtocolVersion::V1_2);
        ensure!(opened.daemon_instance_id == expected_daemon);
        ensure!(opened.snapshot.runtime.daemon_instance_id == expected_daemon);
        ensure!(opened.snapshot.goals.is_empty());
        ensure!(opened.snapshot.phase2.is_none());
        ensure!(opened.authenticated_actor.actor_id != prior_diagnostic_actor);
        Ok((pipe, opened.authenticated_actor))
    }

    async fn connect_fixed_diagnostic_pipe() -> Result<NamedPipeClient> {
        let pipe_name = default_pipe_name().context("diagnostic endpoint is unavailable")?;
        let started = Instant::now();
        loop {
            match ClientOptions::new().open(&pipe_name) {
                Ok(pipe) => return Ok(pipe),
                Err(error)
                    if (matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) || error.raw_os_error() == Some(ERROR_PIPE_BUSY))
                        && started.elapsed() < IO_TIMEOUT =>
                {
                    sleep(Duration::from_millis(75)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn expect_private_request_denied(
        pipe: &mut NamedPipeClient,
        actor: &ActorReference,
        body: RequestBody,
    ) -> Result<()> {
        let kind = body.kind();
        let metadata =
            RequestMetadata::new(Component::CoreCli, kind.sensitivity(), kind.retention());
        let request = RequestEnvelope::new(metadata, body);
        write_frame(pipe, &ClientMessage::Request(request.clone()))
            .await
            .context("private probe write failed")?;
        let message = timeout(IO_TIMEOUT, read_frame::<_, ServerMessage>(pipe))
            .await
            .context("private probe timed out")??;
        validate_private_denial_response(message, &request, actor)
    }

    fn validate_private_denial_response(
        message: ServerMessage,
        request: &RequestEnvelope,
        actor: &ActorReference,
    ) -> Result<()> {
        let ServerMessage::Response(response) = message else {
            bail!("private probe returned an unexpected frame");
        };
        ensure!(response.request_id == request.request_id);
        ensure!(response.metadata.causation_id == request.metadata.message_id);
        ensure!(response.metadata.correlation_id == request.metadata.correlation_id);
        ensure!(response.metadata.actor == *actor);
        ensure!(response.metadata.sensitivity == request.metadata.sensitivity);
        ensure!(response.metadata.retention == request.metadata.retention);
        let ResponseOutcome::Error(error) = response.outcome else {
            bail!("private probe unexpectedly succeeded");
        };
        ensure!(error.code == ErrorCode::PermissionDenied);
        ensure!(error.category == ErrorCategory::PermissionDenied);
        ensure!(!error.retryable);
        ensure!(error.correlation_id == request.metadata.correlation_id);
        ensure!(error.details.is_none());
        ensure!(error.summary == DENIAL_SUMMARY);
        Ok(())
    }

    async fn expect_private_cancel_denied(pipe: &mut NamedPipeClient) -> Result<()> {
        let cancel = CancelRequest {
            message_id: MessageId::new_v7(),
            issued_at: UtcTimestamp::now(),
            correlation_id: CorrelationId::new_v7(),
            origin: Component::CoreCli,
            target_request_id: RequestId::new_v7(),
            cancellation_id: CancellationId::new_v7(),
        };
        write_frame(pipe, &ClientMessage::Cancel(cancel))
            .await
            .context("private cancellation probe write failed")?;
        let message = timeout(IO_TIMEOUT, read_frame::<_, ServerMessage>(pipe))
            .await
            .context("private cancellation probe timed out")??;
        validate_private_cancel_denial(message)
    }

    fn validate_private_cancel_denial(message: ServerMessage) -> Result<()> {
        let ServerMessage::Fatal(fatal) = message else {
            bail!("private cancellation probe returned an unexpected frame");
        };
        ensure!(fatal.reason == FatalReason::AuthenticationFailed);
        ensure!(fatal.error.code == ErrorCode::PermissionDenied);
        ensure!(fatal.error.category == ErrorCategory::PermissionDenied);
        ensure!(!fatal.error.retryable);
        ensure!(fatal.error.details.is_none());
        ensure!(fatal.error.summary == DENIAL_SUMMARY);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use stein_protocol::{ActorId, ActorKind, PublicError, ResponseEnvelope, ResponseMetadata};

        use super::*;

        fn fixture_denial() -> (RequestEnvelope, ActorReference, ServerMessage) {
            let body = RequestBody::GetSnapshot(GetSnapshotRequest::default());
            let kind = body.kind();
            let request = RequestEnvelope::new(
                RequestMetadata::new(Component::CoreCli, kind.sensitivity(), kind.retention()),
                body,
            );
            let actor = ActorReference {
                actor_id: ActorId::new_v7(),
                kind: ActorKind::LocalOsUser,
            };
            let message = ServerMessage::Response(ResponseEnvelope {
                request_id: request.request_id,
                metadata: ResponseMetadata::for_request(&request.metadata, actor.clone()),
                outcome: ResponseOutcome::Error(PublicError {
                    code: ErrorCode::PermissionDenied,
                    category: ErrorCategory::PermissionDenied,
                    summary: DENIAL_SUMMARY.to_owned(),
                    retryable: false,
                    correlation_id: request.metadata.correlation_id,
                    details: None,
                }),
            });
            (request, actor, message)
        }

        #[test]
        fn denial_validator_requires_the_exact_content_free_error() {
            let (request, actor, message) = fixture_denial();
            validate_private_denial_response(message.clone(), &request, &actor)
                .expect("exact denial is accepted");

            let ServerMessage::Response(mut wrong_code) = message.clone() else {
                unreachable!();
            };
            let ResponseOutcome::Error(error) = &mut wrong_code.outcome else {
                unreachable!();
            };
            error.code = ErrorCode::InvalidArgument;
            assert!(
                validate_private_denial_response(
                    ServerMessage::Response(wrong_code),
                    &request,
                    &actor,
                )
                .is_err()
            );

            let ServerMessage::Response(mut leaked_summary) = message else {
                unreachable!();
            };
            let ResponseOutcome::Error(error) = &mut leaked_summary.outcome else {
                unreachable!();
            };
            error.summary = "synthetic private value".into();
            assert!(
                validate_private_denial_response(
                    ServerMessage::Response(leaked_summary),
                    &request,
                    &actor,
                )
                .is_err()
            );
        }
    }
}

async fn shutdown(timeout_ms: u64) -> Result<()> {
    let client = Client::connect_with_support("stein-cli-shutdown", ProtocolSupport::V1).await?;
    timeout(
        Duration::from_millis(timeout_ms),
        client.shutdown(ShutdownReason::UserRequested),
    )
    .await
    .context("shutdown request timed out")??;
    println!("CORE accepted shutdown");
    Ok(())
}

fn print_json(value: &Value, compact: bool) -> Result<()> {
    if compact {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_denial_receipt_is_closed_content_free_and_fail_closed() {
        let passed = private_denial_receipt(None);
        assert_eq!(passed["schema_version"], 1);
        assert_eq!(passed["fixture_id"], PRIVATE_DENIAL_FIXTURE_ID);
        assert_eq!(passed["runner_id"], PRIVATE_DENIAL_RUNNER_ID);
        assert_eq!(passed["result"], "pass");
        assert_eq!(passed["summary"]["required"], 5);
        assert_eq!(passed["summary"]["passed"], 5);
        assert_eq!(passed["summary"]["failed"], 0);
        assert_eq!(passed["summary"]["not_run"], 0);
        assert_eq!(passed["subchecks"].as_array().map(Vec::len), Some(5));

        let failed = private_denial_receipt(Some(2));
        assert_eq!(failed["result"], "fail");
        assert_eq!(failed["summary"]["passed"], 2);
        assert_eq!(failed["summary"]["failed"], 1);
        assert_eq!(failed["summary"]["not_run"], 2);
        assert_eq!(failed["subchecks"][0]["result"], "pass");
        assert_eq!(failed["subchecks"][2]["result"], "fail");
        assert_eq!(failed["subchecks"][3]["result"], "not_run");

        let invalid_failure_index = private_denial_receipt(Some(usize::MAX));
        assert_eq!(invalid_failure_index["result"], "fail");
        assert_eq!(invalid_failure_index["summary"]["failed"], 1);
        assert_eq!(invalid_failure_index["subchecks"][0]["result"], "fail");

        let serialized = serde_json::to_string(&failed).expect("receipt serializes");
        for prohibited in [
            "error",
            "summary_text",
            "actor_id",
            "daemon_instance_id",
            "correlation_id",
            "request_id",
            "pipe",
            "goal_id",
        ] {
            assert!(!serialized.contains(prohibited));
        }
    }

    #[test]
    fn private_denial_command_accepts_no_endpoint_or_payload_input() {
        Arguments::try_parse_from(["stein-cli", "private-denial-proof", "--json"])
            .expect("the fixed proof command parses");
        assert!(
            Arguments::try_parse_from([
                "stein-cli",
                "private-denial-proof",
                "--pipe",
                r"\\.\pipe\untrusted",
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from(["stein-cli", "private-denial-proof", "--payload", "{}",])
                .is_err()
        );
    }

    #[test]
    fn toast_com_receipt_and_command_are_closed_and_content_free() {
        let passed = denial_receipt(
            TOAST_COM_DENIAL_FIXTURE_ID,
            TOAST_COM_DENIAL_RUNNER_ID,
            &TOAST_COM_DENIAL_SUBCHECKS,
            None,
        );
        assert_eq!(passed["schema_version"], 1);
        assert_eq!(passed["fixture_id"], TOAST_COM_DENIAL_FIXTURE_ID);
        assert_eq!(passed["runner_id"], TOAST_COM_DENIAL_RUNNER_ID);
        assert_eq!(passed["result"], "pass");
        assert_eq!(passed["summary"]["required"], 2);
        assert_eq!(passed["summary"]["passed"], 2);
        assert_eq!(passed["summary"]["failed"], 0);
        assert_eq!(passed["summary"]["not_run"], 0);

        let failed = denial_receipt(
            TOAST_COM_DENIAL_FIXTURE_ID,
            TOAST_COM_DENIAL_RUNNER_ID,
            &TOAST_COM_DENIAL_SUBCHECKS,
            Some(1),
        );
        assert_eq!(failed["result"], "fail");
        assert_eq!(failed["subchecks"][0]["result"], "pass");
        assert_eq!(failed["subchecks"][1]["result"], "fail");
        let serialized = serde_json::to_string(&failed).expect("receipt serializes");
        for prohibited in [
            "clsid",
            "argument",
            "intervention",
            "error",
            "hresult",
            "process",
            "stein.phase2.invalid",
            "018f0000-0000-7000-8000-000000000901",
            "3db3b5b0-1ba5-49d1-a8f0-cf2b3ea6d781",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(prohibited));
        }

        Arguments::try_parse_from(["stein-cli", "toast-com-denial-proof", "--json"])
            .expect("the fixed COM proof command parses");
        assert!(
            Arguments::try_parse_from([
                "stein-cli",
                "toast-com-denial-proof",
                "--aumid",
                "untrusted",
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "stein-cli",
                "toast-com-denial-proof",
                "--argument",
                "untrusted",
            ])
            .is_err()
        );
    }
}
