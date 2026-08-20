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
