use std::future::Future;

use anyhow::{Context, Result};
use clap::Parser;
use stein_core::{ActorId, CoreApplication, SecondMindError};
#[cfg(any(test, not(all(windows, feature = "production-private-endpoint"))))]
use stein_core::{StaticConfigProvider, UnavailableSecretStore};
use stein_ipc::{PrivateServerIdentity, ServerConfig, run_private_server, run_server};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[cfg(all(windows, feature = "production-edge-producer"))]
mod browser_producer;
#[cfg(all(windows, feature = "production-private-endpoint"))]
mod production;
#[cfg(all(windows, feature = "production-private-endpoint"))]
mod toast_registration;
#[cfg(all(windows, feature = "production-private-endpoint"))]
mod windows_storage;

#[derive(Debug, Parser)]
#[command(name = "stein-core", version, about = "STEIN CORE per-user daemon")]
struct Arguments {
    /// Indicates launch by the installed per-user supervisor.
    #[arg(long)]
    installed: bool,
}

#[cfg(feature = "production-private-endpoint")]
fn embedded_private_identity() -> Result<Option<PrivateServerIdentity>> {
    // build.rs emits both values only after exact production validation. They
    // are immutable bytes in the signed CORE image, never runtime/task input.
    Ok(Some(PrivateServerIdentity::production(
        env!("STEIN_EMBEDDED_PACKAGE_FAMILY_NAME"),
        env!("STEIN_EMBEDDED_BROKER_AUMID"),
    )?))
}

#[cfg(not(feature = "production-private-endpoint"))]
fn embedded_private_identity() -> Result<Option<PrivateServerIdentity>> {
    Ok(None)
}

struct DaemonComposition {
    core: CoreApplication,
    emergency_owner: Option<ActorId>,
    #[cfg(all(windows, feature = "production-edge-producer"))]
    browser_producer: Option<std::sync::Arc<browser_producer::WindowsBrowserProducerPort>>,
}

fn spawn_supervised_background_task<F>(
    core: CoreApplication,
    task_name: &'static str,
    future: F,
) -> tokio::task::JoinHandle<Result<()>>
where
    F: Future<Output = std::result::Result<(), SecondMindError>> + Send + 'static,
{
    let shutdown = core.shutdown_token();
    tokio::spawn(async move {
        let worker = tokio::spawn(future);
        match worker.await {
            Ok(Ok(())) if shutdown.is_cancelled() => Ok(()),
            Ok(Ok(())) => {
                error!(
                    background_task = task_name,
                    "background task stopped unexpectedly; stopping CORE fail-closed"
                );
                core.request_shutdown();
                Err(anyhow::anyhow!(
                    "the {task_name} background task stopped unexpectedly"
                ))
            }
            Ok(Err(failure)) => {
                error!(
                    background_task = task_name,
                    error = failure.summary,
                    "background task failed; stopping CORE fail-closed"
                );
                core.request_shutdown();
                Err(anyhow::anyhow!(
                    "the {task_name} background task failed: {}",
                    failure.summary
                ))
            }
            Err(join_failure) => {
                let termination = if join_failure.is_panic() {
                    "panicked"
                } else {
                    "was cancelled"
                };
                error!(
                    background_task = task_name,
                    termination, "background task terminated abnormally; stopping CORE fail-closed"
                );
                core.request_shutdown();
                Err(anyhow::anyhow!(
                    "the {task_name} background task {termination}"
                ))
            }
        }
    })
}

async fn join_background_task(
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    task_name: &'static str,
) -> Result<()> {
    match task {
        Some(task) => task
            .await
            .map_err(|_| anyhow::anyhow!("the {task_name} supervisor terminated unexpectedly"))?,
        None => Ok(()),
    }
}

#[cfg(all(windows, feature = "production-private-endpoint"))]
fn build_daemon_composition() -> Result<DaemonComposition> {
    let composition = production::ProductionComposition::build(env!("CARGO_PKG_VERSION"))?;
    if composition.toast_registration_verified {
        info!("exact signed Windows desktop notification registration verified");
    } else {
        warn!(
            "Windows notification registration is unverified; native delivery remains unavailable"
        );
    }
    Ok(DaemonComposition {
        core: composition.core,
        emergency_owner: Some(composition.owner),
        #[cfg(feature = "production-edge-producer")]
        browser_producer: Some(composition.browser_producer),
    })
}

#[cfg(not(all(windows, feature = "production-private-endpoint")))]
fn build_daemon_composition() -> Result<DaemonComposition> {
    let secret_store = UnavailableSecretStore::default();
    let core = CoreApplication::build(
        env!("CARGO_PKG_VERSION"),
        &StaticConfigProvider::default(),
        &secret_store,
    )
    .map_err(|error| anyhow::anyhow!(error.summary))?;
    Ok(DaemonComposition {
        core,
        emergency_owner: None,
        #[cfg(all(windows, feature = "production-edge-producer"))]
        browser_producer: None,
    })
}

#[cfg(all(windows, feature = "production-private-endpoint"))]
async fn recover_daemon_workflows(core: &CoreApplication, owner: Option<ActorId>) -> Result<()> {
    let owner = owner.context("production CORE has no stable Windows owner")?;
    let recovery = production::recover_authorized_workflows(core, owner).await?;
    info!(
        interrupted_deliveries = recovery.interrupted_deliveries_reconciled,
        reactivated_sessions = recovery.reactivated_with_fresh_sources,
        ended_sessions = recovery.ended_without_restart_authority,
        resumed_stopping_cleanup = recovery.resumed_stopping_cleanup,
        native_cleanups_completed = recovery.native_cleanups_completed,
        native_cleanups_pending = recovery.native_cleanups_pending,
        secret_cleanups_completed = recovery.secret_cleanups_completed,
        secret_cleanups_pending = recovery.secret_cleanups_pending,
        "durable Phase 2 recovery revalidated"
    );
    Ok(())
}

#[cfg(not(all(windows, feature = "production-private-endpoint")))]
async fn recover_daemon_workflows(_core: &CoreApplication, _owner: Option<ActorId>) -> Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(!arguments.installed)
        .compact()
        .init();

    let composition = build_daemon_composition()?;
    let core = composition.core;
    let emergency_owner = composition.emergency_owner;
    #[cfg(all(windows, feature = "production-edge-producer"))]
    let browser_producer = composition.browser_producer;

    let private_identity = embedded_private_identity()
        .context("validate embedded production private broker identity")?;
    if private_identity.is_none() {
        warn!("private client endpoint disabled in this CORE build");
    }

    let signal_core = core.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("console shutdown requested");
            signal_core.request_shutdown();
        }
    });

    let emergency_task = emergency_owner.map(|owner| {
        let runtime = core.second_mind().clone();
        let shutdown = core.shutdown_token();
        spawn_supervised_background_task(
            core.clone(),
            "independent emergency control",
            async move { runtime.run_emergency_control_loop(owner, shutdown).await },
        )
    });
    #[cfg(all(windows, feature = "production-edge-producer"))]
    let browser_producer_task = browser_producer.map(|producer| {
        let shutdown = core.shutdown_token();
        spawn_supervised_background_task(core.clone(), "Edge observation producer", async move {
            producer.run(shutdown).await
        })
    });
    if let Err(error) = recover_daemon_workflows(&core, emergency_owner).await {
        core.request_shutdown();
        if let Some(task) = emergency_task {
            let _ = task.await;
        }
        #[cfg(all(windows, feature = "production-edge-producer"))]
        if let Some(task) = browser_producer_task {
            let _ = task.await;
        }
        return Err(error);
    }

    info!(
        daemon_instance = %core.runtime_status().daemon_instance_id,
        endpoint = "protected-current-user-pipe",
        installed = arguments.installed,
        "STEIN CORE starting"
    );

    let pending_delivery_recovery_task = emergency_owner.map(|owner| {
        let runtime = core.second_mind().clone();
        let shutdown = core.shutdown_token();
        spawn_supervised_background_task(core.clone(), "pending-delivery recovery", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` ticks immediately once. Startup already reconciled
            // durable workflow authority; wait one full bounded recovery
            // interval before attempting queued delivery revalidation.
            interval.tick().await;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break Ok(()),
                    _ = interval.tick() => {
                        let changed = runtime.revalidate_pending_deliveries(owner).await?;
                        if !changed.is_empty() {
                            info!(
                                changed_interventions = changed.len(),
                                "bounded pending-delivery recovery completed"
                            );
                        }
                    }
                }
            }
        })
    });

    let reasoning_task = emergency_owner.map(|owner| {
        let runtime = core.second_mind().clone();
        let shutdown = core.shutdown_token();
        spawn_supervised_background_task(core.clone(), "reasoning scheduler", async move {
            runtime.run_reasoning_scheduler(owner, shutdown).await
        })
    });

    let retention_maintenance_task = emergency_owner.map(|owner| {
        let runtime = core.second_mind().clone();
        let shutdown = core.shutdown_token();
        spawn_supervised_background_task(core.clone(), "retention maintenance", async move {
            runtime.run_retention_maintenance(owner, shutdown).await
        })
    });

    let transport = if let Some(identity) = private_identity {
        let diagnostic = run_server(core.clone(), ServerConfig::default());
        let private = run_private_server(core.clone(), ServerConfig::default(), identity);
        tokio::try_join!(diagnostic, private).map(|_| ())
    } else {
        run_server(core.clone(), ServerConfig::default()).await
    };
    core.request_shutdown();
    let emergency = join_background_task(emergency_task, "independent emergency control").await;
    let pending_delivery_recovery =
        join_background_task(pending_delivery_recovery_task, "pending-delivery recovery").await;
    let reasoning = join_background_task(reasoning_task, "reasoning scheduler").await;
    let retention_maintenance =
        join_background_task(retention_maintenance_task, "retention maintenance").await;
    #[cfg(all(windows, feature = "production-edge-producer"))]
    let browser_producer =
        join_background_task(browser_producer_task, "Edge observation producer").await;
    if let Err(error) = transport {
        error!(error = %error, "CORE transport failed");
        return Err(error).context("run CORE local protocol");
    }
    emergency.context("run independent emergency control")?;
    pending_delivery_recovery.context("run pending-delivery recovery")?;
    reasoning.context("run reasoning scheduler")?;
    retention_maintenance.context("run retention maintenance")?;
    #[cfg(all(windows, feature = "production-edge-producer"))]
    browser_producer.context("run Edge observation producer")?;

    info!("STEIN CORE stopped cleanly");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_core() -> CoreApplication {
        let secret_store = UnavailableSecretStore::default();
        CoreApplication::build(
            "supervision-test",
            &StaticConfigProvider::default(),
            &secret_store,
        )
        .expect("build in-memory test CORE")
    }

    #[tokio::test]
    async fn background_task_panic_requests_shutdown_immediately() {
        let core = test_core();
        let shutdown = core.shutdown_token();
        let supervisor = spawn_supervised_background_task(core, "synthetic panic", async {
            panic!("synthetic background task panic")
        });

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor)
            .await
            .expect("supervisor observed the worker panic")
            .expect("supervisor itself remained healthy");
        assert!(outcome.is_err());
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn unexpected_background_task_exit_requests_shutdown_immediately() {
        let core = test_core();
        let shutdown = core.shutdown_token();
        let supervisor =
            spawn_supervised_background_task(core, "synthetic early exit", async { Ok(()) });

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor)
            .await
            .expect("supervisor observed the early worker exit")
            .expect("supervisor itself remained healthy");
        assert!(outcome.is_err());
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn coordinated_shutdown_keeps_background_task_exit_clean() {
        let core = test_core();
        let worker_shutdown = core.shutdown_token();
        let supervisor = spawn_supervised_background_task(
            core.clone(),
            "synthetic coordinated exit",
            async move {
                worker_shutdown.cancelled().await;
                Ok(())
            },
        );

        core.request_shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), supervisor)
            .await
            .expect("supervisor completed after coordinated shutdown")
            .expect("supervisor itself remained healthy")
            .expect("coordinated worker exit remained clean");
    }

    #[test]
    fn runtime_arguments_cannot_select_private_package_identity() {
        let arguments = Arguments::try_parse_from(["stein-core", "--installed"])
            .expect("installed mode remains available");
        assert!(arguments.installed);
        assert!(
            Arguments::try_parse_from([
                "stein-core",
                "--installed",
                "--private-package-family-name",
                "STEIN.PersonalIntelligence_qrfd6g9swygw6",
            ])
            .is_err(),
            "runtime input must not be able to select the trusted package"
        );
    }
}
