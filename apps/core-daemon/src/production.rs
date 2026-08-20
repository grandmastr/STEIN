use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use stein_core::{
    ActorId, Clock, CoreApplication, DurableRepository, EmergencyControlPort, FocusSessionState,
    ModelGateway, NativeStatusPort, NotificationPort, ObservationPort, PermissionScope,
    PlatformPortAvailability, ResourceSelectionPort, RuntimeCapabilityInputs, SecondMindConfig,
    SecondMindPorts, SecondMindRuntime, SecretStore, StaticConfigProvider, SystemClock,
};
use stein_model_openai::OpenAiResponsesGateway;
use stein_platform_windows::{
    WindowsCredentialSecretStore, WindowsNativeSurface, WindowsNotificationConfig,
    WindowsNotificationPort, WindowsObservationPort, WindowsToastRegistrationHealth,
};
use stein_store_sqlite::SqliteRepository;
use uuid::Uuid;

#[cfg(feature = "production-edge-producer")]
use crate::browser_producer::{WindowsBrowserProducerPort, WindowsObservationWithBrowser};

use crate::toast_registration::exact_desktop_registration_is_healthy;
use crate::windows_storage::{prepare_repository_path, verify_repository_artifacts};

/// Phase 2's explicit Windows input-inactivity signal threshold. This is not a
/// claim that the user is absent, unproductive, or interruptible.
pub const WINDOWS_INPUT_INACTIVITY_THRESHOLD: Duration = Duration::from_secs(60);

pub struct ProductionComposition {
    pub core: CoreApplication,
    pub owner: ActorId,
    pub toast_registration_verified: bool,
    #[cfg(feature = "production-edge-producer")]
    pub browser_producer: Arc<WindowsBrowserProducerPort>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoverySummary {
    pub reactivated_with_fresh_sources: usize,
    pub ended_without_restart_authority: usize,
    pub resumed_stopping_cleanup: usize,
    pub native_cleanups_completed: usize,
    pub native_cleanups_pending: usize,
    pub secret_cleanups_completed: usize,
    pub secret_cleanups_pending: usize,
}

struct RuntimeComponents {
    repository: Arc<dyn DurableRepository>,
    durable_persistence: PlatformPortAvailability,
    clock: Arc<dyn Clock>,
    secret_store: Arc<dyn SecretStore>,
    observation: Arc<dyn ObservationPort>,
    resource_selection: Arc<dyn ResourceSelectionPort>,
    model: Arc<dyn ModelGateway>,
    notification: Arc<dyn NotificationPort>,
    native_status: Arc<dyn NativeStatusPort>,
    emergency_control: Arc<dyn EmergencyControlPort>,
}

impl ProductionComposition {
    pub fn build(build_id: &str) -> Result<Self> {
        let owner_sid = stein_ipc::current_user_sid()
            .context("resolve the current Windows user for durable CORE ownership")?;
        let owner = stable_owner_actor(&owner_sid);
        let repository_path = prepare_repository_path(&owner_sid)
            .context("establish the protected current-user SQLite boundary")?;
        let repository = Arc::new(
            SqliteRepository::open(&repository_path)
                .map_err(|error| anyhow!(error.summary))
                .context("open and migrate the Phase 2 SQLite repository")?,
        );
        verify_repository_artifacts(&repository_path, &owner_sid)
            .context("verify SQLite and migration artifact access controls")?;
        repository
            .health()
            .map_err(|error| anyhow!(error.summary))
            .context("verify SQLite schema, migration catalog, and database integrity")?;

        let secret_store: Arc<dyn SecretStore> = Arc::new(WindowsCredentialSecretStore::new());
        let windows_observation = Arc::new(
            build_windows_observation(WindowsObservationPort::new)
                .map_err(|error| anyhow!(error.summary))
                .context("configure Windows observation")?,
        );
        #[cfg(feature = "production-edge-producer")]
        let browser_producer = {
            let expected = stein_broker_windows::ExpectedPackageIdentity::new(
                owner_sid.clone(),
                env!("STEIN_EMBEDDED_PACKAGE_FAMILY_NAME"),
                env!("STEIN_EMBEDDED_BROWSER_PRODUCER_AUMID"),
            )
            .map_err(|_| anyhow!("the Edge producer package identity is invalid"))?;
            let listener = stein_platform_windows::BrowserProducerListener::new(
                expected,
                *Uuid::now_v7().as_bytes(),
            )
            .map_err(|error| anyhow!(error.summary))
            .context("configure the package-admitted Edge producer endpoint")?;
            Arc::new(WindowsBrowserProducerPort::new(
                listener,
                repository.clone(),
                owner,
                env!("STEIN_EMBEDDED_EDGE_EXTENSION_ID"),
                env!("STEIN_EMBEDDED_EDGE_EXTENSION_VERSION"),
            ))
        };
        #[cfg(feature = "production-edge-producer")]
        let observation_stack = Arc::new(WindowsObservationWithBrowser::new(
            windows_observation,
            browser_producer.clone(),
        ));
        #[cfg(feature = "production-edge-producer")]
        let observation: Arc<dyn ObservationPort> = observation_stack.clone();
        #[cfg(feature = "production-edge-producer")]
        let resource_selection: Arc<dyn ResourceSelectionPort> = observation_stack;
        #[cfg(not(feature = "production-edge-producer"))]
        let observation: Arc<dyn ObservationPort> = windows_observation.clone();
        #[cfg(not(feature = "production-edge-producer"))]
        let resource_selection: Arc<dyn ResourceSelectionPort> = windows_observation;
        let model = Arc::new(
            OpenAiResponsesGateway::new(Arc::clone(&secret_store))
                .map_err(|error| anyhow!(error.summary))
                .context("configure the OpenAI Responses gateway")?,
        );
        let native_surface = Arc::new(
            WindowsNativeSurface::start()
                .map_err(|error| anyhow!(error.summary))
                .context("start the independent Windows status and emergency-control surface")?,
        );

        let expected_package_family_name = env!("STEIN_EMBEDDED_PACKAGE_FAMILY_NAME");
        let expected_desktop_aumid = env!("STEIN_EMBEDDED_DESKTOP_AUMID");
        let toast_registration_verified = exact_desktop_registration_is_healthy(
            expected_package_family_name,
            expected_desktop_aumid,
        );
        let registration = if toast_registration_verified {
            WindowsToastRegistrationHealth::VerifiedByInstaller
        } else {
            WindowsToastRegistrationHealth::Unavailable
        };
        let notification_config =
            WindowsNotificationConfig::new(expected_desktop_aumid, registration)
                .map_err(|error| anyhow!(error.summary))
                .context("validate the embedded Windows notification identity")?;
        let notification = Arc::new(
            WindowsNotificationPort::start(notification_config)
                .map_err(|error| anyhow!(error.summary))
                .context("start Windows notification delivery")?,
        );

        let native_status: Arc<dyn NativeStatusPort> = native_surface.clone();
        let emergency_control: Arc<dyn EmergencyControlPort> = native_surface;
        let components = RuntimeComponents {
            repository,
            durable_persistence: PlatformPortAvailability::Available,
            clock: Arc::new(SystemClock::default()),
            secret_store,
            observation,
            resource_selection,
            model,
            notification,
            native_status,
            emergency_control,
        };
        let core = assemble_application(build_id, components)?;
        Ok(Self {
            core,
            owner,
            toast_registration_verified,
            #[cfg(feature = "production-edge-producer")]
            browser_producer,
        })
    }
}

pub async fn recover_authorized_workflows(
    core: &CoreApplication,
    owner: ActorId,
) -> Result<RecoverySummary> {
    let cleanup = core
        .second_mind()
        .recover_cleanup_obligations(owner)
        .await
        .map_err(|error| anyhow!(error.summary))
        .context("retry durable platform cleanup after daemon restart")?;
    let recovered = core
        .second_mind()
        .recover_owner(owner)
        .map_err(|error| anyhow!(error.summary))
        .context("revalidate durable workflow continuity after daemon restart")?;
    let ended_without_restart_authority = recovered
        .iter()
        .filter(|session| session.state == FocusSessionState::Ended)
        .count();
    let mut resumed_stopping_cleanup = 0;
    for session in recovered
        .iter()
        .filter(|session| session.state == FocusSessionState::Stopping)
    {
        core.second_mind()
            .finish_end_focus_session(owner, session.id, session.revision)
            .await
            .map_err(|error| anyhow!(error.summary))
            .context("resume bounded adapter and native-status cleanup for a stopping session")?;
        resumed_stopping_cleanup += 1;
    }
    let mut reactivated_with_fresh_sources = 0;
    for session in recovered
        .iter()
        .filter(|session| session.state == FocusSessionState::Recovering)
    {
        core.second_mind()
            .reactivate_recovered_focus_session(owner, session.id)
            .await
            .map_err(|error| anyhow!(error.summary))
            .context("restart an authorized focus session with fresh native evidence")?;
        reactivated_with_fresh_sources += 1;
    }
    Ok(RecoverySummary {
        reactivated_with_fresh_sources,
        ended_without_restart_authority,
        resumed_stopping_cleanup,
        native_cleanups_completed: cleanup.native_resource_completed,
        native_cleanups_pending: cleanup.native_resource_pending,
        secret_cleanups_completed: cleanup.secret_deletion_completed,
        secret_cleanups_pending: cleanup.secret_deletion_pending,
    })
}

fn assemble_application(build_id: &str, components: RuntimeComponents) -> Result<CoreApplication> {
    let second_mind = SecondMindRuntime::new(
        SecondMindConfig::default(),
        SecondMindPorts {
            repository: Arc::clone(&components.repository),
            clock: Arc::clone(&components.clock),
            observation: Arc::clone(&components.observation),
            model: Arc::clone(&components.model),
            notification: Arc::clone(&components.notification),
            native_status: Arc::clone(&components.native_status),
            emergency_control: Arc::clone(&components.emergency_control),
            secret_store: Arc::clone(&components.secret_store),
            resource_selection: Arc::clone(&components.resource_selection),
        },
    )
    .map_err(|error| anyhow!(error.summary))
    .context("construct the Phase 2 second-mind runtime")?;
    let capability_inputs = RuntimeCapabilityInputs {
        durable_persistence: components.durable_persistence,
        desktop_observation: components
            .observation
            .availability(PermissionScope::ObserveDesktopPresence),
        model_reasoning: components.model.availability(),
    };
    CoreApplication::build_with_second_mind_capabilities(
        build_id,
        &StaticConfigProvider::default(),
        components.secret_store.as_ref(),
        components.notification.as_ref(),
        components.native_status.as_ref(),
        components.emergency_control.as_ref(),
        second_mind,
        capability_inputs,
    )
    .map_err(|error| anyhow!(error.summary))
    .context("construct the CORE application")
}

fn build_windows_observation<T, E>(
    factory: impl FnOnce(Duration) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    factory(WINDOWS_INPUT_INACTIVITY_THRESHOLD)
}

fn stable_owner_actor(owner_sid: &str) -> ActorId {
    ActorId::from_uuid(Uuid::new_v5(&Uuid::NAMESPACE_OID, owner_sid.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use stein_core::{
        CapabilityState, CreateGoal, FocusSession, FocusSessionId, GoalId, IdempotencyKey,
        MemoryRepository, ModelRouteApprovalId, NativeStatusAcknowledgement, NativeStatusError,
        PortFuture, UnavailableEmergencyControlPort, UnavailableModelGateway,
        UnavailableNativeStatusPort, UnavailableNotificationPort, UnavailableObservationPort,
        UnavailableResourceSelectionPort, UnavailableSecretStore,
    };
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn owner_identity_matches_the_ipc_sid_derivation_exactly() {
        let sid = "S-1-5-21-1000-2000-3000-1001";
        assert_eq!(
            stable_owner_actor(sid),
            ActorId::from_uuid(Uuid::new_v5(&Uuid::NAMESPACE_OID, sid.as_bytes()))
        );
        assert_ne!(stable_owner_actor(sid), stable_owner_actor("S-1-5-21-9"));
    }

    #[test]
    fn windows_observation_receives_the_exact_input_inactivity_threshold() {
        let supplied = build_windows_observation(Ok::<Duration, ()>).unwrap();
        assert_eq!(supplied, Duration::from_secs(60));
    }

    #[derive(Default)]
    struct ControllableNativeStatus {
        clear_calls: Mutex<Vec<(FocusSessionId, u64)>>,
        fail_clear: AtomicBool,
    }

    impl NativeStatusPort for ControllableNativeStatus {
        fn availability(&self) -> PlatformPortAvailability {
            PlatformPortAvailability::Available
        }

        fn clear<'a>(
            &'a self,
            session_id: FocusSessionId,
            revision: u64,
        ) -> PortFuture<'a, std::result::Result<NativeStatusAcknowledgement, NativeStatusError>>
        {
            self.clear_calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((session_id, revision));
            let fail = self.fail_clear.load(Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    Err(NativeStatusError {
                        summary: "Synthetic clear failure.",
                        retryable: true,
                    })
                } else {
                    let acknowledged_at = OffsetDateTime::now_utc();
                    Ok(NativeStatusAcknowledgement {
                        session_id,
                        revision,
                        acknowledged_at,
                        heartbeat_deadline: acknowledged_at + time::Duration::seconds(10),
                    })
                }
            })
        }
    }

    #[tokio::test]
    async fn daemon_startup_resumes_stopping_cleanup_and_ends_fail_closed() {
        let repository = Arc::new(MemoryRepository::default());
        let owner = ActorId::new_v7();
        let session_id = FocusSessionId::new_v7();
        let now = OffsetDateTime::now_utc();
        let stopping = FocusSession {
            id: session_id,
            revision: 4,
            owner,
            goal_id: GoalId::from_uuid(Uuid::now_v7()),
            goal_revision: 1,
            state: FocusSessionState::Stopping,
            muted: false,
            source_degraded: false,
            client_disconnect_allowed: true,
            daemon_restart_allowed: false,
            permission_grant_ids: BTreeSet::new(),
            selected_resource_ids: BTreeSet::new(),
            model_route_approval_id: ModelRouteApprovalId::new_v7(),
            requested_at: now,
            started_at: Some(now),
            ended_at: None,
            updated_at: now,
            failure_reason: Some("ending_user_request".to_owned()),
        };
        repository.save_focus_session(&stopping, None).unwrap();
        let native_status = Arc::new(ControllableNativeStatus::default());
        native_status.fail_clear.store(true, Ordering::SeqCst);
        let repository_port: Arc<dyn DurableRepository> = repository.clone();
        let native_status_port: Arc<dyn NativeStatusPort> = native_status.clone();
        let core = assemble_application(
            "synthetic",
            RuntimeComponents {
                repository: repository_port,
                durable_persistence: PlatformPortAvailability::Available,
                clock: Arc::new(SystemClock::default()),
                secret_store: Arc::new(UnavailableSecretStore::default()),
                observation: Arc::new(UnavailableObservationPort),
                resource_selection: Arc::new(UnavailableResourceSelectionPort),
                model: Arc::new(UnavailableModelGateway),
                notification: Arc::new(UnavailableNotificationPort),
                native_status: native_status_port,
                emergency_control: Arc::new(UnavailableEmergencyControlPort),
            },
        )
        .unwrap();

        let summary = recover_authorized_workflows(&core, owner).await.unwrap();

        assert_eq!(summary.resumed_stopping_cleanup, 1);
        assert_eq!(
            *native_status
                .clear_calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![(session_id, stopping.revision)]
        );
        let ended = repository.find_focus_session(session_id).unwrap().unwrap();
        assert_eq!(ended.state, FocusSessionState::Ended);
        assert!(ended.source_degraded);
        assert_eq!(
            ended.failure_reason.as_deref(),
            Some("ended_cleanup_incomplete")
        );
        assert!(
            repository
                .load_audit(owner, OffsetDateTime::UNIX_EPOCH, 10)
                .unwrap()
                .iter()
                .any(|record| record
                    .reason_codes
                    .iter()
                    .any(|reason| reason == "focus_session_ended_cleanup_incomplete"))
        );
    }

    #[test]
    fn injected_repository_is_the_canonical_goal_owner() {
        let repository = Arc::new(MemoryRepository::default());
        let repository_port: Arc<dyn DurableRepository> = repository.clone();
        let components = RuntimeComponents {
            repository: repository_port,
            durable_persistence: PlatformPortAvailability::Unavailable {
                reason: "Synthetic memory repository.",
            },
            clock: Arc::new(SystemClock::default()),
            secret_store: Arc::new(UnavailableSecretStore::default()),
            observation: Arc::new(UnavailableObservationPort),
            resource_selection: Arc::new(UnavailableResourceSelectionPort),
            model: Arc::new(UnavailableModelGateway),
            notification: Arc::new(UnavailableNotificationPort),
            native_status: Arc::new(UnavailableNativeStatusPort),
            emergency_control: Arc::new(UnavailableEmergencyControlPort),
        };
        let core = assemble_application("synthetic", components).unwrap();
        let owner = ActorId::new_v7();
        core.create_goal(CreateGoal {
            actor: owner,
            idempotency_key: IdempotencyKey::new_v7(),
            title: "Synthetic Atlas review".to_owned(),
            success_statement: "A synthetic recommendation is recorded.".to_owned(),
            deadline: None,
        })
        .unwrap();

        assert_eq!(repository.load_goals(owner).unwrap().len(), 1);
        for capability_id in ["core.persistence", "observation.desktop", "model.reasoning"] {
            assert!(core.capability_health().iter().any(|capability| {
                capability.id == capability_id && capability.state == CapabilityState::Unavailable
            }));
        }
    }

    #[tokio::test]
    async fn emergency_loop_stops_cleanly_with_daemon_shutdown() {
        #[derive(Default)]
        struct WaitingEmergency {
            calls: AtomicUsize,
        }
        impl EmergencyControlPort for WaitingEmergency {
            fn availability(&self) -> stein_core::PlatformPortAvailability {
                stein_core::PlatformPortAvailability::Available
            }

            fn next_command<'a>(
                &'a self,
            ) -> stein_core::PortFuture<
                'a,
                std::result::Result<stein_core::EmergencyCommandEnvelope, &'static str>,
            > {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::pending())
            }
        }

        let emergency = Arc::new(WaitingEmergency::default());
        let emergency_port: Arc<dyn EmergencyControlPort> = emergency.clone();
        let repository: Arc<dyn DurableRepository> = Arc::new(MemoryRepository::default());
        let components = RuntimeComponents {
            repository,
            durable_persistence: PlatformPortAvailability::Unavailable {
                reason: "Synthetic memory repository.",
            },
            clock: Arc::new(SystemClock::default()),
            secret_store: Arc::new(UnavailableSecretStore::default()),
            observation: Arc::new(UnavailableObservationPort),
            resource_selection: Arc::new(UnavailableResourceSelectionPort),
            model: Arc::new(UnavailableModelGateway),
            notification: Arc::new(UnavailableNotificationPort),
            native_status: Arc::new(UnavailableNativeStatusPort),
            emergency_control: emergency_port,
        };
        let core = assemble_application("synthetic", components).unwrap();
        let shutdown = core.shutdown_token();
        let runtime = core.second_mind().clone();
        let owner = ActorId::new_v7();
        let task =
            tokio::spawn(async move { runtime.run_emergency_control_loop(owner, shutdown).await });
        tokio::task::yield_now().await;
        core.request_shutdown();

        task.await.unwrap().unwrap();
        assert_eq!(emergency.calls.load(Ordering::SeqCst), 1);
    }
}
