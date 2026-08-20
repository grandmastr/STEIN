use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

use stein_core::{
    ChannelAcknowledgement, DeliveryChannelHealth, DeliveryChannelStatus, NotificationDelivery,
    NotificationPort, NotificationPortError, PlatformPortAvailability, PresenceState,
};
use time::OffsetDateTime;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const DELIVERY_QUEUE_CAPACITY: usize = 16;
const DEDUPLICATION_WINDOW_CAPACITY: usize = 256;
const MAX_TITLE_SCALARS: usize = 64;
const MAX_BODY_SCALARS: usize = 512;

#[cfg(windows)]
mod native;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsToastRegistrationHealth {
    /// The installer or its health checker has verified that the exact AUMID,
    /// Start-menu shortcut, executable identity, and COM activator agree.
    VerifiedByInstaller,
    /// Registration has not been verified. The adapter remains fail-closed and
    /// never attempts to create or repair registration itself.
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsNotificationConfig {
    aumid: String,
    registration: WindowsToastRegistrationHealth,
}

impl WindowsNotificationConfig {
    pub fn new(
        aumid: impl Into<String>,
        registration: WindowsToastRegistrationHealth,
    ) -> Result<Self, WindowsNotificationError> {
        let aumid = aumid.into();
        if !valid_aumid(&aumid) {
            return Err(WindowsNotificationError {
                summary: "The Windows notification AUMID is invalid.",
            });
        }
        Ok(Self {
            aumid,
            registration,
        })
    }

    pub fn aumid(&self) -> &str {
        &self.aumid
    }

    pub const fn registration(&self) -> WindowsToastRegistrationHealth {
        self.registration
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsNotificationError {
    pub summary: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerHealth {
    Starting,
    Healthy,
    SuppressedByWindows,
    RegistrationUnavailable,
    NativeUnavailable,
    Degraded,
    Stopped,
}

impl WorkerHealth {
    const fn port_availability(self) -> PlatformPortAvailability {
        match self {
            Self::Healthy | Self::Degraded => PlatformPortAvailability::Available,
            Self::Starting => PlatformPortAvailability::Unavailable {
                reason: "The Windows notification channel is starting.",
            },
            Self::SuppressedByWindows => PlatformPortAvailability::Unavailable {
                reason: "Windows notification settings suppress this application.",
            },
            Self::RegistrationUnavailable => PlatformPortAvailability::Unavailable {
                reason: "The installed Windows toast identity is not verified.",
            },
            Self::NativeUnavailable => PlatformPortAvailability::Unavailable {
                reason: "The Windows App Notification API is unavailable.",
            },
            Self::Stopped => PlatformPortAvailability::Unavailable {
                reason: "The Windows notification worker stopped.",
            },
        }
    }
}

trait PresenceProbe: Send + Sync {
    fn current(&self) -> PresenceState;
}

trait ToastNative: Send + 'static {
    fn initialize(&mut self, aumid: &str) -> NativeInitialization;
    fn show(&mut self, payload: &ToastPayload) -> ToastSubmission;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeInitialization {
    Ready,
    Suppressed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToastSubmission {
    Accepted,
    DefiniteFailure,
    Unknown,
}

struct ToastPayload {
    xml: String,
    intervention_id: Uuid,
    deduplication_key: Uuid,
    expires_at: OffsetDateTime,
}

impl fmt::Debug for ToastPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToastPayload")
            .field("intervention_id", &self.intervention_id)
            .field("deduplication_key", &self.deduplication_key)
            .field("expires_at", &self.expires_at)
            .field("xml_bytes", &self.xml.len())
            .finish_non_exhaustive()
    }
}

struct ToastJob {
    payload: ToastPayload,
    cancellation: CancellationToken,
    response: oneshot::Sender<Result<ChannelAcknowledgement, NotificationPortError>>,
}

enum WorkerMessage {
    Deliver(ToastJob),
    Shutdown,
}

struct NotificationRuntime {
    sender: Option<mpsc::SyncSender<WorkerMessage>>,
    presence: Arc<dyn PresenceProbe>,
    health: Arc<Mutex<WorkerHealth>>,
    registration: WindowsToastRegistrationHealth,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl NotificationRuntime {
    fn start(
        config: WindowsNotificationConfig,
        native: Box<dyn ToastNative>,
        presence: Arc<dyn PresenceProbe>,
    ) -> Result<Self, WindowsNotificationError> {
        let (sender, receiver) = mpsc::sync_channel(DELIVERY_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let health = Arc::new(Mutex::new(WorkerHealth::Starting));
        let worker_health = Arc::clone(&health);
        let worker_presence = Arc::clone(&presence);
        let registration = config.registration;
        let thread = thread::Builder::new()
            .name("stein-windows-notification".to_owned())
            .spawn(move || {
                run_notification_worker(
                    receiver,
                    native,
                    worker_presence,
                    config,
                    worker_health,
                    ready_tx,
                );
            })
            .map_err(|_| WindowsNotificationError {
                summary: "The Windows notification worker could not start.",
            })?;
        if ready_rx.recv().is_err() {
            let _ = thread.join();
            return Err(WindowsNotificationError {
                summary: "The Windows notification worker stopped during initialization.",
            });
        }
        Ok(Self {
            sender: Some(sender),
            presence,
            health,
            registration,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn availability(&self) -> PlatformPortAvailability {
        self.health.lock().map_or(
            PlatformPortAvailability::Unavailable {
                reason: "The Windows notification health state is unavailable.",
            },
            |health| health.port_availability(),
        )
    }

    async fn deliver(
        &self,
        delivery: &NotificationDelivery,
        cancellation: CancellationToken,
    ) -> Result<ChannelAcknowledgement, NotificationPortError> {
        if cancellation.is_cancelled() {
            return Err(notification_error(
                "The Windows notification delivery was cancelled.",
                false,
            ));
        }
        let now = OffsetDateTime::now_utc();
        let payload = prepare_payload(delivery, now)?;
        if self.registration != WindowsToastRegistrationHealth::VerifiedByInstaller {
            return Err(notification_error(
                "The installed Windows toast identity is not verified.",
                false,
            ));
        }
        if self.presence.current() != PresenceState::Active {
            return Err(notification_error(
                "The Windows session is not safely interactive.",
                true,
            ));
        }
        if !self.availability().is_available() {
            return Err(notification_error(
                "The Windows notification channel is unavailable.",
                true,
            ));
        }

        let wait_cancellation = cancellation.clone();
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| notification_error("The Windows notification worker stopped.", true))?
            .try_send(WorkerMessage::Deliver(ToastJob {
                payload,
                cancellation,
                response,
            }))
            .map_err(|error| {
                if matches!(error, mpsc::TrySendError::Disconnected(_)) {
                    set_health(&self.health, WorkerHealth::Stopped);
                    notification_error("The Windows notification worker stopped.", true)
                } else {
                    set_health(&self.health, WorkerHealth::Degraded);
                    notification_error("The Windows notification queue is full.", true)
                }
            })?;

        tokio::select! {
            () = wait_cancellation.cancelled() => Err(notification_error(
                "The Windows notification delivery was cancelled.",
                false,
            )),
            result = receiver => result.unwrap_or_else(|_| {
                set_health(&self.health, WorkerHealth::Stopped);
                Err(notification_error(
                    "The Windows notification result is unknown because its worker stopped.",
                    false,
                ))
            }),
        }
    }

    fn channel_status(&self) -> DeliveryChannelStatus {
        let presence = self.presence.current();
        let worker = self
            .health
            .lock()
            .map_or(WorkerHealth::Stopped, |health| *health);
        let (health, detail) = if presence != PresenceState::Active {
            (
                DeliveryChannelHealth::Suppressed,
                "Native notifications are suppressed while the Windows session is not safely interactive.",
            )
        } else {
            match worker {
                WorkerHealth::Healthy => (
                    DeliveryChannelHealth::Healthy,
                    "Windows accepts native notification submissions for the verified AUMID.",
                ),
                WorkerHealth::SuppressedByWindows => (
                    DeliveryChannelHealth::Suppressed,
                    "Windows notification settings suppress this application.",
                ),
                WorkerHealth::Degraded => (
                    DeliveryChannelHealth::Degraded,
                    "The last Windows notification outcome was degraded or ambiguous.",
                ),
                WorkerHealth::Starting
                | WorkerHealth::RegistrationUnavailable
                | WorkerHealth::NativeUnavailable
                | WorkerHealth::Stopped => (
                    DeliveryChannelHealth::Unavailable,
                    "The Windows native notification channel is unavailable.",
                ),
            }
        };
        DeliveryChannelStatus {
            channel_id: "native_notification".to_owned(),
            health,
            detail,
            observed_at: OffsetDateTime::now_utc(),
        }
    }
}

impl Drop for NotificationRuntime {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.try_send(WorkerMessage::Shutdown);
            // Dropping the last sender guarantees that a full queue eventually
            // terminates after its already-owned bounded jobs drain.
            drop(sender);
        }
        if let Ok(thread) = self.thread.get_mut()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

fn run_notification_worker(
    receiver: mpsc::Receiver<WorkerMessage>,
    mut native: Box<dyn ToastNative>,
    presence: Arc<dyn PresenceProbe>,
    config: WindowsNotificationConfig,
    health: Arc<Mutex<WorkerHealth>>,
    ready: mpsc::SyncSender<()>,
) {
    let initialized = if config.registration != WindowsToastRegistrationHealth::VerifiedByInstaller
    {
        WorkerHealth::RegistrationUnavailable
    } else {
        match native.initialize(config.aumid()) {
            NativeInitialization::Ready => WorkerHealth::Healthy,
            NativeInitialization::Suppressed => WorkerHealth::SuppressedByWindows,
            NativeInitialization::Unavailable => WorkerHealth::NativeUnavailable,
        }
    };
    set_health(&health, initialized);
    if ready.send(()).is_err() {
        return;
    }

    let mut outcomes = HashMap::new();
    let mut outcome_order = VecDeque::new();
    while let Ok(message) = receiver.recv() {
        let WorkerMessage::Deliver(job) = message else {
            break;
        };
        let result = process_job(
            &mut *native,
            &*presence,
            &job,
            &mut outcomes,
            &mut outcome_order,
        );
        match &result {
            Ok(ChannelAcknowledgement::AcceptedByChannel) => {
                set_health(&health, WorkerHealth::Healthy)
            }
            Ok(ChannelAcknowledgement::DeliveryUnknown)
            | Ok(ChannelAcknowledgement::DeliveryFailed) => {
                set_health(&health, WorkerHealth::Degraded)
            }
            Err(_) => {}
        }
        let _ = job.response.send(result);
    }
    set_health(&health, WorkerHealth::Stopped);
}

fn process_job(
    native: &mut dyn ToastNative,
    presence: &dyn PresenceProbe,
    job: &ToastJob,
    outcomes: &mut HashMap<Uuid, ChannelAcknowledgement>,
    outcome_order: &mut VecDeque<Uuid>,
) -> Result<ChannelAcknowledgement, NotificationPortError> {
    if job.cancellation.is_cancelled() {
        return Err(notification_error(
            "The Windows notification delivery was cancelled.",
            false,
        ));
    }
    if OffsetDateTime::now_utc() >= job.payload.expires_at {
        return Err(notification_error(
            "The Windows notification expired before submission.",
            false,
        ));
    }
    if presence.current() != PresenceState::Active {
        return Err(notification_error(
            "The Windows session stopped being safely interactive before submission.",
            true,
        ));
    }
    if let Some(outcome) = outcomes.get(&job.payload.deduplication_key) {
        return Ok(*outcome);
    }
    let submission =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native.show(&job.payload)))
            .unwrap_or(ToastSubmission::Unknown);
    let outcome = match submission {
        ToastSubmission::Accepted => ChannelAcknowledgement::AcceptedByChannel,
        ToastSubmission::DefiniteFailure => ChannelAcknowledgement::DeliveryFailed,
        ToastSubmission::Unknown => ChannelAcknowledgement::DeliveryUnknown,
    };
    remember_outcome(
        outcomes,
        outcome_order,
        job.payload.deduplication_key,
        outcome,
    );
    Ok(outcome)
}

fn remember_outcome(
    outcomes: &mut HashMap<Uuid, ChannelAcknowledgement>,
    order: &mut VecDeque<Uuid>,
    key: Uuid,
    outcome: ChannelAcknowledgement,
) {
    if outcomes.insert(key, outcome).is_some() {
        return;
    }
    order.push_back(key);
    if order.len() > DEDUPLICATION_WINDOW_CAPACITY
        && let Some(expired) = order.pop_front()
    {
        outcomes.remove(&expired);
    }
}

fn prepare_payload(
    delivery: &NotificationDelivery,
    now: OffsetDateTime,
) -> Result<ToastPayload, NotificationPortError> {
    if now >= delivery.expires_at {
        return Err(notification_error(
            "The Windows notification is already expired.",
            false,
        ));
    }
    if !valid_notification_text(&delivery.title, MAX_TITLE_SCALARS)
        || !valid_notification_text(&delivery.body, MAX_BODY_SCALARS)
    {
        return Err(notification_error(
            "The Windows notification text exceeds its privacy-safe bound.",
            false,
        ));
    }
    let intervention_id = delivery.intervention_id.as_uuid();
    let activation = activation_arguments(intervention_id);
    let xml = format!(
        "<toast launch=\"{}\"><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual><actions><action content=\"Open STEIN\" arguments=\"{}\" activationType=\"foreground\"/></actions></toast>",
        xml_escape(&activation),
        xml_escape(&delivery.title),
        xml_escape(&delivery.body),
        xml_escape(&activation),
    );
    Ok(ToastPayload {
        xml,
        intervention_id,
        deduplication_key: delivery.deduplication_key,
        expires_at: delivery.expires_at,
    })
}

fn activation_arguments(intervention_id: Uuid) -> String {
    format!("action=open&intervention={intervention_id}")
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn valid_notification_text(value: &str, maximum_scalars: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= maximum_scalars
        && !value
            .chars()
            .any(|character| character == '\0' || (character.is_control() && character != '\n'))
}

fn valid_aumid(value: &str) -> bool {
    (2..=128).contains(&value.len())
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'-' | b'_'))
}

fn notification_error(summary: &'static str, retryable: bool) -> NotificationPortError {
    NotificationPortError { summary, retryable }
}

fn set_health(health: &Mutex<WorkerHealth>, value: WorkerHealth) {
    if let Ok(mut health) = health.lock() {
        *health = value;
    }
}

#[cfg(windows)]
struct WindowsSessionProbe;

#[cfg(windows)]
impl PresenceProbe for WindowsSessionProbe {
    fn current(&self) -> PresenceState {
        crate::presence::current_native_presence()
    }
}

/// Daemon-owned WinRT/App Notification delivery port. The caller supplies the
/// stable installed AUMID and an installer-produced registration-health result;
/// this adapter never creates or mutates Start-menu or activator registration.
#[cfg(windows)]
pub struct WindowsNotificationPort {
    runtime: NotificationRuntime,
}

#[cfg(windows)]
impl WindowsNotificationPort {
    pub fn start(config: WindowsNotificationConfig) -> Result<Self, WindowsNotificationError> {
        Ok(Self {
            runtime: NotificationRuntime::start(
                config,
                Box::new(native::WinRtToastNative::default()),
                Arc::new(WindowsSessionProbe),
            )?,
        })
    }
}

#[cfg(windows)]
impl fmt::Debug for WindowsNotificationPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsNotificationPort")
            .field("availability", &self.runtime.availability())
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl NotificationPort for WindowsNotificationPort {
    fn availability(&self) -> PlatformPortAvailability {
        self.runtime.availability()
    }

    fn deliver<'a>(
        &'a self,
        delivery: &'a NotificationDelivery,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<ChannelAcknowledgement, NotificationPortError>> {
        Box::pin(self.runtime.deliver(delivery, cancellation))
    }

    fn status<'a>(&'a self) -> stein_core::PortFuture<'a, DeliveryChannelStatus> {
        Box::pin(async move { self.runtime.channel_status() })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use stein_core::{InterventionId, PolicyDecisionId, Urgency};

    use super::*;

    struct StaticPresence(PresenceState);

    impl PresenceProbe for StaticPresence {
        fn current(&self) -> PresenceState {
            self.0
        }
    }

    struct ScriptedNative {
        initialization: NativeInitialization,
        outcome: ToastSubmission,
        calls: Arc<AtomicUsize>,
    }

    impl ToastNative for ScriptedNative {
        fn initialize(&mut self, _aumid: &str) -> NativeInitialization {
            self.initialization
        }

        fn show(&mut self, _payload: &ToastPayload) -> ToastSubmission {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome
        }
    }

    fn config(registration: WindowsToastRegistrationHealth) -> WindowsNotificationConfig {
        WindowsNotificationConfig::new("STEIN.Synthetic.Desktop", registration).unwrap()
    }

    fn delivery() -> NotificationDelivery {
        NotificationDelivery {
            intervention_id: InterventionId::new_v7(),
            policy_decision_id: PolicyDecisionId::new_v7(),
            title: "STEIN focus note".to_owned(),
            body: "Review the synthetic release ledger.".to_owned(),
            urgency: Urgency::Normal,
            deduplication_key: Uuid::now_v7(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(1),
        }
    }

    fn runtime(
        presence: PresenceState,
        initialization: NativeInitialization,
        outcome: ToastSubmission,
        calls: Arc<AtomicUsize>,
    ) -> NotificationRuntime {
        NotificationRuntime::start(
            config(WindowsToastRegistrationHealth::VerifiedByInstaller),
            Box::new(ScriptedNative {
                initialization,
                outcome,
                calls,
            }),
            Arc::new(StaticPresence(presence)),
        )
        .unwrap()
    }

    #[test]
    fn payload_contains_only_approved_text_and_opaque_activation() {
        let delivery = delivery();
        let payload = prepare_payload(&delivery, OffsetDateTime::now_utc()).unwrap();

        assert!(payload.xml.contains("STEIN focus note"));
        assert!(payload.xml.contains("Review the synthetic release ledger."));
        assert!(payload.xml.contains("action=open&amp;intervention="));
        assert!(
            !payload
                .xml
                .contains(&delivery.policy_decision_id.to_string())
        );
        assert!(!payload.xml.contains("grant"));
        assert!(!payload.xml.contains("path"));
        assert!(!payload.xml.contains("credential"));
    }

    #[test]
    fn xml_and_debug_rendering_do_not_leak_or_inject_markup() {
        let mut delivery = delivery();
        delivery.body = "Synthetic <review> & verify".to_owned();
        let payload = prepare_payload(&delivery, OffsetDateTime::now_utc()).unwrap();
        assert!(
            payload
                .xml
                .contains("Synthetic &lt;review&gt; &amp; verify")
        );
        assert!(!format!("{payload:?}").contains("Synthetic"));
    }

    #[tokio::test]
    async fn show_success_means_only_accepted_by_channel() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = runtime(
            PresenceState::Active,
            NativeInitialization::Ready,
            ToastSubmission::Accepted,
            Arc::clone(&calls),
        );
        let acknowledgement = runtime
            .deliver(&delivery(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(acknowledgement, ChannelAcknowledgement::AcceptedByChannel);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn locked_switched_and_unknown_presence_fail_before_native_submission() {
        for presence in [
            PresenceState::Locked,
            PresenceState::SwitchedAway,
            PresenceState::Unknown,
            PresenceState::Idle,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let runtime = runtime(
                presence,
                NativeInitialization::Ready,
                ToastSubmission::Accepted,
                Arc::clone(&calls),
            );
            assert!(
                runtime
                    .deliver(&delivery(), CancellationToken::new())
                    .await
                    .is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                runtime.channel_status().health,
                DeliveryChannelHealth::Suppressed
            );
        }
    }

    #[tokio::test]
    async fn cancellation_and_expiry_are_checked_before_queueing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = runtime(
            PresenceState::Active,
            NativeInitialization::Ready,
            ToastSubmission::Accepted,
            Arc::clone(&calls),
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(runtime.deliver(&delivery(), cancellation).await.is_err());
        let mut expired = delivery();
        expired.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        assert!(
            runtime
                .deliver(&expired, CancellationToken::new())
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn definite_and_ambiguous_native_outcomes_remain_distinct() {
        for (native, expected) in [
            (
                ToastSubmission::DefiniteFailure,
                ChannelAcknowledgement::DeliveryFailed,
            ),
            (
                ToastSubmission::Unknown,
                ChannelAcknowledgement::DeliveryUnknown,
            ),
        ] {
            let runtime = runtime(
                PresenceState::Active,
                NativeInitialization::Ready,
                native,
                Arc::new(AtomicUsize::new(0)),
            );
            assert_eq!(
                runtime
                    .deliver(&delivery(), CancellationToken::new())
                    .await
                    .unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn deduplication_does_not_resubmit_accepted_or_ambiguous_delivery() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = runtime(
            PresenceState::Active,
            NativeInitialization::Ready,
            ToastSubmission::Accepted,
            Arc::clone(&calls),
        );
        let delivery = delivery();
        for _ in 0..2 {
            assert_eq!(
                runtime
                    .deliver(&delivery, CancellationToken::new())
                    .await
                    .unwrap(),
                ChannelAcknowledgement::AcceptedByChannel
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unverified_registration_is_an_explicit_fail_closed_seam() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = NotificationRuntime::start(
            config(WindowsToastRegistrationHealth::Unavailable),
            Box::new(ScriptedNative {
                initialization: NativeInitialization::Ready,
                outcome: ToastSubmission::Accepted,
                calls,
            }),
            Arc::new(StaticPresence(PresenceState::Active)),
        )
        .unwrap();
        assert!(!runtime.availability().is_available());
        assert_eq!(
            runtime.channel_status().health,
            DeliveryChannelHealth::Unavailable
        );
    }

    #[test]
    fn aumid_and_text_bounds_are_strict() {
        assert!(
            WindowsNotificationConfig::new(
                "contains whitespace",
                WindowsToastRegistrationHealth::VerifiedByInstaller,
            )
            .is_err()
        );
        let mut delivery = delivery();
        delivery.body = "x".repeat(MAX_BODY_SCALARS + 1);
        assert!(prepare_payload(&delivery, OffsetDateTime::now_utc()).is_err());
    }

    #[test]
    fn worker_queue_is_bounded_and_does_not_depend_on_desktop_process_state() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let job = || {
            let (response, _) = oneshot::channel();
            WorkerMessage::Deliver(ToastJob {
                payload: prepare_payload(&delivery(), OffsetDateTime::now_utc()).unwrap(),
                cancellation: CancellationToken::new(),
                response,
            })
        };
        assert!(sender.try_send(job()).is_ok());
        assert!(matches!(
            sender.try_send(job()),
            Err(mpsc::TrySendError::Full(_))
        ));
    }

    #[tokio::test]
    async fn delivery_is_independent_of_tauri_lifecycle() {
        let runtime = runtime(
            PresenceState::Active,
            NativeInitialization::Ready,
            ToastSubmission::Accepted,
            Arc::new(AtomicUsize::new(0)),
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            runtime.deliver(&delivery(), CancellationToken::new()),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "submits one synthetic toast under STEIN_TEST_AUMID"]
    async fn registered_native_port_reports_os_submission_only_as_acceptance() {
        let Ok(aumid) = std::env::var("STEIN_TEST_AUMID") else {
            return;
        };
        let port = WindowsNotificationPort::start(
            WindowsNotificationConfig::new(
                aumid,
                WindowsToastRegistrationHealth::VerifiedByInstaller,
            )
            .unwrap(),
        )
        .unwrap();
        let acknowledgement =
            NotificationPort::deliver(&port, &delivery(), CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(acknowledgement, ChannelAcknowledgement::AcceptedByChannel);
    }
}
