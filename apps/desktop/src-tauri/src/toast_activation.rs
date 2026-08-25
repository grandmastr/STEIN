//! Packaged Windows toast activation for the Tauri desktop.
//!
//! The package manifest maps one fixed COM CLSID to this executable. This
//! module registers that class only when the current process token proves the
//! exact production desktop AUMID. The COM callback accepts only the opaque
//! `action=open&intervention=<canonical UUID>` payload emitted by CORE; it does
//! not accept command-line payloads, user input, private text, or authority.

use std::{ffi::c_void, mem::ManuallyDrop, sync::Arc};

use tokio::sync::mpsc::{Receiver, Sender, channel};
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOINTERFACE, RPC_E_CHANGED_MODE},
        System::Com::{
            CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, CoInitializeEx, CoRegisterClassObject,
            CoRevokeClassObject, CoUninitialize, IClassFactory, IClassFactory_Impl,
            REGCLS_MULTIPLEUSE,
        },
        UI::Notifications::{
            INotificationActivationCallback, INotificationActivationCallback_Impl,
            NOTIFICATION_USER_INPUT_DATA,
        },
    },
    core::{BOOL, GUID, IUnknown, Interface, PCWSTR, Ref},
};

use crate::bridge::CoreBridge;
use crate::private_broker::{PrivateBrokerError, current_desktop_aumid};
use tauri::{Emitter, Manager, WebviewWindow};

#[cfg(test)]
const TOAST_ACTIVATOR_CLSID_TEXT: &str = "3DB3B5B0-1BA5-49D1-A8F0-CF2B3EA6D781";
const TOAST_ACTIVATOR_CLSID: GUID = GUID::from_u128(0x3db3b5b0_1ba5_49d1_a8f0_cf2b3ea6d781);
const TOAST_ACTIVATED_ARGUMENT: &str = "-ToastActivated";
const ACTIVATION_PREFIX: &str = "action=open&intervention=";
const ACTIVATION_QUEUE_CAPACITY: usize = 8;
const MAXIMUM_AUMID_UTF16_UNITS: usize = 256;
const MAXIMUM_ACTIVATION_UTF16_UNITS: usize = 128;
pub(crate) const TOAST_ACTIVATION_EVENT: &str = "stein://toast-activation";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToastActivation {
    pub(crate) intervention_id: Uuid,
}

#[derive(Debug)]
pub(crate) enum ToastActivationStartup {
    Registered(ToastActivationRegistration),
    NotPackaged,
    Rejected,
}

pub(crate) struct ToastActivationRegistration {
    receiver: Option<Receiver<ToastActivation>>,
    class_cookie: u32,
    uninitialize_com: bool,
    // Retain our reference for the same lifetime as the class registration.
    _factory: IClassFactory,
}

impl std::fmt::Debug for ToastActivationRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ToastActivationRegistration")
            .field("registered", &true)
            .finish_non_exhaustive()
    }
}

impl ToastActivationRegistration {
    pub(crate) fn take_receiver(&mut self) -> Option<Receiver<ToastActivation>> {
        self.receiver.take()
    }
}

pub(crate) fn spawn(app: tauri::AppHandle, mut receiver: Receiver<ToastActivation>) {
    tauri::async_runtime::spawn(async move {
        while let Some(activation) = receiver.recv().await {
            focus_main_window(&app);
            let bridge = app.state::<CoreBridge>().inner().clone();
            let mut attempt = 0_u8;
            loop {
                attempt = attempt.saturating_add(1);
                match bridge
                    .resolve_toast_activation(&app, activation.intervention_id)
                    .await
                {
                    Ok(explanation) => {
                        if let Err(error) = app.emit(TOAST_ACTIVATION_EVENT, explanation) {
                            tracing::warn!(
                                %error,
                                intervention_id = %activation.intervention_id,
                                "could not route the authoritative toast explanation to the desktop"
                            );
                        }
                        tracing::info!(
                            intervention_id = %activation.intervention_id,
                            "resolved packaged toast activation through authoritative CORE state"
                        );
                        break;
                    }
                    Err(error) if error.retryable && attempt < 3 => {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    Err(error) => {
                        tracing::warn!(
                            code = %error.code,
                            intervention_id = %activation.intervention_id,
                            "rejected or could not resolve packaged toast activation"
                        );
                        break;
                    }
                }
            }
        }
    });
}

fn focus_main_window(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    focus_window(&window);
}

fn focus_window(window: &WebviewWindow) {
    if let Err(error) = window.show() {
        tracing::warn!(%error, "could not show the desktop for toast activation");
        return;
    }
    if let Err(error) = window.unminimize() {
        tracing::warn!(%error, "could not restore the desktop for toast activation");
        return;
    }
    if let Err(error) = window.set_focus() {
        tracing::warn!(%error, "could not focus the desktop for toast activation");
    }
}

impl Drop for ToastActivationRegistration {
    fn drop(&mut self) {
        // SAFETY: `class_cookie` came from this process's successful
        // `CoRegisterClassObject` call and is revoked before its COM apartment.
        let _ = unsafe { CoRevokeClassObject(self.class_cookie) };
        if self.uninitialize_com {
            // SAFETY: this balances the successful initialization performed by
            // `initialize` on the same main thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// Register the packaged activation class. Unpackaged development launches may
/// continue without it, but a direct `-ToastActivated` launch is always rejected
/// unless the process has the exact production package identity and COM setup
/// succeeds. The actual opaque payload arrives only through the COM callback.
pub(crate) fn initialize(arguments: impl IntoIterator<Item = String>) -> ToastActivationStartup {
    let toast_launch = match classify_process_launch(arguments) {
        Some(toast_launch) => toast_launch,
        None => return ToastActivationStartup::Rejected,
    };
    let expected_aumid = match current_desktop_aumid() {
        Ok(aumid) => Arc::<str>::from(aumid),
        Err(PrivateBrokerError::Unpackaged) if !toast_launch => {
            return ToastActivationStartup::NotPackaged;
        }
        Err(_) => return ToastActivationStartup::Rejected,
    };

    let initialization = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let uninitialize_com = if initialization.is_ok() {
        true
    } else if initialization == RPC_E_CHANGED_MODE {
        false
    } else {
        return ToastActivationStartup::Rejected;
    };

    let (sender, receiver) = channel(ACTIVATION_QUEUE_CAPACITY);
    let factory: IClassFactory = ToastActivatorFactory {
        expected_aumid,
        sender,
    }
    .into();
    // SAFETY: COM is initialized for this thread, the CLSID is the exact value
    // declared in the signed manifest, and `factory` implements IClassFactory.
    let class_cookie = match unsafe {
        CoRegisterClassObject(
            &TOAST_ACTIVATOR_CLSID,
            &factory,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE,
        )
    } {
        Ok(cookie) => cookie,
        Err(_) => {
            if uninitialize_com {
                // SAFETY: balances the successful call above on this thread.
                unsafe { CoUninitialize() };
            }
            return ToastActivationStartup::Rejected;
        }
    };

    ToastActivationStartup::Registered(ToastActivationRegistration {
        receiver: Some(receiver),
        class_cookie,
        uninitialize_com,
        _factory: factory,
    })
}

fn classify_process_launch(arguments: impl IntoIterator<Item = String>) -> Option<bool> {
    let arguments = arguments.into_iter().skip(1).collect::<Vec<_>>();
    let toast_like = arguments.iter().any(|argument| {
        argument
            .get(..TOAST_ACTIVATED_ARGUMENT.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TOAST_ACTIVATED_ARGUMENT))
    });
    if !toast_like {
        return Some(false);
    }
    (arguments.len() == 1 && arguments[0] == TOAST_ACTIVATED_ARGUMENT).then_some(true)
}

fn parse_activation(value: &str) -> Option<ToastActivation> {
    let identifier = value.strip_prefix(ACTIVATION_PREFIX)?;
    if identifier.len() != 36 || identifier.contains('&') || identifier.contains('=') {
        return None;
    }
    let intervention_id = Uuid::parse_str(identifier).ok()?;
    if intervention_id.hyphenated().to_string() != identifier {
        return None;
    }
    Some(ToastActivation { intervention_id })
}

fn wide_string(value: &PCWSTR, maximum_units: usize) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let pointer = value.as_ptr();
    for length in 0..=maximum_units {
        // SAFETY: COM marshals each callback PCWSTR as a NUL-terminated value
        // for this synchronous call. We inspect at most the declared hard
        // ceiling plus its terminator and copy before returning.
        if unsafe { *pointer.add(length) } == 0 {
            // SAFETY: the loop proved that these `length` units precede the
            // terminator in the callback-owned buffer.
            let units = unsafe { std::slice::from_raw_parts(pointer, length) };
            return String::from_utf16(units).ok();
        }
    }
    None
}

#[windows::core::implement(INotificationActivationCallback)]
struct ToastActivator {
    expected_aumid: Arc<str>,
    sender: Sender<ToastActivation>,
}

#[allow(non_snake_case)]
impl INotificationActivationCallback_Impl for ToastActivator_Impl {
    fn Activate(
        &self,
        app_user_model_id: &PCWSTR,
        invoked_arguments: &PCWSTR,
        data: *const NOTIFICATION_USER_INPUT_DATA,
        count: u32,
    ) -> windows::core::Result<()> {
        if count != 0 {
            return Err(windows::core::Error::from(E_INVALIDARG));
        }
        let _ = data;
        let Some(aumid) = wide_string(app_user_model_id, MAXIMUM_AUMID_UTF16_UNITS) else {
            return Err(windows::core::Error::from(E_INVALIDARG));
        };
        let Some(arguments) = wide_string(invoked_arguments, MAXIMUM_ACTIVATION_UTF16_UNITS) else {
            return Err(windows::core::Error::from(E_INVALIDARG));
        };
        if aumid != self.expected_aumid.as_ref() {
            return Err(windows::core::Error::from(E_INVALIDARG));
        }
        let Some(activation) = parse_activation(&arguments) else {
            return Err(windows::core::Error::from(E_INVALIDARG));
        };
        self.sender
            .try_send(activation)
            .map_err(|_| windows::core::Error::from(E_INVALIDARG))
    }
}

#[windows::core::implement(IClassFactory)]
struct ToastActivatorFactory {
    expected_aumid: Arc<str>,
    sender: Sender<ToastActivation>,
}

#[allow(non_snake_case)]
impl IClassFactory_Impl for ToastActivatorFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<'_, IUnknown>,
        requested_interface: *const GUID,
        object: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        if object.is_null() || requested_interface.is_null() {
            return Err(windows::core::Error::from(E_INVALIDARG));
        }
        // SAFETY: `object` is a non-null COM output pointer supplied by COM.
        unsafe { *object = std::ptr::null_mut() };
        if !outer.is_null() {
            return Err(windows::core::Error::from(CLASS_E_NOAGGREGATION));
        }
        // SAFETY: pointer nullity was checked and COM keeps the IID live for
        // the duration of this synchronous call.
        let requested_interface = unsafe { &*requested_interface };
        if requested_interface != &INotificationActivationCallback::IID
            && requested_interface != &IUnknown::IID
        {
            return Err(windows::core::Error::from(E_NOINTERFACE));
        }

        let callback: INotificationActivationCallback = ToastActivator {
            expected_aumid: Arc::clone(&self.expected_aumid),
            sender: self.sender.clone(),
        }
        .into();
        let callback = ManuallyDrop::new(callback);
        // Both accepted IIDs have the same IUnknown identity pointer because
        // the callback implements exactly one interface.
        // SAFETY: `object` is valid and ownership of one COM reference is
        // transferred to the caller by preventing the local drop.
        unsafe { *object = callback.as_raw() };
        Ok(())
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "018f0000-0000-7000-8000-000000000901";

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn accepts_only_exact_open_action_and_canonical_uuid() {
        assert_eq!(
            parse_activation(&format!("{ACTIVATION_PREFIX}{ID}")),
            Some(ToastActivation {
                intervention_id: Uuid::parse_str(ID).unwrap(),
            })
        );

        for malformed in [
            "",
            "action=Open&intervention=018f0000-0000-7000-8000-000000000901",
            "action=open",
            "action=open&intervention=018F0000-0000-7000-8000-000000000901",
            "action=open&intervention=018f0000000070008000000000000901",
            "action=open&intervention=018f0000-0000-7000-8000-000000000901&goal=private",
            "action=open&intervention=not-a-uuid",
        ] {
            assert_eq!(parse_activation(malformed), None, "accepted {malformed}");
        }
    }

    #[test]
    fn command_line_recognizes_only_the_fixed_marker_and_never_a_payload() {
        assert_eq!(
            classify_process_launch([
                "stein-desktop.exe".to_owned(),
                TOAST_ACTIVATED_ARGUMENT.to_owned(),
            ]),
            Some(true)
        );
        for rejected in [
            vec![
                "stein-desktop.exe".to_owned(),
                "-ToastActivated:action=open&intervention=private".to_owned(),
            ],
            vec![
                "stein-desktop.exe".to_owned(),
                TOAST_ACTIVATED_ARGUMENT.to_owned(),
                "action=open&intervention=private".to_owned(),
            ],
            vec!["stein-desktop.exe".to_owned(), "-toastactivated".to_owned()],
        ] {
            assert_eq!(classify_process_launch(rejected), None);
        }
        assert_eq!(
            classify_process_launch(["stein-desktop.exe".to_owned(), "--diagnostic".to_owned(),]),
            Some(false)
        );
    }

    #[test]
    fn activator_clsid_is_stable_and_canonical() {
        let parsed = Uuid::parse_str(TOAST_ACTIVATOR_CLSID_TEXT).unwrap();
        assert_eq!(TOAST_ACTIVATOR_CLSID, GUID::from_u128(parsed.as_u128()));
    }

    #[test]
    fn com_callback_validates_identity_and_forbids_user_input_before_dispatch() {
        let expected_aumid = Arc::<str>::from("STEIN.PersonalIntelligence_qrfd6g9swygw6!Desktop");
        let (sender, mut receiver) = channel(ACTIVATION_QUEUE_CAPACITY);
        let callback: INotificationActivationCallback = ToastActivator {
            expected_aumid: Arc::clone(&expected_aumid),
            sender,
        }
        .into();
        let aumid = wide(&expected_aumid);
        let arguments = wide(&format!("{ACTIVATION_PREFIX}{ID}"));
        // SAFETY: the test-owned null-terminated UTF-16 buffers outlive each
        // synchronous COM call.
        unsafe {
            callback
                .Activate(PCWSTR(aumid.as_ptr()), PCWSTR(arguments.as_ptr()), &[])
                .unwrap();
        }
        assert_eq!(
            receiver.try_recv().unwrap(),
            ToastActivation {
                intervention_id: Uuid::parse_str(ID).unwrap(),
            }
        );

        let wrong_aumid = wide("STEIN.PersonalIntelligence_wrong!Desktop");
        // SAFETY: same buffer-lifetime argument as above.
        assert!(
            unsafe {
                callback.Activate(
                    PCWSTR(wrong_aumid.as_ptr()),
                    PCWSTR(arguments.as_ptr()),
                    &[],
                )
            }
            .is_err()
        );
        let input = [NOTIFICATION_USER_INPUT_DATA::default()];
        // SAFETY: same buffer-lifetime argument as above; nonempty input is
        // deliberately rejected before it is read.
        assert!(
            unsafe {
                callback.Activate(PCWSTR(aumid.as_ptr()), PCWSTR(arguments.as_ptr()), &input)
            }
            .is_err()
        );
        assert!(receiver.try_recv().is_err());

        let oversized_arguments = wide(&"x".repeat(MAXIMUM_ACTIVATION_UTF16_UNITS + 1));
        // SAFETY: the oversized test buffer remains valid and terminated; the
        // callback must reject it at the local hard ceiling.
        assert!(
            unsafe {
                callback.Activate(
                    PCWSTR(aumid.as_ptr()),
                    PCWSTR(oversized_arguments.as_ptr()),
                    &[],
                )
            }
            .is_err()
        );
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn unpackaged_direct_toast_server_launch_is_rejected_before_tauri() {
        assert!(matches!(
            initialize([
                "stein-desktop.exe".to_owned(),
                TOAST_ACTIVATED_ARGUMENT.to_owned(),
            ]),
            ToastActivationStartup::Rejected
        ));
        assert!(matches!(
            initialize(["stein-desktop.exe".to_owned()]),
            ToastActivationStartup::NotPackaged
        ));
    }
}
