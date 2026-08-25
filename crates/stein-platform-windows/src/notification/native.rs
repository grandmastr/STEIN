use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::{DateTime, IReference, PropertyValue};
use windows::UI::Notifications::{
    NotificationSetting, ToastNotification, ToastNotificationManager, ToastNotifier,
};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{HSTRING, Interface};

use super::{NativeInitialization, ToastNative, ToastPayload, ToastSubmission};

const WINDOWS_EPOCH_OFFSET_SECONDS: i128 = 11_644_473_600;
const TICKS_PER_SECOND: i128 = 10_000_000;

#[derive(Default)]
pub(super) struct WinRtToastNative {
    apartment_initialized: bool,
    notifier: Option<ToastNotifier>,
}

impl ToastNative for WinRtToastNative {
    fn initialize(&mut self, aumid: &str) -> NativeInitialization {
        // SAFETY: called exactly once on the dedicated notification thread;
        // Drop performs the matching RoUninitialize on that same thread.
        if unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.is_err() {
            return NativeInitialization::Unavailable;
        }
        self.apartment_initialized = true;
        let Ok(notifier) =
            ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))
        else {
            return NativeInitialization::Unavailable;
        };
        let Ok(setting) = notifier.Setting() else {
            return NativeInitialization::Unavailable;
        };
        if setting != NotificationSetting::Enabled {
            return NativeInitialization::Suppressed;
        }
        self.notifier = Some(notifier);
        NativeInitialization::Ready
    }

    fn show(&mut self, payload: &ToastPayload) -> ToastSubmission {
        let Some(notifier) = self.notifier.as_ref() else {
            return ToastSubmission::DefiniteFailure;
        };
        let Ok(document) = XmlDocument::new() else {
            return ToastSubmission::DefiniteFailure;
        };
        if document.LoadXml(&HSTRING::from(&payload.xml)).is_err() {
            return ToastSubmission::DefiniteFailure;
        }
        let Ok(toast) = ToastNotification::CreateToastNotification(&document) else {
            return ToastSubmission::DefiniteFailure;
        };
        if set_expiration(&toast, payload.expires_at).is_err()
            || toast
                .SetTag(&HSTRING::from(payload.deduplication_key.to_string()))
                .is_err()
            || toast.SetGroup(&HSTRING::from("stein")).is_err()
        {
            return ToastSubmission::DefiniteFailure;
        }
        match notifier.Show(&toast) {
            Ok(()) => ToastSubmission::Accepted,
            Err(_) => ToastSubmission::DefiniteFailure,
        }
    }
}

impl Drop for WinRtToastNative {
    fn drop(&mut self) {
        if self.apartment_initialized {
            // SAFETY: balances the successful RoInitialize on this dedicated
            // worker thread; the object never leaves the thread.
            unsafe { RoUninitialize() };
        }
    }
}

fn set_expiration(
    toast: &ToastNotification,
    expires_at: time::OffsetDateTime,
) -> windows::core::Result<()> {
    let unix_ticks = i128::from(expires_at.unix_timestamp())
        .checked_add(WINDOWS_EPOCH_OFFSET_SECONDS)
        .and_then(|seconds| seconds.checked_mul(TICKS_PER_SECOND))
        .and_then(|ticks| ticks.checked_add(i128::from(expires_at.nanosecond() / 100)))
        .and_then(|ticks| i64::try_from(ticks).ok())
        .ok_or_else(|| {
            windows::core::Error::from_hresult(windows::core::HRESULT(0x80070057_u32 as i32))
        })?;
    let boxed = PropertyValue::CreateDateTime(DateTime {
        UniversalTime: unix_ticks,
    })?;
    let reference: IReference<DateTime> = boxed.cast()?;
    toast.SetExpirationTime(&reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_boundary_stays_on_its_worker_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<WinRtToastNative>();
    }

    #[test]
    #[ignore = "requires installed AUMID, activator, and interactive Windows session"]
    fn registered_native_notifier_can_initialize() {
        let Some(aumid) = std::env::var_os("STEIN_TEST_AUMID") else {
            return;
        };
        let mut native = WinRtToastNative::default();
        assert_eq!(
            native.initialize(&aumid.to_string_lossy()),
            NativeInitialization::Ready
        );
    }
}
