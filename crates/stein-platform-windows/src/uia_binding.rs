use std::fmt;

use crate::WindowsApplicationBinding;

const PREFIX: &str = "winuia:v1";
// CORE's selected-resource contract accepts at most 512 bytes. Keep the
// adapter's canonical binding within that public boundary so a successful
// native pick cannot later fail solely during registration.
const MAXIMUM_BINDING_BYTES: usize = 512;

/// Canonical, path- and content-free identity for one explicitly selected
/// top-level Windows window. The HWND is coupled to its owner process creation
/// time and stable application identity so stale cross-process reuse fails
/// closed during revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsUiaWindowBinding {
    window: usize,
    process_id: u32,
    process_created_at_ticks: u64,
    application: WindowsApplicationBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiaWindowBindingError {
    pub summary: &'static str,
}

impl WindowsUiaWindowBinding {
    pub(crate) fn new(
        window: usize,
        process_id: u32,
        process_created_at_ticks: u64,
        application: WindowsApplicationBinding,
    ) -> Result<Self, UiaWindowBindingError> {
        if window == 0 || process_id == 0 || process_created_at_ticks == 0 {
            return Err(malformed());
        }
        let value = Self {
            window,
            process_id,
            process_created_at_ticks,
            application,
        };
        if value.to_string().len() > MAXIMUM_BINDING_BYTES {
            return Err(malformed());
        }
        Ok(value)
    }

    pub(crate) fn parse(value: &str) -> Result<Self, UiaWindowBindingError> {
        if value.is_empty() || value.len() > MAXIMUM_BINDING_BYTES {
            return Err(malformed());
        }
        let mut parts = value.splitn(6, ':');
        let (
            Some("winuia"),
            Some("v1"),
            Some(window),
            Some(process_id),
            Some(created),
            Some(application),
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Err(malformed());
        };
        if window.len() != 16
            || process_id.len() != 8
            || created.len() != 16
            || !window.bytes().all(is_lower_hex)
            || !process_id.bytes().all(is_lower_hex)
            || !created.bytes().all(is_lower_hex)
        {
            return Err(malformed());
        }
        Self::new(
            usize::try_from(u64::from_str_radix(window, 16).map_err(|_| malformed())?)
                .map_err(|_| malformed())?,
            u32::from_str_radix(process_id, 16).map_err(|_| malformed())?,
            u64::from_str_radix(created, 16).map_err(|_| malformed())?,
            WindowsApplicationBinding::parse(application).map_err(|_| malformed())?,
        )
    }

    pub(crate) const fn window(&self) -> usize {
        self.window
    }

    pub(crate) const fn process_id(&self) -> u32 {
        self.process_id
    }

    pub(crate) const fn process_created_at_ticks(&self) -> u64 {
        self.process_created_at_ticks
    }

    pub(crate) fn application(&self) -> &WindowsApplicationBinding {
        &self.application
    }
}

impl fmt::Display for WindowsUiaWindowBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{PREFIX}:{:016x}:{:08x}:{:016x}:{}",
            self.window, self.process_id, self.process_created_at_ticks, self.application
        )
    }
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

fn malformed() -> UiaWindowBindingError {
    UiaWindowBindingError {
        summary: "The selected Windows UI Automation binding is malformed or stale.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> WindowsUiaWindowBinding {
        WindowsUiaWindowBinding::new(
            0x1234,
            0x4567,
            0x0102_0304_0506_0708,
            WindowsApplicationBinding::unpackaged(9, [0x11; 16], [0x22; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn selected_window_binding_round_trips_without_content_or_paths() {
        let binding = fixture();
        let encoded = binding.to_string();
        assert_eq!(WindowsUiaWindowBinding::parse(&encoded).unwrap(), binding);
        assert!(!encoded.contains('\\'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains("Notepad"));
        assert!(encoded.len() <= MAXIMUM_BINDING_BYTES);
    }

    #[test]
    fn maximum_packaged_application_identity_stays_inside_core_resource_limit() {
        let package_family = "p".repeat(63);
        let application_id = format!("{package_family}!{}", "a".repeat(65));
        let binding = WindowsUiaWindowBinding::new(
            0x1234,
            0x4567,
            0x0102_0304_0506_0708,
            WindowsApplicationBinding::packaged(package_family, application_id).unwrap(),
        )
        .unwrap();

        let encoded = binding.to_string();
        assert!(encoded.len() <= MAXIMUM_BINDING_BYTES);
        assert_eq!(WindowsUiaWindowBinding::parse(&encoded).unwrap(), binding);
    }

    #[test]
    fn malformed_noncanonical_or_zero_window_bindings_fail_closed() {
        for value in [
            "",
            "winuia:v2:0000000000001234:00004567:0102030405060708:00",
            "winuia:v1:0000000000000000:00004567:0102030405060708:00",
            "winuia:v1:0000000000001234:00000000:0102030405060708:00",
            "winuia:v1:0000000000001234:00004567:0000000000000000:00",
            "winuia:v1:000000000000ABCD:00004567:0102030405060708:00",
        ] {
            assert!(WindowsUiaWindowBinding::parse(value).is_err(), "{value}");
        }
        assert!(WindowsUiaWindowBinding::parse(&"x".repeat(MAXIMUM_BINDING_BYTES + 1)).is_err());
    }
}
