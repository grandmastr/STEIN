use std::fmt;

use crate::WindowsApplicationBinding;

const PREFIX: &str = "winuia:v1";
const MAXIMUM_BINDING_BYTES: usize = 1_024;

/// Canonical, path- and content-free identity for one explicitly selected
/// top-level Windows window. HWND/PID reuse is closed by the process creation
/// timestamp and the independently stable application identity.
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

    #[cfg(test)]
    pub(crate) fn parse(value: &str) -> Result<Self, UiaWindowBindingError> {
        if value.is_empty() || value.len() > MAXIMUM_BINDING_BYTES {
            return Err(malformed());
        }
        let parts: Vec<_> = value.split(':').collect();
        let [
            "winuia",
            "v1",
            window,
            process_id,
            created,
            encoded_application,
        ] = parts.as_slice()
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
        let application =
            String::from_utf8(decode_hex(encoded_application)?).map_err(|_| malformed())?;
        Self::new(
            usize::try_from(u64::from_str_radix(window, 16).map_err(|_| malformed())?)
                .map_err(|_| malformed())?,
            u32::from_str_radix(process_id, 16).map_err(|_| malformed())?,
            u64::from_str_radix(created, 16).map_err(|_| malformed())?,
            WindowsApplicationBinding::parse(&application).map_err(|_| malformed())?,
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
            self.window,
            self.process_id,
            self.process_created_at_ticks,
            encode_hex(self.application.to_string().as_bytes())
        )
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
fn decode_hex(value: &str) -> Result<Vec<u8>, UiaWindowBindingError> {
    if value.is_empty() || !value.len().is_multiple_of(2) || !value.bytes().all(is_lower_hex) {
        return Err(malformed());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
fn nibble(value: u8) -> Result<u8, UiaWindowBindingError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(malformed()),
    }
}

#[cfg(test)]
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
