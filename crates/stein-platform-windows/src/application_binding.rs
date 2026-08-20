use std::fmt;

const PREFIX: &str = "winapp:v1:";
const PACKAGED_KIND: &str = "packaged";
const UNPACKAGED_KIND: &str = "unpackaged";
// Win32's limits include the terminating NUL.
const MAX_PACKAGE_FAMILY_NAME_BYTES: usize = 63;
const MAX_AUMID_BYTES: usize = 129;
const MAX_OPAQUE_REFERENCE_BYTES: usize = 512;

/// Exact installed identity for a packaged Windows application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPackagedApplicationIdentity {
    package_family_name: String,
    application_user_model_id: String,
}

/// Exact signed-file identity for an unpackaged Windows application.
///
/// A file replacement or publisher change intentionally invalidates this
/// binding and requires a new user selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsUnpackagedApplicationIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
    publisher_sha256: [u8; 32],
}

/// Versioned Windows representation proposed for
/// `ResourceBinding.opaque_reference` when `ResourceKind::Application` is used.
/// It deliberately contains no executable path, title, process identifier, or
/// user content.
///
/// The canonical wire forms are:
///
/// - `winapp:v1:packaged:<hex-utf8-pfn>:<hex-utf8-aumid>`
/// - `winapp:v1:unpackaged:<volume-u64-hex>:<file-id-hex>:<publisher-sha256-hex>`
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsApplicationBinding {
    Packaged(WindowsPackagedApplicationIdentity),
    Unpackaged(WindowsUnpackagedApplicationIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationBindingError {
    pub summary: &'static str,
}

impl WindowsApplicationBinding {
    pub fn packaged(
        package_family_name: impl Into<String>,
        application_user_model_id: impl Into<String>,
    ) -> Result<Self, ApplicationBindingError> {
        let value = Self::Packaged(WindowsPackagedApplicationIdentity {
            package_family_name: package_family_name.into(),
            application_user_model_id: application_user_model_id.into(),
        });
        value.validate()?;
        Ok(value)
    }

    pub fn unpackaged(
        volume_serial_number: u64,
        file_id: [u8; 16],
        publisher_sha256: [u8; 32],
    ) -> Result<Self, ApplicationBindingError> {
        let value = Self::Unpackaged(WindowsUnpackagedApplicationIdentity {
            volume_serial_number,
            file_id,
            publisher_sha256,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn parse(value: &str) -> Result<Self, ApplicationBindingError> {
        if value.is_empty() || value.len() > MAX_OPAQUE_REFERENCE_BYTES {
            return Err(malformed_binding());
        }
        let components: Vec<_> = value.split(':').collect();
        match components.as_slice() {
            ["winapp", "v1", PACKAGED_KIND, package, aumid] => {
                Self::packaged(decode_text(package)?, decode_text(aumid)?)
            }
            ["winapp", "v1", UNPACKAGED_KIND, volume, file_id, publisher] => {
                if volume.len() != 16 || !volume.bytes().all(is_lower_hex) {
                    return Err(malformed_binding());
                }
                let volume_serial_number =
                    u64::from_str_radix(volume, 16).map_err(|_| malformed_binding())?;
                Self::unpackaged(
                    volume_serial_number,
                    decode_fixed::<16>(file_id)?,
                    decode_fixed::<32>(publisher)?,
                )
            }
            _ => Err(malformed_binding()),
        }
    }

    fn validate(&self) -> Result<(), ApplicationBindingError> {
        match self {
            Self::Packaged(identity) => {
                if !valid_identity_text(
                    &identity.package_family_name,
                    MAX_PACKAGE_FAMILY_NAME_BYTES,
                ) || !valid_identity_text(&identity.application_user_model_id, MAX_AUMID_BYTES)
                    || identity
                        .application_user_model_id
                        .strip_prefix(&identity.package_family_name)
                        .is_none_or(|suffix| !suffix.starts_with('!') || suffix.len() == 1)
                {
                    return Err(malformed_binding());
                }
            }
            Self::Unpackaged(identity) => {
                if identity.volume_serial_number == 0
                    || identity.file_id.iter().all(|byte| *byte == 0)
                    || identity.publisher_sha256.iter().all(|byte| *byte == 0)
                {
                    return Err(malformed_binding());
                }
            }
        }
        Ok(())
    }
}

impl WindowsPackagedApplicationIdentity {
    pub fn package_family_name(&self) -> &str {
        &self.package_family_name
    }

    pub fn application_user_model_id(&self) -> &str {
        &self.application_user_model_id
    }
}

impl WindowsUnpackagedApplicationIdentity {
    pub const fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    pub const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
    }

    pub const fn publisher_sha256(&self) -> &[u8; 32] {
        &self.publisher_sha256
    }
}

impl fmt::Display for WindowsApplicationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packaged(identity) => write!(
                formatter,
                "{PREFIX}{PACKAGED_KIND}:{}:{}",
                encode_bytes(identity.package_family_name.as_bytes()),
                encode_bytes(identity.application_user_model_id.as_bytes())
            ),
            Self::Unpackaged(identity) => write!(
                formatter,
                "{PREFIX}{UNPACKAGED_KIND}:{:016x}:{}:{}",
                identity.volume_serial_number,
                encode_bytes(&identity.file_id),
                encode_bytes(&identity.publisher_sha256)
            ),
        }
    }
}

fn valid_identity_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .chars()
            .all(|character| character.is_ascii_graphic() && !matches!(character, ':' | '/' | '\\'))
}

fn encode_bytes(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_text(value: &str) -> Result<String, ApplicationBindingError> {
    String::from_utf8(decode_bytes(value)?).map_err(|_| malformed_binding())
}

fn decode_fixed<const LENGTH: usize>(value: &str) -> Result<[u8; LENGTH], ApplicationBindingError> {
    decode_bytes(value)?
        .try_into()
        .map_err(|_| malformed_binding())
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, ApplicationBindingError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(malformed_binding());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, ApplicationBindingError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(malformed_binding()),
    }
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

fn malformed_binding() -> ApplicationBindingError {
    ApplicationBindingError {
        summary: "The Windows application binding is malformed or unsupported.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_binding_round_trips_without_delimiter_ambiguity() {
        let binding = WindowsApplicationBinding::packaged(
            "Synthetic.App_1234567890abc",
            "Synthetic.App_1234567890abc!Main",
        )
        .unwrap();
        let encoded = binding.to_string();
        assert_eq!(WindowsApplicationBinding::parse(&encoded).unwrap(), binding);
        assert!(!encoded.contains("Synthetic.App"));
        assert!(encoded.len() <= MAX_OPAQUE_REFERENCE_BYTES);
    }

    #[test]
    fn unpackaged_binding_round_trips_exact_file_and_publisher_identity() {
        let binding =
            WindowsApplicationBinding::unpackaged(0x0123, [0x45; 16], [0xab; 32]).unwrap();
        let encoded = binding.to_string();
        assert_eq!(WindowsApplicationBinding::parse(&encoded).unwrap(), binding);
        assert_eq!(encoded.len(), 1 + encoded.rfind(':').unwrap() + 64);
        assert!(encoded.len() <= MAX_OPAQUE_REFERENCE_BYTES);
    }

    #[test]
    fn malformed_or_noncanonical_bindings_fail_closed() {
        for value in [
            "",
            "winapp:v2:packaged:00:00",
            "winapp:v1:packaged:zz:00",
            "winapp:v1:packaged:00:00",
            "winapp:v1:unpackaged:1:00:00",
            "winapp:v1:unpackaged:0000000000000001:0000:0000",
            "winapp:v1:unpackaged:00000000000000AB:45454545454545454545454545454545:abababababababababababababababababababababababababababababababab",
            "winapp:v1:unpackaged:0000000000000000:45454545454545454545454545454545:abababababababababababababababababababababababababababababababab",
        ] {
            assert!(WindowsApplicationBinding::parse(value).is_err(), "{value}");
        }
        assert!(WindowsApplicationBinding::parse(&"x".repeat(513)).is_err());
    }
}
