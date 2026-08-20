use std::fmt;

use stein_core::ResourceKind;

const PREFIX: &str = "winresource:v1:";
const DOCUMENT_KIND: &str = "document";
const WORKSPACE_KIND: &str = "workspace";
const TEXT_FORMAT: &str = "txt";
const MARKDOWN_FORMAT: &str = "md";
const MAX_OPAQUE_REFERENCE_BYTES: usize = 128;

/// The locally verified extraction format of an explicitly selected document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsDocumentFormat {
    PlainText,
    Markdown,
}

impl WindowsDocumentFormat {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::PlainText => TEXT_FORMAT,
            Self::Markdown => MARKDOWN_FORMAT,
        }
    }

    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            TEXT_FORMAT => Some(Self::PlainText),
            MARKDOWN_FORMAT => Some(Self::Markdown),
            _ => None,
        }
    }
}

/// Path-free identity established from a handle returned by a trusted Windows
/// picker. It contains no file name, directory name, local path, or content.
///
/// Canonical wire forms are:
///
/// - `winresource:v1:document:<volume-u64-hex>:<file-id-128-hex>:txt`
/// - `winresource:v1:document:<volume-u64-hex>:<file-id-128-hex>:md`
/// - `winresource:v1:workspace:<volume-u64-hex>:<file-id-128-hex>`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsSelectedResourceBinding {
    volume_identity: u64,
    file_id: [u8; 16],
    kind: ResourceKind,
    document_format: Option<WindowsDocumentFormat>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedResourceBindingError {
    pub summary: &'static str,
}

impl WindowsSelectedResourceBinding {
    pub fn parse(value: &str) -> Result<Self, SelectedResourceBindingError> {
        if value.is_empty() || value.len() > MAX_OPAQUE_REFERENCE_BYTES {
            return Err(malformed_binding());
        }
        let components: Vec<_> = value.split(':').collect();
        let binding = match components.as_slice() {
            ["winresource", "v1", DOCUMENT_KIND, volume, file_id, format] => Self {
                volume_identity: decode_volume(volume)?,
                file_id: decode_fixed::<16>(file_id)?,
                kind: ResourceKind::Document,
                document_format: Some(
                    WindowsDocumentFormat::from_wire_name(format).ok_or_else(malformed_binding)?,
                ),
            },
            ["winresource", "v1", WORKSPACE_KIND, volume, file_id] => Self {
                volume_identity: decode_volume(volume)?,
                file_id: decode_fixed::<16>(file_id)?,
                kind: ResourceKind::Workspace,
                document_format: None,
            },
            _ => return Err(malformed_binding()),
        };
        binding.validate()?;
        if binding.to_string() != value {
            return Err(malformed_binding());
        }
        Ok(binding)
    }

    pub const fn volume_identity(&self) -> u64 {
        self.volume_identity
    }

    pub const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
    }

    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub const fn document_format(&self) -> Option<WindowsDocumentFormat> {
        self.document_format
    }

    pub(crate) fn from_selected_handle(
        volume_identity: u64,
        file_id: [u8; 16],
        kind: ResourceKind,
        document_format: Option<WindowsDocumentFormat>,
    ) -> Result<Self, SelectedResourceBindingError> {
        let value = Self {
            volume_identity,
            file_id,
            kind,
            document_format,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SelectedResourceBindingError> {
        if self.volume_identity == 0 || self.file_id.iter().all(|byte| *byte == 0) {
            return Err(malformed_binding());
        }
        match (self.kind, self.document_format) {
            (ResourceKind::Document, Some(_)) | (ResourceKind::Workspace, None) => Ok(()),
            _ => Err(malformed_binding()),
        }
    }
}

impl fmt::Display for WindowsSelectedResourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind, self.document_format) {
            (ResourceKind::Document, Some(format)) => write!(
                formatter,
                "{PREFIX}{DOCUMENT_KIND}:{:016x}:{}:{}",
                self.volume_identity,
                encode_bytes(&self.file_id),
                format.wire_name(),
            ),
            (ResourceKind::Workspace, None) => write!(
                formatter,
                "{PREFIX}{WORKSPACE_KIND}:{:016x}:{}",
                self.volume_identity,
                encode_bytes(&self.file_id),
            ),
            _ => Err(fmt::Error),
        }
    }
}

fn decode_volume(value: &str) -> Result<u64, SelectedResourceBindingError> {
    if value.len() != 16 || !value.bytes().all(is_lower_hex) {
        return Err(malformed_binding());
    }
    u64::from_str_radix(value, 16).map_err(|_| malformed_binding())
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

fn decode_fixed<const LENGTH: usize>(
    value: &str,
) -> Result<[u8; LENGTH], SelectedResourceBindingError> {
    if value.len() != LENGTH * 2 || !value.bytes().all(is_lower_hex) {
        return Err(malformed_binding());
    }
    let mut decoded = [0_u8; LENGTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or_else(malformed_binding)?;
        let low = decode_nibble(pair[1]).ok_or_else(malformed_binding)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

fn malformed_binding() -> SelectedResourceBindingError {
    SelectedResourceBindingError {
        summary: "The Windows selected-resource binding is malformed or unsupported.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_free_document_and_workspace_bindings_round_trip_canonically() {
        let document = WindowsSelectedResourceBinding::from_selected_handle(
            0x0123,
            [0xab; 16],
            ResourceKind::Document,
            Some(WindowsDocumentFormat::Markdown),
        )
        .unwrap();
        let workspace = WindowsSelectedResourceBinding::from_selected_handle(
            0x4567,
            [0xcd; 16],
            ResourceKind::Workspace,
            None,
        )
        .unwrap();

        for binding in [document, workspace] {
            let encoded = binding.to_string();
            assert_eq!(
                WindowsSelectedResourceBinding::parse(&encoded).unwrap(),
                binding
            );
            assert!(!encoded.contains(['/', '\\']));
            assert!(encoded.len() <= MAX_OPAQUE_REFERENCE_BYTES);
        }
    }

    #[test]
    fn noncanonical_or_cross_kind_bindings_fail_closed() {
        for malformed in [
            "",
            "winresource:v1:document:0000000000000001:abab:md",
            "winresource:v1:document:0000000000000001:abababababababababababababababab:pdf",
            "winresource:v1:workspace:0000000000000000:abababababababababababababababab",
            "winresource:v1:workspace:0000000000000001:ABABABABABABABABABABABABABABABAB",
            "winresource:v1:workspace:0000000000000001:abababababababababababababababab:md",
        ] {
            assert!(WindowsSelectedResourceBinding::parse(malformed).is_err());
        }
    }
}
