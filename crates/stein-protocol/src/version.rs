use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 2;
pub const SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const V1_0: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: 0,
    };

    pub const V1_1: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: 1,
    };

    pub const V1_2: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: 2,
    };

    pub const CURRENT: Self = Self::V1_2;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolSupport {
    pub major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
}

impl ProtocolSupport {
    /// Every released minor in protocol major 1.
    pub const V1: Self = Self {
        major: PROTOCOL_MAJOR,
        minimum_minor: 0,
        maximum_minor: PROTOCOL_MINOR,
    };

    pub const V1_0: Self = Self::exact(ProtocolVersion::V1_0);
    pub const V1_1: Self = Self::exact(ProtocolVersion::V1_1);
    pub const V1_2: Self = Self::exact(ProtocolVersion::V1_2);

    #[must_use]
    pub const fn exact(version: ProtocolVersion) -> Self {
        Self {
            major: version.major,
            minimum_minor: version.minor,
            maximum_minor: version.minor,
        }
    }

    #[must_use]
    pub const fn supports(self, version: ProtocolVersion) -> bool {
        self.major == version.major
            && self.minimum_minor <= version.minor
            && version.minor <= self.maximum_minor
    }
}

/// Selects the newest minor version understood by both peers.
pub fn negotiate_protocol(
    client: ProtocolSupport,
    server: ProtocolSupport,
) -> Result<ProtocolVersion, CompatibilityError> {
    if client.minimum_minor > client.maximum_minor || server.minimum_minor > server.maximum_minor {
        return Err(CompatibilityError::InvalidRange);
    }
    if client.major != server.major {
        return Err(CompatibilityError::MajorVersionMismatch {
            client_major: client.major,
            server_major: server.major,
        });
    }

    let minimum_minor = client.minimum_minor.max(server.minimum_minor);
    let maximum_minor = client.maximum_minor.min(server.maximum_minor);
    if minimum_minor > maximum_minor {
        return Err(CompatibilityError::NoSharedMinorVersion {
            major: client.major,
            client_minimum_minor: client.minimum_minor,
            client_maximum_minor: client.maximum_minor,
            server_minimum_minor: server.minimum_minor,
            server_maximum_minor: server.maximum_minor,
        });
    }

    Ok(ProtocolVersion {
        major: client.major,
        minor: maximum_minor,
    })
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompatibilityError {
    #[error("protocol minor version range is invalid")]
    InvalidRange,
    #[error(
        "client protocol major {client_major} is incompatible with server major {server_major}"
    )]
    MajorVersionMismatch {
        client_major: u16,
        server_major: u16,
    },
    #[error("protocol major {major} has no shared minor version")]
    NoSharedMinorVersion {
        major: u16,
        client_minimum_minor: u16,
        client_maximum_minor: u16,
        server_minimum_minor: u16,
        server_maximum_minor: u16,
    },
}
