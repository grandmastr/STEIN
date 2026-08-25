use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

/// A protocol wall-clock instant serialized as RFC 3339 with a UTC `Z` offset.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp(OffsetDateTime);

impl UtcTimestamp {
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Normalizes an instant to UTC before it reaches the wire.
    #[must_use]
    pub fn from_datetime(value: OffsetDateTime) -> Self {
        Self(value.to_offset(UtcOffset::UTC))
    }

    #[must_use]
    pub const fn as_datetime(&self) -> OffsetDateTime {
        self.0
    }

    #[must_use]
    pub const fn unix_timestamp(&self) -> i64 {
        self.0.unix_timestamp()
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self
            .0
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|_| fmt::Error)?;
        formatter.write_str(&value)
    }
}

impl FromStr for UtcTimestamp {
    type Err = TimestampParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !value.ends_with('Z') {
            return Err(TimestampParseError::NotUtc);
        }

        OffsetDateTime::parse(value, &Rfc3339)
            .map(Self::from_datetime)
            .map_err(TimestampParseError::Invalid)
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum TimestampParseError {
    #[error("timestamp must use the UTC Z offset")]
    NotUtc,
    #[error("invalid RFC 3339 timestamp: {0}")]
    Invalid(time::error::Parse),
}
