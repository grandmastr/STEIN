use crate::Revision;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    InvalidArgument,
    PermissionDenied,
    NotFound,
    Conflict,
    Unavailable,
    DeadlineExceeded,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldViolation {
    pub field: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationError {
    pub code: ErrorCode,
    pub summary: &'static str,
    pub retryable: bool,
    pub field_violations: Vec<FieldViolation>,
    pub current_revision: Option<Revision>,
}

impl ApplicationError {
    pub(crate) fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self {
            code: ErrorCode::InvalidArgument,
            summary: "The request is invalid.",
            retryable: false,
            field_violations: vec![FieldViolation { field, reason }],
            current_revision: None,
        }
    }

    pub(crate) fn cancelled() -> Self {
        Self {
            code: ErrorCode::Cancelled,
            summary: "The request was cancelled.",
            retryable: false,
            field_violations: Vec::new(),
            current_revision: None,
        }
    }

    pub(crate) fn deadline_exceeded() -> Self {
        Self {
            code: ErrorCode::DeadlineExceeded,
            summary: "The request deadline elapsed.",
            retryable: true,
            field_violations: Vec::new(),
            current_revision: None,
        }
    }
}
