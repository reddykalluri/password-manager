//! RFC3339 timestamp helpers shared across the server.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{AppError, AppResult};

pub fn to_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

pub fn now_rfc3339() -> String {
    to_rfc3339(OffsetDateTime::now_utc())
}

pub fn parse_rfc3339(s: &str) -> AppResult<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|e| AppError::Internal(format!("bad timestamp: {e}")))
}
