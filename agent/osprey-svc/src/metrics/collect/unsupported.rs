//! The non-Windows collector, which collects nothing.
//!
//! Windows is the only agent platform (brief §2), but the crate must build and
//! its tests must run on the Linux CI host. This exists so that happens without
//! anyone being tempted to return plausible numbers there: every call fails
//! loudly, and the engine surfaces the failure rather than storing a sample.

use crate::metrics::{MetricsError, Sample};

pub struct Collector;

impl Collector {
    pub fn new() -> Self {
        Self
    }

    pub fn sample(&mut self) -> Result<Sample, MetricsError> {
        Err(MetricsError::Unsupported)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}
