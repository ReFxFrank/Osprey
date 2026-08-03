//! Platform counter reading.
//!
//! Selected at compile time rather than behind a runtime switch, matching the
//! keystore: the platform that has real counters cannot accidentally select the
//! one that has none.

#[cfg(windows)]
mod windows_impl;
#[cfg(windows)]
pub use windows_impl::Collector;

#[cfg(not(windows))]
mod unsupported;
#[cfg(not(windows))]
pub use unsupported::Collector;
