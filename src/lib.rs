//! drill-core — shared event schema and drill primitives for pleme-io
//! drill orchestrators (`pitr-forge`, `failover-forge`).
//!
//! This crate centralizes the event schema, `drill_id` semantics, and
//! event emission machinery so that multiple drill tools share a single
//! source of truth. Downstream consumers (shinryū queries, report
//! assemblers, dashboards) can rely on a stable event envelope shape
//! regardless of which forge produced the events.
//!
//! ## What lives here
//!
//! - [`events`] — `DrillEvent` enum, `EventEnvelope`, `EventContext`,
//!   `emit()`, drill_id construction, file capture for tarball assembly
//!
//! ## Future extractions
//!
//! When `pitr-forge` and `failover-forge` accumulate enough common code,
//! candidate next extractions:
//!
//! - `tarball` (currently lives in pitr-forge with a hard dep on its
//!   `DrillResult` type)
//! - `manifest` (drill_id, verdict, RTO, gate counts — common shape)
//! - `gate` traits (pass/fail/expected/actual semantics)

#![allow(clippy::module_name_repetitions)]

pub mod events;

pub use events::{
    emit, DrillEvent, EventContext, EventEnvelope, Mode, Phase, Verdict, EVENT_SCHEMA_VERSION,
};
