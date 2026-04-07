//! Structured drill events for cluster-native shinryū consumption.
//!
//! Events are emitted as JSON-lines to stderr. Vector picks them up via the
//! `kubernetes_logs` source and ships them to shinryū, indexed by `drill_id`.
//!
//! This module is **additive** — the existing local-mode drill commands
//! (`drill`, `drill-full`, `drill-rds`) continue to work without emitting
//! events. Cluster-native drills construct an [`EventContext`] at startup
//! and call [`emit`] at every state transition; phase functions and gate
//! checks accept an optional context so the same code paths serve both
//! modes.
//!
//! The envelope shape is intentionally flat — every field is queryable in
//! shinryū without nested-object traversal. The `event` discriminator field
//! identifies the variant; the rest of the variant's fields are flattened
//! alongside it.

#![allow(clippy::module_name_repetitions)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Event schema version. Bumped on incompatible payload changes.
pub const EVENT_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Discriminator types
// ---------------------------------------------------------------------------

/// Phase identifier in the 8-phase PITR drill lifecycle.
///
/// Mirrors the phases driven by `phases.rs` so events from any phase can be
/// joined back to its phase boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preconditions,
    Setup,
    Trigger,
    Restore,
    Verification,
    Extraction,
    Teardown,
    Report,
}

/// Drill verdict — the final outcome of a drill run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
}

/// Drill mode — sentinel canary drill or real recovery.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Drill,
    Recovery,
}

// ---------------------------------------------------------------------------
// Context — held for the lifetime of a drill run
// ---------------------------------------------------------------------------

/// Common drill identity carried on every emitted event.
///
/// Constructed once at drill start and threaded through phase and gate
/// functions. The `drill_id` is the join key for shinryū queries: every
/// event for a single drill carries the same value, and downstream
/// consumers reconstruct the run by filtering on it.
///
/// Optionally carries an `events_file_path` — when set, [`emit`] appends
/// each event to that file in JSON-lines format in addition to writing
/// to stderr. This is how the tarball assembler captures `events.ndjson`
/// for compliance archival, separate from the Vector→shinryū stream.
#[derive(Debug, Clone)]
pub struct EventContext {
    pub drill_id: String,
    pub tenant: String,
    pub cloud: String,
    pub environment: String,
    pub events_file_path: Option<PathBuf>,
}

impl EventContext {
    /// Construct a new context with a freshly generated `drill_id`.
    ///
    /// The `drill_id` format is `{tenant}-{cloud_lowercase}-{environment}-{utc_timestamp}`,
    /// where the timestamp is `YYYYMMDDTHHMMSSZ`. This is unique per second
    /// per tenant/cloud/env combination — sufficient for quarterly drill
    /// cadence and trivially sortable.
    #[must_use]
    pub fn new(tenant: String, cloud: String, environment: String) -> Self {
        let drill_id = format!(
            "{}-{}-{}-{}",
            tenant,
            cloud.to_lowercase(),
            environment,
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        );
        Self {
            drill_id,
            tenant,
            cloud,
            environment,
            events_file_path: None,
        }
    }

    /// Builder: attach an `events.ndjson` capture file.
    ///
    /// When set, [`emit`] appends each event to the given path in addition
    /// to writing it to stderr. The cluster-mode entry point uses this to
    /// capture the event stream for inclusion in the drill tarball.
    #[must_use]
    pub fn with_events_file_path(mut self, path: PathBuf) -> Self {
        self.events_file_path = Some(path);
        self
    }
}

// ---------------------------------------------------------------------------
// Event envelope and payload variants
// ---------------------------------------------------------------------------

/// Common envelope wrapping every emitted event.
///
/// Carries the join-key fields (`drill_id`, `tenant`, `cloud`, `environment`)
/// plus a `schema_version`, `timestamp`, and the typed event payload. The
/// event variant is flattened so all variant fields appear at the top level
/// of the JSON object alongside the envelope fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: &'static str,
    pub timestamp: String,
    pub drill_id: String,
    pub tenant: String,
    pub cloud: String,
    pub environment: String,
    #[serde(flatten)]
    pub event: DrillEvent,
}

/// Drill lifecycle events.
///
/// Each variant represents a meaningful state transition during a drill run.
/// Variants are tagged with the `event` discriminator field for downstream
/// consumers (Vector → shinryū queries → report assembler).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DrillEvent {
    /// A drill run has started. Emitted exactly once at the very beginning.
    DrillStarted {
        mode: Mode,
        restore_time: String,
        app_version: String,
        terraform_path: String,
    },

    /// A phase has begun executing.
    PhaseStarted { phase: Phase },

    /// A phase has finished executing. Carries the phase duration and the
    /// pass/fail outcome of any gates checked within the phase.
    PhaseCompleted {
        phase: Phase,
        duration_ms: u64,
        passed: bool,
    },

    /// A gate check has been evaluated.
    GateChecked {
        phase: Phase,
        gate: String,
        passed: bool,
        message: String,
        expected: String,
        actual: String,
    },

    /// The canary secret was created in the live Akeyless environment.
    CanaryCreated { secret_path: String },

    /// The canary secret was deleted, simulating data loss.
    CanaryDeleted { secret_path: String },

    /// The canary secret was verified in the restored environment.
    CanaryVerified {
        secret_path: String,
        found: bool,
        gateway_url: String,
    },

    /// A terraform resource change was observed during apply or destroy.
    TerraformResourceChange {
        phase: Phase,
        action: String,
        resource_type: String,
        resource_address: String,
    },

    /// The drill run completed (passed or failed).
    DrillCompleted {
        verdict: Verdict,
        total_duration_ms: u64,
        measured_rto_secs: u64,
    },

    /// The drill run failed mid-flight with an error.
    DrillFailed { phase: Phase, error: String },
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

/// Emit a single event as a JSON-line on stderr.
///
/// Vector's `kubernetes_logs` source captures stderr output from the drill
/// container and ships it to shinryū. Each event is a single line of JSON
/// so Vector can parse it as a structured event.
///
/// If `ctx.events_file_path` is `Some`, the same line is also appended to
/// that file (opened in `create + append` mode each call). This is how the
/// tarball assembler captures `events.ndjson` for compliance archival.
///
/// Failures (serialization, file I/O) are silently dropped — emit must
/// never fail the drill itself. Worst case, an event is lost but the
/// drill continues and the sidecar `DrillResult` JSON in the tarball
/// still captures the outcome.
pub fn emit(ctx: &EventContext, event: DrillEvent) {
    let envelope = EventEnvelope {
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: chrono::Utc::now().to_rfc3339(),
        drill_id: ctx.drill_id.clone(),
        tenant: ctx.tenant.clone(),
        cloud: ctx.cloud.clone(),
        environment: ctx.environment.clone(),
        event,
    };
    if let Ok(line) = serde_json::to_string(&envelope) {
        eprintln!("{line}");
        if let Some(path) = &ctx.events_file_path {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                use std::io::Write;
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drill_id_is_constructed_from_components() {
        let ctx = EventContext::new(
            "cvs".to_string(),
            "GCP".to_string(),
            "production".to_string(),
        );
        assert!(ctx.drill_id.starts_with("cvs-gcp-production-"));
        // 16 chars after the prefix: YYYYMMDDTHHMMSSZ
        let suffix = &ctx.drill_id["cvs-gcp-production-".len()..];
        assert_eq!(suffix.len(), 16);
        assert!(suffix.contains('T'));
        assert!(suffix.ends_with('Z'));
    }

    #[test]
    fn envelope_serializes_with_flattened_event_tag() {
        let ctx = EventContext::new(
            "mte".to_string(),
            "AWS".to_string(),
            "staging".to_string(),
        );
        let envelope = EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            drill_id: ctx.drill_id.clone(),
            tenant: ctx.tenant.clone(),
            cloud: ctx.cloud.clone(),
            environment: ctx.environment.clone(),
            event: DrillEvent::PhaseStarted {
                phase: Phase::Preconditions,
            },
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"event\":\"phase_started\""));
        assert!(json.contains("\"phase\":\"preconditions\""));
        assert!(json.contains("\"schema_version\":\"1.0.0\""));
        assert!(json.contains("\"tenant\":\"mte\""));
    }

    #[test]
    fn emit_appends_to_events_file_when_path_set() {
        let path = std::env::temp_dir().join(format!(
            "pitr-forge-events-test-{}.ndjson",
            chrono::Utc::now().timestamp_micros()
        ));
        let _ = std::fs::remove_file(&path);

        let ctx = EventContext::new(
            "cvs".to_string(),
            "GCP".to_string(),
            "production".to_string(),
        )
        .with_events_file_path(path.clone());

        emit(&ctx, DrillEvent::PhaseStarted { phase: Phase::Preconditions });
        emit(&ctx, DrillEvent::PhaseCompleted {
            phase: Phase::Preconditions,
            duration_ms: 1234,
            passed: true,
        });

        let contents = std::fs::read_to_string(&path).expect("events file should exist");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected two lines in events file");
        assert!(lines[0].contains("\"event\":\"phase_started\""));
        assert!(lines[1].contains("\"event\":\"phase_completed\""));
        assert!(lines[1].contains("\"duration_ms\":1234"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drill_completed_event_carries_verdict_and_rto() {
        let envelope = EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            drill_id: "test".to_string(),
            tenant: "cvs".to_string(),
            cloud: "GCP".to_string(),
            environment: "production".to_string(),
            event: DrillEvent::DrillCompleted {
                verdict: Verdict::Pass,
                total_duration_ms: 670_024,
                measured_rto_secs: 594,
            },
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"event\":\"drill_completed\""));
        assert!(json.contains("\"verdict\":\"pass\""));
        assert!(json.contains("\"measured_rto_secs\":594"));
    }
}
