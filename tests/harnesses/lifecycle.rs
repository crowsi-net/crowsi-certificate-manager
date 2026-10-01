//! Durable lifecycle and reconciliation scenarios share one executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../completion_delivery_v2.rs"]
mod completion_delivery_v2;
#[path = "../completion_outbox_v2.rs"]
mod completion_outbox_v2;
#[path = "../handoff_v2.rs"]
mod handoff_v2;
#[path = "../reconciliation_resolution_v2.rs"]
mod reconciliation_resolution_v2;
#[path = "../reconciliation_security_v2.rs"]
mod reconciliation_security_v2;
#[path = "../replay_overflow_v2.rs"]
mod replay_overflow_v2;
#[path = "../state_cas_adversarial_v2.rs"]
mod state_cas_adversarial_v2;
