//! Certificate, execution, and schema contracts share one executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../authority_execution_time_v2.rs"]
mod authority_execution_time_v2;
#[path = "../certificate_signature_v2.rs"]
mod certificate_signature_v2;
#[path = "../contract_conformance.rs"]
mod contract_conformance;
#[path = "../debug_redaction_v2.rs"]
mod debug_redaction_v2;
#[path = "../execution_authorization_v2.rs"]
mod execution_authorization_v2;
#[path = "../execution_configuration_v2.rs"]
mod execution_configuration_v2;
#[path = "../execution_integrity_v2.rs"]
mod execution_integrity_v2;
#[path = "../execution_success_v2.rs"]
mod execution_success_v2;
#[path = "../resource_normalization_v2.rs"]
mod resource_normalization_v2;
#[path = "../schema_documents.rs"]
mod schema_documents;
#[path = "../schema_projections.rs"]
mod schema_projections;
#[path = "../status_v2.rs"]
mod status_v2;
