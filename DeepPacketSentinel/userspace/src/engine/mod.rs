pub mod normalization;
pub mod policy;
pub mod protocol;
pub mod kronos_sender;
// pub mod flow; // flow might be deprecated if we use ProtocolEngine directly, but I'll keep it commented or remove it if not used.
// The prompt says "The userspace architecture separates concerns: a blocking worker thread ... while an async Tokio task consumes the Ring Buffer".
// The new plan uses new engines. I'll just expose new modules.
