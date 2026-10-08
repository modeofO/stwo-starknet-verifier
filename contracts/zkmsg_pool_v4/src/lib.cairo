//! SPIKE: accountless zkmsg sends through a shared pool account.
//!
//!   facts.cairo           pure proof-facts parsing, epoch rules
//!   policy.cairo          pure fee-field policy for the signature-less pool
//!   prover.cairo          ZkmsgSendProverV4: v3 membership + rate-limit nullifier
//!   pool.cairo            ZkmsgPoolV4: the store AND the account that publishes
//!   virtual_sender.cairo  ZkmsgVirtualSenderV4: shared sender of virtual proofs
pub mod facts;
pub mod merkle;
pub mod policy;
pub mod pool;
pub mod prover;
pub mod virtual_sender;
