//! SPIKE: accountless zkmsg sends through a shared pool account.
//!
//!   facts.cairo           pure proof-facts parsing, epoch rules
//!   policy.cairo          pure fee-field policy for the signature-less pool
//!   prover.cairo          ZkmsgSendProverV4: v3 membership + quota nullifier + ticket spend
//!   pool.cairo            ZkmsgPoolV4: the store AND the account that publishes,
//!                         funded only by anonymous single-send tickets
//!   mock_strk.cairo       test-only ERC20
//!   virtual_sender.cairo  ZkmsgVirtualSenderV4: shared sender of virtual proofs
pub mod facts;
pub mod merkle;
pub mod mock_strk;
pub mod policy;
pub mod pool;
pub mod prover;
pub mod virtual_sender;
