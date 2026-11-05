//! Authorization at the PEP (§9.5, K08, K11): asking the decision point for one intent, checking
//! the signed receipt of an ALLOW against the intent and the PEP's own identity (L2-RCP-3), and
//! handing the effect an `Authorized` value that exists only after that check.
