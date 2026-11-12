//! The attacker regression suites on the real server path (SA-T12, SA-8, §14.3 AS-16…AS-19,
//! OP-159 m.3 (gg)), the local equivalent of the external red team: each suite replays what a
//! red team tries against one surface through the real routers on real PostgreSQL, the
//! sequencer and `SoftHSM`. AS-16 (XML signature wrapping) runs in the parser worker's XSW
//! corpus and its real-process run under the Linux lockdown; AS-17 (LDAP injection) runs against
//! the gateway and the real edge router in `bins/access-gw-ldap/tests/redteam.rs`.

use super::*;

#[path = "redteam/enumeration.rs"]
mod enumeration;
#[path = "redteam/scim.rs"]
mod scim;
