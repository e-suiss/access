//! CR-K4: `recorded_at` monotonicity of the hash chain, `access_kernel::record::check_link`
//! (TI-RT2, TI-19): a record follows another only at the next position, over its leaf, in the
//! same domain and never earlier.

use access_kernel::digest::Digest;
use access_kernel::record::{Header, LeafCore, RecordKind, check_link};

use super::digest;

/// One side of a link: position, recorded time and whether it names the expected domain.
pub(crate) type Side = (u64, u64, bool);

fn core((pos, recorded_at, ours): Side, prev: Digest) -> LeafCore {
    LeafCore {
        header: Header {
            domain: Some(if ours { digest(30) } else { digest(31) }),
            pos,
            kind: RecordKind::Decision,
            recorded_at,
            prev: Some(prev),
        },
        field_root: digest(32).0,
    }
}

/// `check_link` accepts exactly the next position over the previous leaf in the same domain at
/// the same or a later time, so an accepted chain never goes back in time.
pub(crate) fn link_is_monotone(previous: Side, next: Side, over_leaf: bool) -> bool {
    let domain = digest(30);
    let before = core(previous, digest(33));
    let Ok(leaf) = before.leaf_hash() else {
        return false;
    };
    let prev = if over_leaf { Digest(leaf) } else { digest(34) };
    let after = core(next, prev);
    let want = previous.0.checked_add(1) == Some(next.0)
        && after.header.prev == Some(Digest(leaf))
        && next.1 >= previous.1
        && previous.2
        && next.2;
    let ok = check_link(&before, &after, &domain).is_ok();
    ok == want && (!ok || after.header.recorded_at >= before.header.recorded_at)
}

#[cfg(kani)]
mod harness {
    use access_kernel::digest::Hash;
    use access_kernel::record::{LeafCore, RecordError};

    fn leaf_hash_stub(core: &LeafCore) -> Result<Hash, RecordError> {
        let p = core.header.pos.to_le_bytes();
        let t = core.header.recorded_at.to_le_bytes();
        Ok([p[0] ^ t[0] ^ 0x5a; 32])
    }

    // CR-K4, TI-RT2, TI-19
    #[kani::proof]
    #[kani::stub(access_kernel::record::LeafCore::leaf_hash, leaf_hash_stub)]
    fn k4_recorded_at_is_monotone() {
        assert!(super::link_is_monotone(
            kani::any(),
            kani::any(),
            kani::any()
        ));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::super::edge;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K4, TI-RT2, TI-19
        #[test]
        fn k4_recorded_at_is_monotone(
            p in edge(), step in 0..3u64, t1 in edge(), t2 in edge(),
            a in any::<bool>(), b in any::<bool>(), over in any::<bool>()
        ) {
            let next = p.wrapping_add(step);
            prop_assert!(super::link_is_monotone((p, t1, a), (next, t2, b), over));
        }
    }
}
