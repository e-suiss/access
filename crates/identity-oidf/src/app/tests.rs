use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use super::*;
use crate::ports::Unreachable;
use crate::statement::configuration_url;
use crate::testkit::{Fed, HOUR, INT, LEAF, NOW, TA, rp_metadata};

struct Served(BTreeMap<String, String>);

impl Fetch for Served {
    fn fetch(
        &self,
        url: &str,
        _accept: &str,
    ) -> impl Future<Output = Result<(u16, Vec<u8>), Unreachable>> + Send {
        std::future::ready(match self.0.get(url) {
            Some(b) => Ok((200, b.clone().into_bytes())),
            None => Err(Unreachable),
        })
    }
}

fn ready<T>(f: impl Future<Output = T>) -> T {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

// IDP-19, OP-155 m.3 (j)
#[test]
fn resolution_drives_the_fetch_port() {
    let f = Fed::new();
    let exp = NOW.saturating_add(HOUR);
    let mut m = BTreeMap::new();
    m.insert(
        configuration_url(LEAF),
        f.leaf.config(&[INT], &rp_metadata(), &[]),
    );
    m.insert(
        configuration_url(INT),
        f.int.config(&[TA], &f.int.federation_metadata(), &[]),
    );
    m.insert(configuration_url(TA), f.ta_ec());
    m.insert(
        format!("{}?sub=https%3A%2F%2Frp.example", f.int.fetch_endpoint()),
        f.int.about(&f.leaf, None, exp),
    );
    m.insert(
        format!("{}?sub=https%3A%2F%2Fint.example", f.ta.fetch_endpoint()),
        f.ta.about(&f.int, None, exp),
    );
    let served = Served(m);
    let chain = ready(resolve(&served, LEAF, f.anchors(), NOW)).unwrap();
    assert_eq!(chain.anchor, TA);
    let none = Served(BTreeMap::new());
    assert_eq!(
        ready(resolve(&none, LEAF, f.anchors(), NOW)),
        Err(ChainError::Unresolved)
    );
}
