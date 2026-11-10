use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn server(bytes: &[u8]) -> Vec<ServerOp> {
    let mut p = Parser::new();
    p.feed(bytes).unwrap();
    let mut out = Vec::new();
    while let Some(op) = p.server_op().unwrap() {
        out.push(op);
    }
    out
}

#[test]
fn server_operations_parse_across_split_reads() {
    let wire = b"INFO {\"headers\":true}\r\nPING\r\nMSG a.b 1 _INBOX.x.1 5\r\nhello\r\nHMSG a.c 2 20 22\r\nNATS/1.0\r\nX-A: b\r\n\r\nhi\r\n+OK\r\n-ERR 'Authorization Violation'\r\n";
    let mut p = Parser::new();
    let mut ops = Vec::new();
    for chunk in wire.chunks(3) {
        p.feed(chunk).unwrap();
        while let Some(op) = p.server_op().unwrap() {
            ops.push(op);
        }
    }
    assert_eq!(ops, server(wire));
    assert_eq!(ops.len(), 6);
    assert_eq!(ops[0], ServerOp::Info(String::from("{\"headers\":true}")));
    assert_eq!(ops[1], ServerOp::Ping);
    let ServerOp::Msg(m) = &ops[2] else { panic!() };
    assert_eq!((m.subject.as_str(), m.sid.as_str()), ("a.b", "1"));
    assert_eq!(m.reply.as_deref(), Some("_INBOX.x.1"));
    assert_eq!(m.payload, b"hello");
    let ServerOp::Msg(h) = &ops[3] else { panic!() };
    assert_eq!(h.header("x-a").as_deref(), Some("b"));
    assert_eq!(h.payload, b"hi");
    assert_eq!(
        ops[5],
        ServerOp::Err(String::from("Authorization Violation"))
    );
}

#[test]
fn a_no_responders_status_is_read() {
    let ops = server(b"HMSG _INBOX.x.1 1 16 16\r\nNATS/1.0 503\r\n\r\n\r\n");
    let ServerOp::Msg(m) = &ops[0] else { panic!() };
    assert_eq!(m.status(), Some(503));
}

#[test]
fn bad_input_is_refused() {
    for bad in [
        b"NOPE\r\n".as_slice(),
        b"MSG a 1 x\r\n",
        b"MSG a 1 3\r\nabcd\r\n",
        b"HMSG a 1 9 3\r\nabc\r\n",
    ] {
        let mut p = Parser::new();
        p.feed(bad).unwrap();
        assert!(p.server_op().is_err(), "{bad:?}");
    }
    let mut p = Parser::new();
    assert!(p.feed(&vec![b'a'; MAX_LINE + MAX_PAYLOAD + 8]).is_err());
    let mut p = Parser::new();
    p.feed(&vec![b'a'; MAX_LINE + 1]).unwrap();
    assert!(p.server_op().is_err());
}

#[test]
fn publish_writes_pub_and_hpub() {
    assert_eq!(
        publish("a.b", None, &[], b"xy").unwrap(),
        b"PUB a.b 2\r\nxy\r\n"
    );
    let h = publish("a.b", Some("_INBOX.i.1"), &[("Nats-Msg-Id", "ab")], b"xy").unwrap();
    assert_eq!(
        h,
        b"HPUB a.b _INBOX.i.1 29 31\r\nNATS/1.0\r\nNats-Msg-Id: ab\r\n\r\nxy\r\n"
    );
    let mut p = Parser::new();
    p.feed(&h).unwrap();
    let Some(ClientOp::Pub(m)) = p.client_op().unwrap() else {
        panic!()
    };
    assert_eq!(m.header("nats-msg-id").as_deref(), Some("ab"));
    assert_eq!(m.reply.as_deref(), Some("_INBOX.i.1"));
    assert_eq!(m.payload, b"xy");
}

#[test]
fn publish_refuses_what_would_break_the_frame() {
    assert!(publish("a b", None, &[], b"").is_err());
    assert!(publish("a..b", None, &[], b"").is_err());
    assert!(publish("a.>.b", None, &[], b"").is_err());
    assert!(publish("a", None, &[("X", "a\r\nb")], b"").is_err());
    assert!(publish("a", None, &[("X:Y", "a")], b"").is_err());
    assert!(publish("a", None, &[], &vec![0; MAX_PAYLOAD + 1]).is_err());
    assert!(sub("a.*", "1").is_ok() && sub("a.>", "1").is_ok() && sub("a b", "1").is_err());
}

#[test]
fn filters_match_by_token() {
    assert!(matches("access.doorbell.*", "access.doorbell.3"));
    assert!(!matches("access.doorbell.*", "access.doorbell.3.x"));
    assert!(matches("access.>", "access.doorbell.3.x"));
    assert!(!matches("access.>", "access"));
    assert!(!matches("a.b", "a.c"));
}

#[test]
fn delivered_messages_read_back() {
    let m = Message {
        subject: String::from("s.1"),
        sid: String::from("7"),
        reply: Some(String::from("r")),
        headers: Some(b"NATS/1.0\r\nA: b\r\n\r\n".to_vec()),
        payload: b"p".to_vec(),
    };
    assert_eq!(server(&deliver(&m)), vec![ServerOp::Msg(m.clone())]);
    let plain = Message { headers: None, ..m };
    assert_eq!(server(&deliver(&plain)), vec![ServerOp::Msg(plain)]);
}
