#![cfg(windows)]
//! `localhost` on this host is an IPv6 loopback first. A client that
//! uses 127.0.0.1 must still get an answer.

use hushid::Glossary;
use hushid_proxy::Proxy;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

#[test]
fn localhost_answers_ipv4_and_ipv6_loopback() {
    let dir = std::env::temp_dir().join(format!("hushid-proxy-localhost-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let proxy = Proxy::bind("localhost:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
    let port = proxy.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _ = proxy.serve_one();
        let _ = proxy.serve_one();
    });
    for addr in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ] {
        let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .unwrap_or_else(|err| panic!("{addr} did not connect: {err}"));
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.contains("missing session"), "{addr} {response}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
