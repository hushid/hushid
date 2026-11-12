use hushid::Glossary;
use hushid::Vault;
use hushid_proxy::{mcp_message, restore_chat, shield_chat, Proxy};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn base_vault() -> Vault {
    Vault::new()
}

#[test]
fn chat_json_shields_and_restores() {
    let mut vault = base_vault();
    let body = r#"{"messages":[{"role":"user","content":"ada@example.com"}]}"#;
    let shielded = shield_chat(body, &mut vault, &Glossary::empty()).unwrap();
    assert!(!shielded.contains("ada@example.com"), "{shielded}");
    assert!(shielded.contains("h1_email_"), "{shielded}");
    let restored = restore_chat(&shielded, &vault).unwrap();
    assert_eq!(restored, body);
}

#[test]
#[allow(clippy::while_let_loop)]
fn proxy_round_trip_hides_the_email_from_upstream() {
    let upstream_body = br#"{"choices":[{"message":{"content":"TOKEN"}}]}"#;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_body = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                break;
            };
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                let header_end = buf
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap();
                let header = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + 4 + length {
                    let read = stream.read(&mut chunk).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..read]);
                }
                let body = &buf[header_end + 4..header_end + 4 + length];
                *seen_body.lock().unwrap() = body.to_vec();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    upstream_body.len(),
                    std::str::from_utf8(upstream_body).unwrap()
                );
                let _ = stream.write_all(response.as_bytes());
                break;
            }
        }
    });
    let dir = std::env::temp_dir().join(format!("hushid-proxy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let proxy = Proxy::bind(
        "127.0.0.1:0",
        &format!("http://127.0.0.1:{port}"),
        &dir,
        Glossary::empty(),
    )
    .unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _ = proxy.serve_one();
    });
    let body = r#"{"model":"local","messages":[{"role":"user","content":"ada@example.com"}]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Hushid-Session: demo\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let upstream = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
    assert!(!upstream.contains("ada@example.com"), "{upstream}");
    assert!(upstream.contains("h1_email_"), "{upstream}");
    assert!(response.contains("TOKEN"), "{response}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mcp_shield_and_restore() {
    let dir = std::env::temp_dir().join(format!("hushid-mcp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let glossary = Glossary::empty();
    let init = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    )
    .unwrap();
    assert!(init.contains("2024-11-05"), "{init}");
    let call = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"ada@example.com"}}}"#,
    )
    .unwrap();
    assert!(call.contains("h1_email_"), "{call}");
    assert!(!call.contains("ada@example.com"), "{call}");
    let token = call
        .split("h1_email_")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let token = format!("h1_email_{token}");
    let restore = mcp_message(
        &dir,
        &glossary,
        &format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"restore","arguments":{{"session":"demo","text":"{token}"}}}}}}"#
        ),
    )
    .unwrap();
    assert!(restore.contains("ada@example.com"), "{restore}");
    let _ = std::fs::remove_dir_all(&dir);
}
