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
#[allow(clippy::while_let_loop)]
fn proxy_round_trip_hides_the_email_when_the_path_has_a_query() {
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
    let dir = std::env::temp_dir().join(format!("hushid-proxy-query-{}", std::process::id()));
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
        "POST /v1/chat/completions?stream=false HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Hushid-Session: demo\r\nConnection: close\r\n\r\n{body}",
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
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!upstream.contains("ada@example.com"), "{upstream}");
    assert!(upstream.contains("h1_email_"), "{upstream}");
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

#[test]
fn mcp_session_is_the_top_level_field() {
    let dir = std::env::temp_dir().join(format!("hushid-mcp-session-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let glossary = Glossary::empty();
    let nested = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shield","arguments":{"note":{"session":"victim"},"session":"alice","text":"ada@example.com"}}}"#,
    )
    .unwrap();
    assert!(nested.contains("h1_email_"), "{nested}");
    assert!(!nested.contains("isError"), "{nested}");
    assert!(dir.join("alice.vault").is_file(), "{nested}");
    assert!(!dir.join("victim.vault").exists(), "{nested}");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let last = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shield","arguments":{"session":"victim","text":"ada@example.com","session":"alice"}}}"#,
    )
    .unwrap();
    assert!(last.contains("h1_email_"), "{last}");
    assert!(dir.join("alice.vault").is_file(), "{last}");
    assert!(!dir.join("victim.vault").exists(), "{last}");
    let word = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shield","arguments":{"text":"session","session":"alice"}}}"#,
    )
    .unwrap();
    assert!(!word.contains("isError"), "{word}");
    assert!(word.contains("session"), "{word}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mcp_tool_text_decodes_json_escapes() {
    let dir = std::env::temp_dir().join(format!("hushid-mcp-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let glossary = Glossary::empty();
    let init = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    )
    .unwrap();
    assert!(init.contains("2024-11-05"), "{init}");

    let shielded = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"ada\u0040example.com"}}}"#,
    )
    .unwrap();
    assert!(shielded.contains("h1_email_"), "{shielded}");
    assert!(!shielded.contains("ada@example.com"), "{shielded}");
    assert!(!shielded.contains("\\u0040"), "{shielded}");
    let restored = mcp_restore(&dir, &glossary, 3, &mcp_text_content(&shielded));
    assert_eq!(mcp_text_content(&restored), "ada@example.com");

    let lined = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"ada@example.com\nnext"}}}"#,
    )
    .unwrap();
    assert!(lined.contains("h1_email_"), "{lined}");
    let token_at = lined.find("h1_email_").unwrap();
    let next_at = lined[token_at..].find("next").unwrap() + token_at;
    let between = &lined[token_at..next_at];
    assert!(between.contains('\\'), "{lined}");
    assert!(between.contains('n'), "{lined}");
    assert!(!between.contains('\n'), "{lined:?}");
    let lined_back = mcp_restore(&dir, &glossary, 5, &mcp_text_content(&lined));
    assert_eq!(
        mcp_text_content(&lined_back).replace("\\n", "\n"),
        "ada@example.com\nnext"
    );

    let tabbed = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"line\t2"}}}"#,
    )
    .unwrap();
    assert!(tabbed.contains("line\\t2"), "{tabbed}");
    assert!(!tabbed.contains('\t'), "{tabbed:?}");

    let lone = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"\uD800"}}}"#,
    )
    .unwrap();
    assert!(lone.contains("isError"), "{lone}");
    assert!(!lone.contains("h1_"), "{lone}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mcp_argument_brace_stays_in_the_string() {
    let dir = std::env::temp_dir().join(format!("hushid-mcp-brace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let glossary = Glossary::empty();
    let init = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    )
    .unwrap();
    assert!(init.contains("2024-11-05"), "{init}");
    let shielded = mcp_message(
        &dir,
        &glossary,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"hello } a@b.co"}}}"#,
    )
    .unwrap();
    assert!(shielded.contains("h1_email_"), "{shielded}");
    assert!(!shielded.contains("a@b.co"), "{shielded}");
    assert!(!shielded.contains("\"text\":\"\""), "{shielded}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn mcp_restore(dir: &std::path::Path, glossary: &Glossary, id: u32, text: &str) -> String {
    mcp_message(
        dir,
        glossary,
        &format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"restore","arguments":{{"session":"demo","text":"{text}"}}}}}}"#
        ),
    )
    .unwrap()
}

fn mcp_text_content(json: &str) -> String {
    let marker = "\"text\":\"";
    let start = json.find(marker).unwrap() + marker.len();
    let bytes = json.as_bytes();
    let mut index = start;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if bytes[index] == b'\\' {
            escaped = true;
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            return json[start..index].to_string();
        }
        index += 1;
    }
    panic!("unterminated text in {json}");
}

#[test]
#[allow(clippy::while_let_loop)]
fn proxy_returns_the_upstream_status_and_restores_the_body() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                break;
            };
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            while buf.len() < header_end + 4 + length {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
            }
            let request = std::str::from_utf8(&buf[header_end + 4..]).unwrap_or("");
            let token = request
                .split("h1_email_")
                .nth(1)
                .unwrap()
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .next()
                .unwrap();
            let body = format!(r#"{{"error":"h1_email_{token}"}}"#);
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            break;
        }
    });
    let dir = std::env::temp_dir().join(format!("hushid-proxy-429-{}", std::process::id()));
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
    assert!(response.starts_with("HTTP/1.1 429"), "{response}");
    assert!(response.contains("ada@example.com"), "{response}");
    assert!(!response.contains("h1_email_"), "{response}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[allow(clippy::while_let_loop)]
fn proxy_refuses_an_upstream_response_without_content_length() {
    let upstream_body = r#"{"completion":"not-forwarded"}"#;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                break;
            };
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if buf.len() >= header_end + 4 + length {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{upstream_body}"
        );
        let _ = stream.write_all(response.as_bytes());
    });
    let dir = std::env::temp_dir().join(format!("hushid-proxy-nolen-{}", std::process::id()));
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
    let body = r#"{"model":"local","messages":[{"role":"user","content":"hello"}]}"#;
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
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(response.contains("upstream"), "{response}");
    assert!(!response.contains(upstream_body), "{response}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[allow(clippy::while_let_loop)]
fn proxy_refuses_a_short_upstream_body() {
    let upstream_body = r#"{"choices":[{"message":{"content":"hel"#;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                break;
            };
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if buf.len() >= header_end + 4 + length {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 48\r\nConnection: close\r\n\r\n{upstream_body}"
        );
        let _ = stream.write_all(response.as_bytes());
    });
    let dir = std::env::temp_dir().join(format!("hushid-proxy-short-{}", std::process::id()));
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
    let body = r#"{"model":"local","messages":[{"role":"user","content":"hello"}]}"#;
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
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(response.contains("upstream"), "{response}");
    assert!(!response.contains("hel"), "{response}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[allow(clippy::while_let_loop)]
fn proxy_returns_a_redirect_instead_of_following_it() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                break;
            };
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"{"error":"slow"}"#;
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/v1/chat/completions\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    });
    let dir = std::env::temp_dir().join(format!("hushid-proxy-302-{}", std::process::id()));
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
    let body = r#"{"model":"local","messages":[{"role":"user","content":"hello"}]}"#;
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
    assert!(response.starts_with("HTTP/1.1 302"), "{response}");
    assert!(response.contains("slow"), "{response}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn proxy_bin() -> String {
    if let Some(path) = option_env!("CARGO_BIN_EXE_hushid_proxy") {
        return path.to_string();
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_hushid-proxy") {
        return path.to_string();
    }
    std::env::var("CARGO_BIN_EXE_hushid-proxy")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_hushid_proxy"))
        .expect("CARGO_BIN_EXE_hushid_proxy")
}

fn proxy_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new(proxy_bin());
    cmd.env_remove("HUSHID_VAULT_DIR");
    cmd.env_remove("HUSHID_GLOSSARY");
    cmd
}

fn proxy_cli_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn proxy_cli_help() {
    for flag in ["--help", "-h"] {
        let output = proxy_cmd().arg(flag).output().unwrap();
        let stdout = proxy_cli_text(&output.stdout);
        let stderr = proxy_cli_text(&output.stderr);
        assert!(
            output.status.success(),
            "{flag} code={:?} stdout={stdout} stderr={stderr}",
            output.status.code()
        );
        for name in ["--upstream", "--vault-dir", "--listen", "--glossary"] {
            assert!(stdout.contains(name), "{flag} stdout={stdout}");
        }
        assert!(!stdout.contains("missing value"), "{flag} stdout={stdout}");
        assert!(!stderr.contains("missing value"), "{flag} stderr={stderr}");
    }
}

#[test]
fn proxy_cli_unknown() {
    let output = proxy_cmd().arg("--nope").output().unwrap();
    let stderr = proxy_cli_text(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={stderr}",
        proxy_cli_text(&output.stdout)
    );
    assert!(stderr.contains("unknown argument --nope"), "{stderr}");
    assert!(stderr.contains("--upstream"), "{stderr}");
}

#[test]
fn proxy_cli_missing_glossary() {
    let dir =
        std::env::temp_dir().join(format!("hushid-proxy-cli-glossary-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("missing-glossary.txt");
    let _ = std::fs::remove_file(&missing);
    let output = proxy_cmd()
        .arg("--upstream")
        .arg("http://127.0.0.1:9")
        .arg("--vault-dir")
        .arg(&dir)
        .arg("--glossary")
        .arg(&missing)
        .output()
        .unwrap();
    let stderr = proxy_cli_text(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={stderr}",
        proxy_cli_text(&output.stdout)
    );
    assert!(stderr.contains(&missing.display().to_string()), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn proxy_cli_bad_listen() {
    let dir = std::env::temp_dir().join(format!("hushid-proxy-cli-listen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = proxy_cmd()
        .arg("--listen")
        .arg("not-a-socket")
        .arg("--upstream")
        .arg("http://127.0.0.1:9")
        .arg("--vault-dir")
        .arg(&dir)
        .output()
        .unwrap();
    let stderr = proxy_cli_text(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={stderr}",
        proxy_cli_text(&output.stdout)
    );
    assert!(stderr.contains("not-a-socket"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
