use std::io::Write;
use std::process::{Command, Stdio};

fn exe(name: &str) -> std::path::PathBuf {
    // Cargo's unused-dependency compile does not set CARGO_BIN_EXE_*.
    let (from_cargo, file) = if name == "mcp" {
        (option_env!("CARGO_BIN_EXE_hushid_mcp"), "hushid-mcp")
    } else {
        (option_env!("CARGO_BIN_EXE_hushid_proxy"), "hushid-proxy")
    };
    if let Some(path) = from_cargo.map(std::path::PathBuf::from) {
        if path.is_file() {
            return path;
        }
    }
    let mut dir = std::env::current_exe().unwrap();
    loop {
        let candidate = dir.join(file);
        if candidate.is_file() {
            return candidate;
        }
        if !dir.pop() {
            break;
        }
    }
    panic!("missing {file} binary");
}

fn frame(message: &str) -> Vec<u8> {
    let mut bytes = format!("Content-Length: {}\r\n\r\n", message.len()).into_bytes();
    bytes.extend(message.as_bytes());
    bytes
}

fn mcp(
    dir: Option<&std::path::Path>,
    glossary: Option<&std::path::Path>,
    stdin: &[u8],
) -> std::process::Output {
    let mut command = Command::new(exe("mcp"));
    command
        .env_remove("HUSHID_VAULT_DIR")
        .env_remove("HUSHID_GLOSSARY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = dir {
        command.env("HUSHID_VAULT_DIR", dir);
    }
    if let Some(glossary) = glossary {
        command.env("HUSHID_GLOSSARY", glossary);
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn the_mcp_binary_frames_a_call_and_stops_on_a_bad_header() {
    let missing = mcp(None, None, b"");
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("HUSHID_VAULT_DIR"));

    let dir = std::env::temp_dir().join(format!("hushid-mcp-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let glossary = dir.join("names.txt");
    std::fs::write(&glossary, "Nadine\n").unwrap();
    let missing_file = dir.join("missing.txt");
    let bad_glossary = mcp(Some(&dir), Some(&missing_file), b"");
    assert_eq!(bad_glossary.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad_glossary.stderr).contains("glossary"),
        "{:?}",
        bad_glossary.stderr
    );

    let quiet = mcp(Some(&dir), Some(&glossary), b"");
    assert_eq!(quiet.status.code(), Some(0), "{:?}", quiet.stderr);

    let mut stdin = frame(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    stdin.extend(frame(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"Nadine"}}}"#,
    ));
    let called = mcp(Some(&dir), Some(&glossary), &stdin);
    assert_eq!(called.status.code(), Some(0), "{:?}", called.stderr);
    let stdout = String::from_utf8_lossy(&called.stdout);
    assert!(stdout.contains("Content-Length:"), "{stdout}");
    assert!(!stdout.contains("Nadine"), "{stdout}");
    assert!(stdout.contains("h1_glossary_"), "{stdout}");

    let mut long = vec![b'A'; 1100];
    long.extend(b"\r\n\r\n");
    for stdin in [
        long.as_slice(),
        b"\xff\r\n\r\n".as_slice(),
        b"Content-Length: no\r\n\r\n".as_slice(),
        b"Content-Length: 10\r\n\r\nab".as_slice(),
        b"Content-Length: 1\r\n\r\n\xff".as_slice(),
        b"\r\n\r\n".as_slice(),
        b"Content-Length: 1048577\r\n\r\n".as_slice(),
    ] {
        let output = mcp(Some(&dir), None, stdin);
        assert_eq!(output.status.code(), Some(1), "{stdin:?} {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("frame"),
            "{stdin:?} {:?}",
            output.stderr
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_proxy_binary_names_a_missing_flag() {
    let mut command = Command::new(exe("proxy"));
    command
        .env_remove("HUSHID_VAULT_DIR")
        .env_remove("HUSHID_GLOSSARY")
        .arg("--help");
    let help = command.output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("--upstream"));

    for arg in ["--listen", "--upstream", "--vault-dir", "--glossary"] {
        let output = Command::new(exe("proxy"))
            .env_remove("HUSHID_VAULT_DIR")
            .env_remove("HUSHID_GLOSSARY")
            .arg(arg)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arg}");
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(err.contains("missing value"), "{arg} {err}");
    }
    let unknown = Command::new(exe("proxy"))
        .env_remove("HUSHID_VAULT_DIR")
        .arg("--nope")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown argument"));
    let no_upstream = Command::new(exe("proxy"))
        .env_remove("HUSHID_VAULT_DIR")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&no_upstream.stderr).contains("missing --upstream"));
    let no_vault = Command::new(exe("proxy"))
        .env_remove("HUSHID_VAULT_DIR")
        .args(["--upstream", "http://127.0.0.1:9"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&no_vault.stderr).contains("missing --vault-dir"));
    let glossary =
        std::env::temp_dir().join(format!("hushid-missing-glossary-{}", std::process::id()));
    let bad_glossary = Command::new(exe("proxy"))
        .env_remove("HUSHID_VAULT_DIR")
        .args([
            "--upstream",
            "http://127.0.0.1:9",
            "--vault-dir",
            "/tmp",
            "--glossary",
        ])
        .arg(&glossary)
        .output()
        .unwrap();
    assert_eq!(bad_glossary.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_glossary.stderr).contains("glossary"));
    let listen = Command::new(exe("proxy"))
        .env_remove("HUSHID_VAULT_DIR")
        .args([
            "--upstream",
            "http://127.0.0.1:9",
            "--vault-dir",
            "/tmp",
            "--listen",
            "not-an-address",
        ])
        .output()
        .unwrap();
    assert_eq!(listen.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&listen.stderr).contains("listen"));
}

#[test]
fn a_closed_stdout_stops_the_mcp_process() {
    let dir = std::env::temp_dir().join(format!("hushid-mcp-closed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut child = Command::new(exe("mcp"))
        .env("HUSHID_VAULT_DIR", &dir)
        .env_remove("HUSHID_GLOSSARY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"ada@example.com"}}}"#,
        ))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{:?}", output.status);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("client"),
        "{:?}",
        output.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_proxy_exits_when_the_client_drops() {
    let dir = std::env::temp_dir().join(format!("hushid-proxy-drop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let glossary = dir.join("names.txt");
    std::fs::write(&glossary, "Nadine\n").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let child = Command::new(exe("proxy"))
        .env_remove("HUSHID_VAULT_DIR")
        .env_remove("HUSHID_GLOSSARY")
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--upstream",
            "http://127.0.0.1:9",
            "--vault-dir",
        ])
        .arg(&dir)
        .arg("--glossary")
        .arg(&glossary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(connected) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            stream = Some(connected);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let stream = stream.expect("proxy did not accept");
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let output = child.wait_with_output().unwrap();
    drop(stream);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
