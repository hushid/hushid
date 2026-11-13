//! OpenAI-compatible chat proxy and a small MCP server.
//!
//! The session id arrives on `X-Hushid-Session`. Message strings use the
//! same vault rules as the library. The clear request is not written beside
//! the vault file. The upstream may be `http` or `https`. A URL with no
//! port uses 80 or 443. A query string stays on the chat path, and a
//! fragment is dropped. The upstream status is returned with a restored
//! body. A redirect is not followed.

use hushid::{Glossary, JsonError, Vault};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const SESSION_HEADER: &str = "x-hushid-session";
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug)]
pub enum ProxyError {
    Session,
    Body,
    Upstream,
    Vault(hushid::VaultError),
    Json(JsonError),
}

pub fn shield_chat(
    body: &str,
    vault: &mut Vault,
    glossary: &Glossary,
) -> Result<String, JsonError> {
    let (out, _) = hushid::shield_json_strings(vault, glossary, body)?;
    Ok(out)
}

pub fn restore_chat(body: &str, vault: &Vault) -> Result<String, JsonError> {
    hushid::restore_json_write(vault, body)
}

pub fn session_path(dir: &Path, session: &str) -> Option<PathBuf> {
    if session.is_empty()
        || session.len() > 64
        || !session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    Some(dir.join(format!("{session}.vault")))
}

pub fn load_session(dir: &Path, session: &str) -> Result<Vault, ProxyError> {
    let path = session_path(dir, session).ok_or(ProxyError::Session)?;
    if !path.exists() {
        return Ok(Vault::new());
    }
    Vault::load(&path).map_err(ProxyError::Vault)
}

pub fn save_session(dir: &Path, session: &str, vault: &Vault) -> Result<(), ProxyError> {
    let path = session_path(dir, session).ok_or(ProxyError::Session)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| ProxyError::Vault(hushid::VaultError::Io(err)))?;
    }
    vault.save(&path).map_err(ProxyError::Vault)
}

pub struct Proxy {
    listener: TcpListener,
    upstream: String,
    vault_dir: PathBuf,
    glossary: Glossary,
}

impl Proxy {
    pub fn bind(
        listen: &str,
        upstream: &str,
        vault_dir: &Path,
        glossary: Glossary,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(listen)?;
        Ok(Self {
            listener,
            upstream: upstream.to_string(),
            vault_dir: vault_dir.to_path_buf(),
            glossary,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_one(&self) -> Result<(), ProxyError> {
        let (mut stream, _) = self.listener.accept().map_err(|_| ProxyError::Upstream)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| ProxyError::Upstream)?;
        let request = read_http(&mut stream).map_err(|_| ProxyError::Body)?;
        let response = self.handle(&request);
        stream
            .write_all(response.as_bytes())
            .map_err(|_| ProxyError::Upstream)?;
        Ok(())
    }

    fn handle(&self, request: &HttpRequest) -> String {
        if request.method != "POST" || request.path != "/v1/chat/completions" {
            return http_response(404, br#"{"error":"not found"}"#);
        }
        let Some(session) = request.header(SESSION_HEADER) else {
            return http_response(400, br#"{"error":"missing session"}"#);
        };
        let Ok(mut vault) = load_session(&self.vault_dir, session) else {
            return http_response(400, br#"{"error":"bad session"}"#);
        };
        let Ok(body) = std::str::from_utf8(&request.body) else {
            return http_response(400, br#"{"error":"body"}"#);
        };
        let Ok(shielded) = shield_chat(body, &mut vault, &self.glossary) else {
            return http_response(400, br#"{"error":"body"}"#);
        };
        if save_session(&self.vault_dir, session, &vault).is_err() {
            return http_response(500, br#"{"error":"vault"}"#);
        }
        let upstream = match forward(&self.upstream, &shielded, request.header("authorization")) {
            Ok(reply) => reply,
            Err(_) => return http_response(502, br#"{"error":"upstream"}"#),
        };
        let restored = match std::str::from_utf8(&upstream.body) {
            Ok(text) => restore_chat(text, &vault).unwrap_or_else(|_| text.to_string()),
            Err(_) => String::from_utf8_lossy(&upstream.body).into_owned(),
        };
        http_response(upstream.status, restored.as_bytes())
    }
}

pub struct UpstreamReply {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn forward(
    upstream: &str,
    body: &str,
    authorization: Option<&str>,
) -> Result<UpstreamReply, ProxyError> {
    let url = completions_url(upstream)?;
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(ProxyError::Upstream);
    };
    let (hostport, path) = rest.split_once('/').ok_or(ProxyError::Upstream)?;
    let path = format!("/{path}");
    let stream = TcpStream::connect(hostport).map_err(|_| ProxyError::Upstream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ProxyError::Upstream)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ProxyError::Upstream)?;
    if https {
        let name = tls_dns_name(hostport)?;
        let connector = native_tls::TlsConnector::new().map_err(|_| ProxyError::Upstream)?;
        let mut stream = connector
            .connect(&name, stream)
            .map_err(|_| ProxyError::Upstream)?;
        exchange(&mut stream, &path, hostport, body, authorization)
    } else {
        let mut stream = stream;
        exchange(&mut stream, &path, hostport, body, authorization)
    }
}

fn exchange(
    stream: &mut (impl Read + Write),
    path: &str,
    hostport: &str,
    body: &str,
    authorization: Option<&str>,
) -> Result<UpstreamReply, ProxyError> {
    let mut headers = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(authorization) = authorization {
        headers.push_str("Authorization: ");
        headers.push_str(authorization);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    stream
        .write_all(headers.as_bytes())
        .map_err(|_| ProxyError::Upstream)?;
    stream
        .write_all(body.as_bytes())
        .map_err(|_| ProxyError::Upstream)?;
    let response = read_http(stream).map_err(|_| ProxyError::Upstream)?;
    if response.status == 0 {
        return Err(ProxyError::Upstream);
    }
    Ok(UpstreamReply {
        status: response.status,
        body: response.body,
    })
}

fn tls_dns_name(hostport: &str) -> Result<String, ProxyError> {
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split_once("]:")
            .map(|(host, _)| host)
            .unwrap_or(rest.trim_end_matches(']'))
    } else {
        hostport
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(hostport)
    };
    let host = host.rsplit_once('@').map(|(_, host)| host).unwrap_or(host);
    if host.is_empty() {
        return Err(ProxyError::Upstream);
    }
    Ok(host.to_string())
}

pub(crate) fn completions_url(upstream: &str) -> Result<String, ProxyError> {
    let (scheme, rest, default_port) = if let Some(rest) = upstream.strip_prefix("https://") {
        ("https", rest, 443)
    } else if let Some(rest) = upstream.strip_prefix("http://") {
        ("http", rest, 80)
    } else {
        return Err(ProxyError::Upstream);
    };
    if rest.is_empty() || rest.starts_with('/') {
        return Err(ProxyError::Upstream);
    }
    let (rest, query) = split_query(rest);
    if rest.is_empty() || rest.starts_with('/') {
        return Err(ProxyError::Upstream);
    }
    let (hostport, prefix) = match rest.split_once('/') {
        Some((host, path)) => (host, path),
        None => (rest, ""),
    };
    let hostport = host_with_port(hostport, default_port)?;
    let mut url = format!("{scheme}://{hostport}{}", chat_path(prefix));
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    Ok(url)
}

fn split_query(rest: &str) -> (&str, Option<&str>) {
    let without_fragment = rest.split('#').next().unwrap_or(rest);
    match without_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (without_fragment, None),
    }
}

fn host_with_port(hostport: &str, default_port: u16) -> Result<String, ProxyError> {
    if hostport.is_empty() {
        return Err(ProxyError::Upstream);
    }
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((host, port)) = rest.rsplit_once("]:") {
            parse_port(port)?;
            return Ok(format!("[{host}]:{port}"));
        }
        let host = rest.trim_end_matches(']');
        if host.is_empty() {
            return Err(ProxyError::Upstream);
        }
        return Ok(format!("[{host}]:{default_port}"));
    }
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if !host.is_empty() && parse_port(port).is_ok() {
            return Ok(hostport.to_string());
        }
    }
    Ok(format!("{hostport}:{default_port}"))
}

fn parse_port(port: &str) -> Result<u16, ProxyError> {
    port.parse().map_err(|_| ProxyError::Upstream)
}

fn chat_path(prefix: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        return "/v1/chat/completions".to_string();
    }
    let path = format!("/{prefix}");
    let path = path.trim_end_matches('/');
    if path.ends_with("/v1/chat/completions") {
        return path.to_string();
    }
    if path.ends_with("/v1") {
        return format!("{path}/chat/completions");
    }
    format!("{path}/v1/chat/completions")
}

struct HttpRequest {
    method: String,
    path: String,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_http(stream: &mut impl Read) -> std::io::Result<HttpRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if find_header_end(&buf).is_some() {
            break;
        }
        if buf.len() > MAX_BODY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers",
            ));
        }
    }
    let header_end = find_header_end(&buf)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "headers"))?;
    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut lines = header_text.split("\r\n");
    let start = lines.next().unwrap_or("");
    let mut parts = start.split(' ');
    let first = parts.next().unwrap_or("");
    let second = parts.next().unwrap_or("");
    let (method, path, status) = if first.starts_with("HTTP/") {
        let status = second.parse().unwrap_or(0);
        (String::new(), String::new(), status)
    } else {
        (first.to_string(), second.to_string(), 0)
    };
    let mut headers = Vec::new();
    let mut length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().unwrap_or(0);
        }
        headers.push((name.to_string(), value.to_string()));
    }
    if length > MAX_BODY {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(HttpRequest {
        method,
        path,
        status,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn http_response(status: u16, body: &[u8]) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Error",
        502 => "Bad Gateway",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
}

pub fn spawn_upstream(body: &'static [u8]) -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Ok(request) = read_http(&mut stream) {
                let _ = std::fs::write(
                    std::env::temp_dir().join(format!("hushid-upstream-{port}.body")),
                    &request.body,
                );
            }
            let response = http_response(200, body);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    Ok(format!("http://127.0.0.1:{port}"))
}

/// One MCP JSON-RPC message. `session` selects the vault file.
pub fn mcp_message(vault_dir: &Path, glossary: &Glossary, message: &str) -> Option<String> {
    let method = json_string_field(message, "method")?;
    let id = json_raw_field(message, "id");
    if method == "notifications/initialized" {
        return None;
    }
    let result = if method == "initialize" {
        r#"{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"hushid","version":"0.1.0"}}"#.to_string()
    } else if method == "tools/list" {
        r#"{"tools":[{"name":"shield","description":"Replace recognized identifiers.","inputSchema":{"type":"object"}},{"name":"restore","description":"Copy original bytes back for tokens this vault issued.","inputSchema":{"type":"object"}}]}"#.to_string()
    } else if method == "tools/call" {
        let params = json_object_field(message, "params").unwrap_or("");
        let name = json_string_field(params, "name").unwrap_or_default();
        let arguments = json_object_field(params, "arguments").unwrap_or("");
        let session = json_string_field(arguments, "session").unwrap_or_default();
        let text = json_string_field(arguments, "text").unwrap_or_default();
        match mcp_tool(vault_dir, glossary, &name, &session, &text) {
            Ok(payload) => format!(r#"{{"content":[{{"type":"text","text":{payload}}}]}}"#),
            Err(err) => {
                format!(r#"{{"content":[{{"type":"text","text":"{err}"}}],"isError":true}}"#)
            }
        }
    } else if method == "ping" {
        "{}".to_string()
    } else {
        return Some(json_error(id, "method"));
    };
    Some(json_result(id, &result))
}

fn mcp_tool(
    vault_dir: &Path,
    glossary: &Glossary,
    name: &str,
    session: &str,
    text: &str,
) -> Result<String, &'static str> {
    let mut vault = load_session(vault_dir, session).map_err(|_| "session")?;
    let out = if name == "shield" {
        let (out, _) = hushid::shield_text(&mut vault, glossary, text).map_err(|_| "shield")?;
        save_session(vault_dir, session, &vault).map_err(|_| "vault")?;
        out
    } else if name == "restore" {
        vault.restore_write(text).map_err(|_| "restore")?
    } else {
        return Err("tool");
    };
    Ok(json_escape(&out))
}

fn json_result(id: Option<&str>, result: &str) -> String {
    match id {
        Some(id) => format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#),
        None => format!(r#"{{"jsonrpc":"2.0","result":{result}}}"#),
    }
}

fn json_error(id: Option<&str>, message: &str) -> String {
    let id = id.unwrap_or("null");
    format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"{message}"}}}}"#)
}

fn json_string_field(json: &str, field: &str) -> Option<String> {
    let raw = json_raw_field(json, field)?;
    let raw = raw.trim();
    let raw = raw.strip_prefix('"')?.strip_suffix('"')?;
    Some(raw.replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn json_object_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let raw = json_raw_field(json, field)?;
    let raw = raw.trim();
    if raw.starts_with('{') {
        Some(raw)
    } else {
        None
    }
}

fn json_raw_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{field}\"");
    let start = json.find(&needle)?;
    let after = json[start + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    if let Some(rest) = after.strip_prefix('"') {
        let mut escaped = false;
        for (index, ch) in rest.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' {
                let end = 1 + index + ch.len_utf8();
                return Some(&after[..end]);
            }
        }
        None
    } else if after.starts_with('{') {
        let mut depth = 0i32;
        for (index, ch) in after.char_indices() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    return Some(&after[..=index]);
                }
            }
        }
        None
    } else {
        let end = after.find([',', '}']).unwrap_or(after.len());
        Some(after[..end].trim())
    }
}

fn json_escape(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod url_tests {
    use super::completions_url;

    #[test]
    fn default_ports_and_chat_path() {
        assert_eq!(
            completions_url("http://example.com").unwrap(),
            "http://example.com:80/v1/chat/completions"
        );
        assert_eq!(
            completions_url("https://example.com").unwrap(),
            "https://example.com:443/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://127.0.0.1:9").unwrap(),
            "http://127.0.0.1:9/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://127.0.0.1:9/v1").unwrap(),
            "http://127.0.0.1:9/v1/chat/completions"
        );
        assert_eq!(
            completions_url("https://api.example/v1/chat/completions").unwrap(),
            "https://api.example:443/v1/chat/completions"
        );
        assert_eq!(
            completions_url("https://api.example/v1/chat/completions?stream=false").unwrap(),
            "https://api.example:443/v1/chat/completions?stream=false"
        );
        assert_eq!(
            completions_url("http://127.0.0.1:9/v1?x=1").unwrap(),
            "http://127.0.0.1:9/v1/chat/completions?x=1"
        );
        assert_eq!(
            completions_url("http://example.com?x=1").unwrap(),
            "http://example.com:80/v1/chat/completions?x=1"
        );
        assert_eq!(
            completions_url("https://api.example/v1/chat/completions#frag").unwrap(),
            "https://api.example:443/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://[::1]:9/v1").unwrap(),
            "http://[::1]:9/v1/chat/completions"
        );
        assert!(completions_url("ftp://example.com").is_err());
    }
}
