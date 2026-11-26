//! OpenAI-compatible chat proxy and a small MCP server.
//!
//! The session id arrives on `X-Hushid-Session`. Message strings use the
//! same vault rules as the library. The clear request is not written beside
//! the vault file. The upstream may be `http` or `https`. A URL with no
//! port uses 80 or 443. A query string stays on the chat path, and a
//! fragment is dropped. A restored body keeps the upstream status and the
//! upstream content type. An event stream stays `text/event-stream`.
//! Content values and `function` argument fragments inside streamed
//! `delta` objects are joined first, so a token split across those
//! values is restored, including a split across more than two events.
//! The status reason is kept, so a rate limit
//! stays `429 Too Many Requests`. A reply
//! that quotes `h1_secret` keeps that mark and still restores other tokens.
//! An unknown `h1_` token is a 502 and is not forwarded. A request with no `Content-Length`
//! is read until the connection closes, the same as a response, up to 1 MiB.
//! A chunked body is assembled the same way, for a request and for a
//! response. A body shorter than a declared
//! `Content-Length` is refused for both directions. A redirect is not followed.

use hushid::{Glossary, HeldStream, JsonError, Vault, SECRET_MARK};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[cfg(test)]
static TEST_TLS_ROOT: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

const SESSION_HEADER: &str = "x-hushid-session";
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug)]
/// Why a proxy call failed.
///
/// `Client` and `Headers` were added after 0.1.2. A caller that matches
/// every variant needs an arm for each. A match that already has a
/// wildcard does not.
pub enum ProxyError {
    Session,
    Body,
    /// The accepted socket failed. Setting its read timeout or writing
    /// the response uses this variant. Its display is `client`. A failed
    /// dial stays [`ProxyError::Upstream`].
    Client,
    /// The inbound `Authorization` value contained a carriage return, a
    /// line feed, or a NUL. Its display is `headers`. No dial happens.
    /// A line break in the configured upstream URL stays
    /// [`ProxyError::Upstream`].
    Headers,
    Upstream,
    Vault(hushid::VaultError),
    Json(JsonError),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Session => write!(f, "session"),
            ProxyError::Body => write!(f, "body"),
            ProxyError::Client => write!(f, "client"),
            ProxyError::Headers => write!(f, "headers"),
            ProxyError::Upstream => write!(f, "upstream"),
            ProxyError::Vault(err) => write!(f, "vault: {err}"),
            ProxyError::Json(err) => write!(f, "body: {err}"),
        }
    }
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
    hushid::restore_json_reply(vault, body)
}

fn event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .eq_ignore_ascii_case("text/event-stream")
}

/// Join streamed `delta` content and `function` argument fragments so a
/// token cut across events is one token.
///
/// [`restore_chat`] rejects a partial `h1_` inside one string. A trailing
/// `h` or `h1` stays with the next values while those values are still the
/// start of a token. The held pieces return to their own events when a
/// later value does not continue that token.
fn reassemble_streamed_deltas(body: &str, vault: &Vault) -> String {
    let slots = streamed_delta_contents(body);
    if slots.len() < 2 {
        return body.to_string();
    }
    let mut pending = String::new();
    let mut pending_parts: Vec<String> = Vec::new();
    let mut emitted: Vec<String> = Vec::with_capacity(slots.len());
    for (index, slot) in slots.iter().enumerate() {
        let next = &slot.decoded;
        let chunk = if pending.is_empty() {
            next.clone()
        } else if join_completes_token(&pending, next, vault) {
            let combined = format!("{pending}{next}");
            pending.clear();
            pending_parts.clear();
            combined
        } else if join_extends_prefix(&pending, next) {
            pending.push_str(next);
            pending_parts.push(next.clone());
            emitted.push(String::new());
            if index + 1 == slots.len() {
                restore_pending_parts(&mut emitted, &pending_parts);
                pending.clear();
                pending_parts.clear();
            }
            continue;
        } else {
            restore_pending_parts(&mut emitted, &pending_parts);
            pending.clear();
            pending_parts.clear();
            next.clone()
        };
        let mut held = HeldStream::new();
        let mut piece = held.push_restore(&chunk, vault);
        let hold = held.finish();
        if index + 1 == slots.len() || hold.is_empty() {
            piece.push_str(&vault.restore_display(&hold));
            pending.clear();
            pending_parts.clear();
        } else {
            pending.clone_from(&hold);
            pending_parts = vec![hold];
        }
        emitted.push(piece);
    }
    if !pending_parts.is_empty() {
        restore_pending_parts(&mut emitted, &pending_parts);
    }
    if slots
        .iter()
        .zip(emitted.iter())
        .all(|(slot, piece)| slot.decoded == *piece)
    {
        return body.to_string();
    }
    let mut out = body.to_string();
    for (slot, piece) in slots.iter().zip(emitted).rev() {
        out.replace_range(slot.raw_start..slot.raw_end, &encode_json_string(&piece));
    }
    out
}

/// A held `h` or `h1` is only part of the next value when that join
/// finishes `h1_secret` or a typed token. Other suffixes stay put.
fn join_completes_token(hold: &str, next: &str, vault: &Vault) -> bool {
    if hold.is_empty() || next.is_empty() {
        return false;
    }
    let joined = format!("{hold}{next}");
    if hold.len() < SECRET_MARK.len()
        && SECRET_MARK.as_bytes()[..hold.len()].eq_ignore_ascii_case(hold.as_bytes())
        && joined.len() >= SECRET_MARK.len()
        && joined.as_bytes()[..SECRET_MARK.len()].eq_ignore_ascii_case(SECRET_MARK.as_bytes())
    {
        return true;
    }
    let restored = vault.restore_display(&joined);
    if restored == joined {
        return false;
    }
    let same = joined
        .bytes()
        .zip(restored.bytes())
        .take_while(|(left, right)| left == right)
        .count();
    same < hold.len()
}

/// A held prefix stays open when the next value is empty or makes a longer
/// prefix that is still not a finished token. A finished token is
/// [`join_completes_token`], not this.
fn join_extends_prefix(hold: &str, next: &str) -> bool {
    if hold.is_empty() {
        return false;
    }
    if next.is_empty() {
        return true;
    }
    let joined = format!("{hold}{next}");
    let mut stream = HeldStream::new();
    let stable = stream.push(&joined);
    let still = stream.finish();
    stable.is_empty() && still.len() > hold.len()
}

fn restore_pending_parts(emitted: &mut [String], parts: &[String]) {
    if parts.is_empty() {
        return;
    }
    let start = emitted.len() - parts.len();
    for (offset, part) in parts.iter().enumerate() {
        emitted[start + offset].push_str(part);
    }
}

struct DeltaContent {
    raw_start: usize,
    raw_end: usize,
    decoded: String,
}

fn streamed_delta_contents(body: &str) -> Vec<DeltaContent> {
    let bytes = body.as_bytes();
    let mut slots = Vec::new();
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if byte == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            let key = br#""delta""#;
            if bytes[index..].starts_with(key) {
                let after = skip_ascii_ws(body, index + key.len());
                if bytes.get(after) == Some(&b':') {
                    let value_at = skip_ascii_ws(body, after + 1);
                    if bytes.get(value_at) == Some(&b'{') {
                        let found = strings_in_delta(body, value_at);
                        if let Some(last) = found.last() {
                            index = last.raw_end;
                            slots.extend(found);
                            continue;
                        }
                    }
                }
            }
            in_string = true;
            index += 1;
            continue;
        }
        index += 1;
    }
    slots
}

fn strings_in_delta(body: &str, open: usize) -> Vec<DeltaContent> {
    let bytes = body.as_bytes();
    let mut index = open;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut found = Vec::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if byte == b'\\' {
                let Some(next) = skip_json_escape(bytes, index) else {
                    return found;
                };
                index = next;
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            let content: &[u8] = br#""content""#;
            let arguments: &[u8] = br#""arguments""#;
            let key = if depth == 1 && bytes[index..].starts_with(content) {
                Some(content)
            } else if depth > 1 && bytes[index..].starts_with(arguments) {
                Some(arguments)
            } else {
                None
            };
            if let Some(key) = key {
                let after = skip_ascii_ws(body, index + key.len());
                if bytes.get(after) == Some(&b':') {
                    let value_at = skip_ascii_ws(body, after + 1);
                    if bytes.get(value_at) == Some(&b'"') {
                        let Some(raw_end) = quoted_string_end(body, value_at) else {
                            return found;
                        };
                        let Ok(decoded) = decode_json_string(&body[value_at + 1..raw_end - 1])
                        else {
                            return found;
                        };
                        found.push(DeltaContent {
                            raw_start: value_at,
                            raw_end,
                            decoded,
                        });
                        index = raw_end;
                        continue;
                    }
                }
            }
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'{' || byte == b'[' {
            depth += 1;
        } else if byte == b'}' || byte == b']' {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        index += 1;
    }
    found
}

fn quoted_string_end(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'"') {
        return None;
    }
    let mut index = open + 1;
    while index < bytes.len() {
        if !text.is_char_boundary(index) {
            return None;
        }
        match bytes[index] {
            b'\\' => index = skip_json_escape(bytes, index)?,
            b'"' => return Some(index + 1),
            byte if byte < 0x20 => return None,
            _ => {
                let ch = text[index..].chars().next()?;
                index += ch.len_utf8();
            }
        }
    }
    None
}

fn skip_json_escape(bytes: &[u8], slash: usize) -> Option<usize> {
    let next = slash + 1;
    let kind = *bytes.get(next)?;
    match kind {
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Some(next + 1),
        b'u' => {
            let end = next + 5;
            if end > bytes.len() || !bytes[next + 1..end].iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            Some(end)
        }
        _ => None,
    }
}

fn skip_ascii_ws(text: &str, mut index: usize) -> usize {
    let bytes = text.as_bytes();
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn encode_json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
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

/// A case-insensitive volume opens `WinCase.vault` when the caller asked
/// for `wincase.vault`. That would load the other session.
fn case_collides(dir: &Path, file_name: &str) -> bool {
    #[cfg(windows)]
    {
        let Ok(entries) = fs::read_dir(dir) else {
            return false;
        };
        let mut exact = false;
        let mut other_case = false;
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name == file_name {
                exact = true;
            } else if name.eq_ignore_ascii_case(file_name) {
                other_case = true;
            }
        }
        other_case && !exact
    }
    #[cfg(not(windows))]
    {
        let _ = (dir, file_name);
        false
    }
}

fn session_file(dir: &Path, session: &str) -> Result<PathBuf, ProxyError> {
    let path = session_path(dir, session).ok_or(ProxyError::Session)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ProxyError::Session)?;
    if case_collides(dir, file_name) {
        return Err(ProxyError::Session);
    }
    Ok(path)
}

pub fn load_session(dir: &Path, session: &str) -> Result<Vault, ProxyError> {
    let path = session_file(dir, session)?;
    if !path.exists() {
        return Ok(Vault::new());
    }
    Vault::load(&path).map_err(ProxyError::Vault)
}

pub fn save_session(dir: &Path, session: &str, vault: &Vault) -> Result<(), ProxyError> {
    let path = session_file(dir, session)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| ProxyError::Vault(hushid::VaultError::Io(err)))?;
    }
    vault.save(&path).map_err(ProxyError::Vault)
}

pub struct Proxy {
    local: SocketAddr,
    upstream: String,
    vault_dir: PathBuf,
    glossary: Glossary,
    incoming: Incoming,
}

enum Incoming {
    Direct(TcpListener),
    Shared {
        rx: Receiver<std::io::Result<TcpStream>>,
        stop: Arc<AtomicBool>,
        joins: Vec<thread::JoinHandle<()>>,
        addrs: Vec<SocketAddr>,
    },
}

#[cfg(windows)]
fn localhost_port(listen: &str) -> Option<u16> {
    let (host, port) = listen.rsplit_once(':')?;
    if !host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    port.parse().ok()
}

fn bind_listeners(listen: &str) -> std::io::Result<Vec<TcpListener>> {
    #[cfg(windows)]
    if let Some(listeners) = bind_localhost(listen)? {
        return Ok(listeners);
    }
    Ok(vec![TcpListener::bind(listen)?])
}

/// Windows resolves `localhost` to `[::1]` first and `TcpListener::bind`
/// keeps only that address. A client of `127.0.0.1` then waits until the
/// connect times out. Listen on both loopbacks, on one port.
#[cfg(windows)]
fn bind_localhost(listen: &str) -> std::io::Result<Option<Vec<TcpListener>>> {
    let Some(port) = localhost_port(listen) else {
        return Ok(None);
    };
    if port == 0 {
        let v4 = TcpListener::bind("127.0.0.1:0")?;
        let chosen = v4.local_addr()?.port();
        let mut listeners = vec![v4];
        if let Ok(v6) = TcpListener::bind(format!("[::1]:{chosen}")) {
            listeners.push(v6);
        }
        return Ok(Some(listeners));
    }
    let mut listeners = Vec::new();
    let mut last_err = None;
    for addr in [format!("127.0.0.1:{port}"), format!("[::1]:{port}")] {
        match TcpListener::bind(addr) {
            Ok(listener) => listeners.push(listener),
            Err(err) => last_err = Some(err),
        }
    }
    if listeners.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "localhost")
        }));
    }
    Ok(Some(listeners))
}

fn share_listeners(listeners: Vec<TcpListener>) -> std::io::Result<(SocketAddr, Incoming)> {
    if listeners.len() == 1 {
        let listener = listeners
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("listen"))?;
        let local = listener.local_addr()?;
        return Ok((local, Incoming::Direct(listener)));
    }
    let local = listeners[0].local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let mut joins = Vec::new();
    let mut addrs = Vec::new();
    for listener in listeners {
        addrs.push(listener.local_addr()?);
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        joins.push(thread::spawn(move || loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if stop.load(Ordering::Relaxed) || tx.send(Ok(stream)).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx.send(Err(err));
                    break;
                }
            }
        }));
    }
    drop(tx);
    Ok((
        local,
        Incoming::Shared {
            rx,
            stop,
            joins,
            addrs,
        },
    ))
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let Incoming::Shared {
            stop, joins, addrs, ..
        } = &mut self.incoming
        else {
            return;
        };
        stop.store(true, Ordering::Relaxed);
        for addr in addrs.iter() {
            let _ = TcpStream::connect_timeout(addr, Duration::from_millis(200));
        }
        for join in joins.drain(..) {
            let _ = join.join();
        }
    }
}

impl Proxy {
    pub fn bind(
        listen: &str,
        upstream: &str,
        vault_dir: &Path,
        glossary: Glossary,
    ) -> std::io::Result<Self> {
        let listeners = bind_listeners(listen)?;
        let (local, incoming) = share_listeners(listeners)?;
        Ok(Self {
            local,
            incoming,
            upstream: upstream.to_string(),
            vault_dir: vault_dir.to_path_buf(),
            glossary,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    pub fn serve_one(&self) -> Result<(), ProxyError> {
        let mut stream = match &self.incoming {
            Incoming::Direct(listener) => listener.accept().map(|(stream, _)| stream),
            Incoming::Shared { rx, .. } => rx.recv().unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "listen",
                ))
            }),
        }
        .map_err(|_| ProxyError::Client)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| ProxyError::Client)?;
        let request = match read_http(&mut stream) {
            Ok(request) => request,
            Err(err) => {
                let word = err.to_string();
                let answered = word == "chunk"
                    || (err.kind() == std::io::ErrorKind::InvalidData
                        && matches!(word.as_str(), "body" | "length" | "headers"));
                if answered {
                    let shown = if word == "chunk" {
                        "body"
                    } else {
                        word.as_str()
                    };
                    let response =
                        http_response(400, format!(r#"{{"error":"{shown}"}}"#).as_bytes());
                    stream
                        .write_all(response.as_bytes())
                        .map_err(|_| ProxyError::Client)?;
                    return Ok(());
                }
                return Err(ProxyError::Body);
            }
        };
        let response = self.handle(&request);
        stream
            .write_all(response.as_bytes())
            .map_err(|_| ProxyError::Client)?;
        Ok(())
    }

    fn handle(&self, request: &HttpRequest) -> String {
        let path = request
            .path
            .split_once('?')
            .map(|(path, _)| path)
            .unwrap_or(&request.path);
        let path = path.split_once('#').map(|(path, _)| path).unwrap_or(path);
        if request.method != "POST" || path != "/v1/chat/completions" {
            return http_response(404, br#"{"error":"not found"}"#);
        }
        let Some(session) = request.header(SESSION_HEADER) else {
            return http_response(400, br#"{"error":"missing session"}"#);
        };
        let mut vault = match load_session(&self.vault_dir, session) {
            Ok(vault) => vault,
            Err(ProxyError::Vault(_)) => return http_response(500, br#"{"error":"vault"}"#),
            Err(_) => return http_response(400, br#"{"error":"bad session"}"#),
        };
        let Ok(body) = std::str::from_utf8(&request.body) else {
            return http_response(400, br#"{"error":"body"}"#);
        };
        let Ok(shielded) = shield_chat(body, &mut vault, &self.glossary) else {
            return http_response(400, br#"{"error":"body"}"#);
        };
        if let Err(err) = save_session(&self.vault_dir, session, &vault) {
            return match err {
                ProxyError::Session => http_response(400, br#"{"error":"bad session"}"#),
                _ => http_response(500, br#"{"error":"vault"}"#),
            };
        }
        let upstream = match forward(&self.upstream, &shielded, request.header("authorization")) {
            Ok(reply) => reply,
            Err(ProxyError::Headers) => return http_response(400, br#"{"error":"headers"}"#),
            Err(_) => return http_response(502, br#"{"error":"upstream"}"#),
        };
        let restored = match std::str::from_utf8(&upstream.body) {
            Ok(text) => {
                let text = if event_stream(&upstream.content_type) {
                    reassemble_streamed_deltas(text, &vault)
                } else {
                    text.to_string()
                };
                match restore_chat(&text, &vault) {
                    Ok(restored) => restored,
                    Err(_) => return http_response(502, br#"{"error":"restore"}"#),
                }
            }
            Err(_) => {
                if upstream
                    .body
                    .windows(3)
                    .any(|window| window.eq_ignore_ascii_case(b"h1_"))
                {
                    return http_response(502, br#"{"error":"restore"}"#);
                }
                String::from_utf8_lossy(&upstream.body).into_owned()
            }
        };
        http_response_typed(
            upstream.status,
            &safe_reason(upstream.status, &upstream.reason),
            &upstream.content_type,
            restored.as_bytes(),
        )
    }
}

pub struct UpstreamReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: String,
    pub reason: String,
}

pub fn forward(
    upstream: &str,
    body: &str,
    authorization: Option<&str>,
) -> Result<UpstreamReply, ProxyError> {
    if let Some(value) = authorization {
        if value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(ProxyError::Headers);
        }
    }
    if upstream
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(ProxyError::Upstream);
    }
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
        let connector = tls_connector()?;
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
        content_type: response_media_type(&response),
        reason: response.reason,
        body: response.body,
    })
}

fn response_media_type(response: &HttpRequest) -> String {
    let Some(value) = response.header("content-type") else {
        return "application/json".to_string();
    };
    if value.is_empty()
        || value.len() > 200
        || value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0 || byte.is_ascii_control())
    {
        return "application/json".to_string();
    }
    value.to_string()
}

fn tls_connector() -> Result<native_tls::TlsConnector, ProxyError> {
    #[cfg(test)]
    if let Some(pem) = TEST_TLS_ROOT
        .lock()
        .map_err(|_| ProxyError::Upstream)?
        .clone()
    {
        let cert = native_tls::Certificate::from_pem(&pem).map_err(|_| ProxyError::Upstream)?;
        let mut builder = native_tls::TlsConnector::builder();
        builder.add_root_certificate(cert);
        return builder.build().map_err(|_| ProxyError::Upstream);
    }
    native_tls::TlsConnector::new().map_err(|_| ProxyError::Upstream)
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
    reason: String,
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
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "headers"))?;
    let mut lines = header_text.split("\r\n");
    let start = lines.next().unwrap_or("");
    let mut parts = start.split(' ');
    let first = parts.next().unwrap_or("");
    let second = parts.next().unwrap_or("");
    let is_response = first.starts_with("HTTP/");
    let (method, path, status) = if is_response {
        let status = second.parse().unwrap_or(0);
        (String::new(), String::new(), status)
    } else {
        (first.to_string(), second.to_string(), 0)
    };
    let reason = if is_response {
        start.splitn(3, ' ').nth(2).unwrap_or("").trim().to_string()
    } else {
        String::new()
    };
    let mut headers = Vec::new();
    let mut length = 0usize;
    let mut saw_length = false;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "length"))?;
            if saw_length && parsed != length {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "length",
                ));
            }
            saw_length = true;
            length = parsed;
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
        headers.push((name.to_string(), value.to_string()));
    }
    let pending = buf[header_end + 4..].to_vec();
    let body = if chunked {
        decode_chunked(stream, &pending)?
    } else if !saw_length {
        read_until_close(stream, pending)?
    } else {
        if length > MAX_BODY {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
        }
        let mut body = pending;
        while body.len() < length {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        if body.len() < length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "length",
            ));
        }
        body.truncate(length);
        body
    };
    Ok(HttpRequest {
        method,
        path,
        status,
        reason,
        headers,
        body,
    })
}

fn read_until_close(stream: &mut impl Read, mut body: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut chunk = [0u8; 2048];
    loop {
        if body.len() > MAX_BODY {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(body);
        }
        let room = MAX_BODY.saturating_sub(body.len());
        if read > room {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

fn decode_chunked(stream: &mut impl Read, pending: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut raw = pending.to_vec();
    let mut filled = raw.len();
    let mut pos = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = loop {
            if let Some(rel) = raw[pos..filled]
                .windows(2)
                .position(|window| window == b"\r\n")
            {
                break pos + rel;
            }
            if filled - pos > 64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk",
                ));
            }
            if !read_more(stream, &mut raw, &mut filled)? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "chunk",
                ));
            }
        };
        let line = std::str::from_utf8(&raw[pos..line_end])
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk"))?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk"))?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        if decoded.len().saturating_add(size) > MAX_BODY {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
        }
        let need = pos
            .checked_add(size)
            .and_then(|end| end.checked_add(2))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk"))?;
        while filled < need {
            if !read_more(stream, &mut raw, &mut filled)? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "chunk",
                ));
            }
        }
        decoded.extend_from_slice(&raw[pos..pos + size]);
        if &raw[pos + size..need] != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk",
            ));
        }
        raw.drain(..need);
        filled -= need;
        pos = 0;
    }
}

fn read_more(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    filled: &mut usize,
) -> std::io::Result<bool> {
    let mut chunk = [0u8; 2048];
    let read = stream.read(&mut chunk)?;
    if read == 0 {
        return Ok(false);
    }
    if *filled + read > MAX_BODY + 64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
    }
    if *filled + read > raw.len() {
        raw.resize(*filled + read, 0);
    }
    raw[*filled..*filled + read].copy_from_slice(&chunk[..read]);
    *filled += read;
    Ok(true)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Error",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

fn safe_reason(status: u16, reason: &str) -> String {
    if reason.is_empty() || reason.len() > 80 || reason.bytes().any(|byte| byte.is_ascii_control())
    {
        return status_reason(status).to_string();
    }
    reason.to_string()
}

fn http_response(status: u16, body: &[u8]) -> String {
    http_response_typed(status, status_reason(status), "application/json", body)
}

fn http_response_typed(status: u16, reason: &str, content_type: &str, body: &[u8]) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    let id = json_raw_field(message, "id");
    let method = match json_string_field(message, "method") {
        Ok(Some(method)) => method,
        Ok(None) => return None,
        Err(_) => return Some(json_error(id, "escape")),
    };
    if method == "notifications/initialized" {
        return None;
    }
    let result = if method == "initialize" {
        format!(
            r#"{{"protocolVersion":"2024-11-05","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"hushid","version":"{}"}}}}"#,
            env!("CARGO_PKG_VERSION")
        )
    } else if method == "tools/list" {
        r#"{"tools":[{"name":"shield","description":"Replace recognized identifiers.","inputSchema":{"type":"object"}},{"name":"restore","description":"Copy original bytes back for tokens this vault issued.","inputSchema":{"type":"object"}}]}"#.to_string()
    } else if method == "tools/call" {
        let params = json_object_field(message, "params").unwrap_or("");
        let name = match json_string_field(params, "name") {
            Ok(value) => value.unwrap_or_default(),
            Err(_) => return Some(escape_tool_error(id)),
        };
        let arguments = json_object_field(params, "arguments").unwrap_or("");
        let session = match json_string_field(arguments, "session") {
            Ok(value) => value.unwrap_or_default(),
            Err(_) => return Some(escape_tool_error(id)),
        };
        let text = match json_string_field(arguments, "text") {
            Ok(value) => value.unwrap_or_default(),
            Err(_) => return Some(escape_tool_error(id)),
        };
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
    let mut vault = match load_session(vault_dir, session) {
        Ok(vault) => vault,
        Err(ProxyError::Vault(_)) => return Err("vault"),
        Err(_) => return Err("session"),
    };
    let out = if name == "shield" {
        let (out, _) = hushid::shield_text(&mut vault, glossary, text).map_err(|_| "shield")?;
        save_session(vault_dir, session, &vault).map_err(|_| "vault")?;
        out
    } else if name == "restore" {
        hushid::restore_readable(&vault, text).map_err(|_| "restore")?
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

fn escape_tool_error(id: Option<&str>) -> String {
    let result = r#"{"content":[{"type":"text","text":"escape"}],"isError":true}"#;
    json_result(id, result)
}

fn json_error(id: Option<&str>, message: &str) -> String {
    let id = id.unwrap_or("null");
    format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"{message}"}}}}"#)
}

fn json_string_field(json: &str, field: &str) -> Result<Option<String>, &'static str> {
    let Some(raw) = json_raw_field(json, field) else {
        return Ok(None);
    };
    let raw = raw.trim();
    let Some(raw) = raw.strip_prefix('"').and_then(|raw| raw.strip_suffix('"')) else {
        return Ok(None);
    };
    decode_json_string(raw).map(Some)
}

fn decode_json_string(raw: &str) -> Result<String, &'static str> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut decoded = String::new();
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                if index >= bytes.len() {
                    return Err("escape");
                }
                match bytes[index] {
                    b'"' => {
                        decoded.push('"');
                        index += 1;
                    }
                    b'\\' => {
                        decoded.push('\\');
                        index += 1;
                    }
                    b'/' => {
                        decoded.push('/');
                        index += 1;
                    }
                    b'b' => {
                        decoded.push('\u{0008}');
                        index += 1;
                    }
                    b'f' => {
                        decoded.push('\u{000c}');
                        index += 1;
                    }
                    b'n' => {
                        decoded.push('\n');
                        index += 1;
                    }
                    b'r' => {
                        decoded.push('\r');
                        index += 1;
                    }
                    b't' => {
                        decoded.push('\t');
                        index += 1;
                    }
                    b'u' => {
                        index += 1;
                        let unit = read_hex4(bytes, index)?;
                        index += 4;
                        let ch = if (0xD800..=0xDBFF).contains(&unit) {
                            if bytes.get(index) != Some(&b'\\')
                                || bytes.get(index + 1) != Some(&b'u')
                            {
                                return Err("escape");
                            }
                            index += 2;
                            let low = read_hex4(bytes, index)?;
                            index += 4;
                            decode_surrogate(unit, low).ok_or("escape")?
                        } else if (0xDC00..=0xDFFF).contains(&unit) {
                            return Err("escape");
                        } else {
                            char::from_u32(u32::from(unit)).ok_or("escape")?
                        };
                        decoded.push(ch);
                    }
                    _ => return Err("escape"),
                }
            }
            byte if byte < 0x20 => return Err("escape"),
            _ => {
                let ch = raw[index..].chars().next().ok_or("escape")?;
                decoded.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    Ok(decoded)
}

fn read_hex4(bytes: &[u8], start: usize) -> Result<u16, &'static str> {
    if start + 4 > bytes.len() {
        return Err("escape");
    }
    let text = std::str::from_utf8(&bytes[start..start + 4]).map_err(|_| "escape")?;
    u16::from_str_radix(text, 16).map_err(|_| "escape")
}

fn decode_surrogate(high: u16, low: u16) -> Option<char> {
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let value = 0x10000 + (((u32::from(high) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
    char::from_u32(value)
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

fn json_key_at(json: &str, needle: &str) -> Option<usize> {
    let bytes = json.as_bytes();
    let needle = needle.as_bytes();
    let mut index = 0;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut found = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if byte == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            if depth == 1 && bytes[index..].starts_with(needle) {
                let rest = json[index + needle.len()..].trim_start();
                if rest.starts_with(':') {
                    found = Some(index);
                }
            }
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'{' || byte == b'[' {
            depth += 1;
        } else if byte == b'}' || byte == b']' {
            depth -= 1;
        }
        index += 1;
    }
    found
}

fn json_raw_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{field}\"");
    let start = json_key_at(json, &needle)?;
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
        let bytes = after.as_bytes();
        let mut depth = 0i32;
        let mut in_string = false;
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if in_string {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == b'"' {
                    in_string = false;
                }
                index += 1;
                continue;
            }
            if byte == b'"' {
                in_string = true;
            } else if byte == b'{' {
                depth += 1;
            } else if byte == b'}' {
                depth -= 1;
                if depth == 0 {
                    return Some(&after[..=index]);
                }
            }
            index += 1;
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
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                let value = u32::from(ch);
                out.push_str(&format!("\\u{value:04x}"));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod proxy_error_tests {
    use super::ProxyError;

    #[test]
    fn proxy_error_includes_the_vault_io_error() {
        let err = ProxyError::Vault(hushid::VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "vault-file",
        )));
        let text = err.to_string();
        assert!(text.contains("vault-file"), "{text}");
    }
}

#[cfg(test)]
mod auth_header_tests {
    use super::forward;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn forward_rejects_a_newline_in_authorization() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_read = Arc::clone(&seen);
        let reader = thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(500) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                if let Ok(read) = stream.read(&mut chunk) {
                    buf.extend_from_slice(&chunk[..read]);
                }
                *seen_read.lock().unwrap() = buf;
                return;
            }
        });
        let err = forward(
            &format!("http://127.0.0.1:{port}"),
            "{}",
            Some("Bearer a\nX: y"),
        );
        reader.join().unwrap();
        match err {
            Err(err) => assert_eq!(err.to_string(), "headers"),
            Ok(_) => panic!("a newline in authorization was accepted"),
        }
        let sent = seen.lock().unwrap();
        let sent = String::from_utf8_lossy(&sent);
        assert!(
            !sent.contains("X: y"),
            "a newline in authorization was sent upstream: {sent}"
        );
    }

    #[test]
    fn forward_rejects_a_newline_in_the_upstream_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = format!("http://127.0.0.1:{port}/v1?x=1\r\nX-Injected: z");
        let err = forward(&upstream, "{}", None);
        match err {
            Err(err) => assert_eq!(err.to_string(), "upstream"),
            Ok(_) => panic!("a newline in the upstream url was accepted"),
        }
        assert!(listener.accept().is_err());
    }
}

#[cfg(test)]
mod header_tests {
    use super::read_http;
    use std::io::{Cursor, Read};

    struct ChunkFlood {
        prefix: &'static [u8],
        pos: usize,
        extra: usize,
    }

    impl Read for ChunkFlood {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos < self.prefix.len() {
                let count = (self.prefix.len() - self.pos).min(buf.len());
                buf[..count].copy_from_slice(&self.prefix[self.pos..self.pos + count]);
                self.pos += count;
                return Ok(count);
            }
            let count = buf.len().min(2048);
            buf[..count].fill(b'A');
            self.extra += count;
            Ok(count)
        }
    }

    #[test]
    fn a_space_before_the_colon_still_decodes_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nTransfer-Encoding : chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let response = read_http(&mut &raw[..]).unwrap();
        assert_eq!(response.body, b"hello");
    }

    #[test]
    fn a_response_without_content_length_is_read_until_close() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"completion\":\"kept\"}";
        let response = read_http(&mut &raw[..]).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"completion":"kept"}"#);
    }

    #[test]
    fn a_chunk_size_line_without_an_end_is_refused() {
        let mut reader = ChunkFlood {
            prefix: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            pos: 0,
            extra: 0,
        };
        assert!(read_http(&mut reader).is_err());
        assert!(reader.extra < 4096, "{}", reader.extra);
    }

    #[test]
    fn a_chunked_request_is_the_decoded_body() {
        let json = br#"{"a":"ada@example.com"}"#;
        let raw = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
            json.len(),
            std::str::from_utf8(json).unwrap()
        );
        let request = read_http(&mut Cursor::new(raw.into_bytes())).unwrap();
        assert_eq!(request.body, json);
    }

    #[test]
    fn a_bad_request_length_is_rejected() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nContent-Length: no\r\n\r\n";
        assert!(read_http(&mut &raw[..]).is_err());
    }

    #[test]
    fn a_request_without_content_length_keeps_the_buffered_json() {
        let json = br#"{"messages":[]}"#;
        let raw = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{}",
            std::str::from_utf8(json).unwrap()
        );
        let request = read_http(&mut Cursor::new(raw.into_bytes())).unwrap();
        assert_eq!(request.body, json);
    }

    #[test]
    fn a_request_shorter_than_content_length_is_refused() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nContent-Length: 32\r\n\r\n{\"messages\":[]}";
        let err = read_http(&mut Cursor::new(&raw[..]))
            .err()
            .expect("short request body was accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "length");
    }

    #[test]
    fn disagreeing_content_lengths_are_refused() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 1\r\n\r\nhello";
        let err = read_http(&mut Cursor::new(&raw[..]))
            .err()
            .expect("two content lengths were accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "length");
    }

    #[test]
    fn the_same_content_length_twice_is_accepted() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        let response = read_http(&mut Cursor::new(&raw[..])).unwrap();
        assert_eq!(response.body, b"hello");
    }
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

#[cfg(test)]
mod tls_tests {
    use super::{forward, Proxy, TEST_TLS_ROOT};
    use hushid::Glossary;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    struct ClearRoot;

    impl Drop for ClearRoot {
        fn drop(&mut self) {
            if let Ok(mut root) = TEST_TLS_ROOT.lock() {
                *root = None;
            }
        }
    }

    fn local_tls_material(dir: &Path) -> (Vec<u8>, Vec<u8>) {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let p12 = dir.join("identity.p12");
        let req = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .args([
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=digitalSignature,keyEncipherment,keyCertSign",
                "-addext",
                "extendedKeyUsage=serverAuth",
            ])
            .status()
            .expect("openssl req");
        assert!(req.success(), "openssl req");
        let export = Command::new("openssl")
            .args(["pkcs12", "-export", "-passout", "pass:test"])
            .arg("-out")
            .arg(&p12)
            .arg("-inkey")
            .arg(&key)
            .arg("-in")
            .arg(&cert)
            .status()
            .expect("openssl pkcs12");
        assert!(export.success(), "openssl pkcs12");
        (std::fs::read(&cert).unwrap(), std::fs::read(&p12).unwrap())
    }

    #[test]
    fn https_upstream_does_not_use_cleartext() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 8];
            let _ = stream.read(&mut buf);
            if buf.starts_with(b"POST") {
                let body = br#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        assert!(forward(&format!("https://127.0.0.1:{port}/v1"), "{}", None).is_err());
    }

    #[test]
    #[allow(clippy::while_let_loop)]
    fn proxy_completes_a_tls_handshake() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_pem, p12) = local_tls_material(&dir);
        let identity = native_tls::Identity::from_pkcs12(&p12, "test").unwrap();
        let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_body = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut stream = acceptor.accept(stream).unwrap();
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
                    let header_end = buf
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .unwrap();
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let length = headers.lines().find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    });
                    if length.is_some_and(|length| buf.len() >= header_end + 4 + length) {
                        break;
                    }
                }
            }
            *seen_body.lock().unwrap() = buf;
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        *TEST_TLS_ROOT.lock().unwrap() = Some(cert_pem);
        let _clear = ClearRoot;
        let vault_dir = dir.join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("https://localhost:{port}/v1"),
            &vault_dir,
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
        assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
        assert!(response.contains("ok"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod coverage_edges {
    use super::{
        completions_url, decode_chunked, decode_json_string, exchange, forward, http_response,
        json_object_field, json_raw_field, mcp_message, read_http, read_more, read_until_close,
        reassemble_streamed_deltas, restore_chat, spawn_upstream, tls_dns_name, HttpRequest, Proxy,
        ProxyError, MAX_BODY,
    };
    use hushid::{Glossary, JsonError, Vault, VaultError};
    use std::io::{self, Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    struct Mem {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl Read for Mem {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for Mem {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            status: 0,
            reason: String::new(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn urls_hosts_and_reasons_cover_the_refused_shapes() {
        assert!(completions_url("http://").is_err());
        assert!(completions_url("http:///v1").is_err());
        assert!(completions_url("http://[]/v1").is_err());
        assert_eq!(
            completions_url("https://example.com/v1").unwrap(),
            "https://example.com:443/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://example.com/openai").unwrap(),
            "http://example.com:80/openai/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://[::1]").unwrap(),
            "http://[::1]:80/v1/chat/completions"
        );
        assert!(completions_url("http://example.com:not-a-port").is_ok());
        assert_eq!(tls_dns_name("user@host:443").unwrap(), "host");
        assert_eq!(tls_dns_name("[::1]:443").unwrap(), "::1");
        assert_eq!(tls_dns_name("[::1]").unwrap(), "::1");
        assert!(tls_dns_name("@:80").is_err());
        assert!(http_response(400, b"{}").contains("Bad Request"));
        assert!(http_response(404, b"{}").contains("Not Found"));
        assert!(http_response(500, b"{}").contains("Error"));
        assert_eq!(ProxyError::Session.to_string(), "session");
        assert_eq!(ProxyError::Body.to_string(), "body");
        assert_eq!(ProxyError::Client.to_string(), "client");
        assert_eq!(ProxyError::Headers.to_string(), "headers");
        assert_eq!(ProxyError::Upstream.to_string(), "upstream");
        assert!(ProxyError::Vault(VaultError::Missing)
            .to_string()
            .contains("vault"));
        assert!(ProxyError::Json(JsonError::Syntax { at: 1 })
            .to_string()
            .starts_with("body"));
    }

    #[test]
    #[allow(clippy::while_let_loop)]
    fn the_proxy_refuses_a_bad_request_before_it_dials() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-edge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let proxy =
            Proxy::bind("127.0.0.1:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
        assert!(proxy
            .handle(&request("GET", "/v1/chat/completions", &[], b"{}"))
            .contains("not found"));
        assert!(proxy
            .handle(&request("POST", "/v1/chat/completions", &[], b"{}"))
            .contains("missing session"));
        assert!(proxy
            .handle(&request(
                "POST",
                "/v1/chat/completions",
                &[("x-hushid-session", "bad/id")],
                b"{}",
            ))
            .contains("bad session"));
        assert!(proxy
            .handle(&request(
                "POST",
                "/v1/chat/completions",
                &[("x-hushid-session", "demo")],
                &[0xff],
            ))
            .contains("\"body\""));
        assert!(proxy
            .handle(&request(
                "POST",
                "/v1/chat/completions",
                &[("x-hushid-session", "demo")],
                br#"{"a":"\q"}"#,
            ))
            .contains("\"body\""));
        let file = dir.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let blocked = Proxy::bind(
            "127.0.0.1:0",
            "http://127.0.0.1:9",
            &file,
            Glossary::empty(),
        )
        .unwrap();
        assert!(blocked
            .handle(&request(
                "POST",
                "/v1/chat/completions",
                &[("x-hushid-session", "demo")],
                b"{}",
            ))
            .contains("vault"));
        assert!(proxy
            .handle(&request(
                "POST",
                "/v1/chat/completions",
                &[("x-hushid-session", "demo")],
                b"{}",
            ))
            .contains("upstream"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
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
                if !buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    continue;
                }
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
                let body = [0xffu8, 0xfe];
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                break;
            }
        });
        let binary = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = binary.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("x-hushid-session", "demo"), ("authorization", "Bearer z")],
            b"{}",
        ));
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secret_mark_in_the_reply_stays_a_mark() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = read_http(&mut stream);
            let body = br#"{"completion":"h1_secret"}"#;
            let _ = stream.write_all(http_response(200, body).as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            b"{}",
        ));
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("h1_secret"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_streamed_reply_keeps_the_event_stream_type() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-sse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = read_http(&mut stream).unwrap();
            let text = String::from_utf8_lossy(&request.body);
            let marker = "\"content\":\"";
            let start = text.find(marker).unwrap() + marker.len();
            let end = start + text[start..].find('"').unwrap();
            let content = &text[start..end];
            let sse = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{content}\"}}}}]}}\n\ndata: [DONE]\n\n"
            );
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sse}",
                sse.len()
            );
            let _ = stream.write_all(raw.as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            br#"{"model":"local","messages":[{"role":"user","content":"Write ada@example.com"}]}"#,
        ));
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert!(
            !response.contains("Content-Type: application/json"),
            "{response}"
        );
        assert!(response.contains("ada@example.com"), "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        assert!(response.contains("data: [DONE]"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_token_split_across_stream_deltas_is_restored() {
        let dir =
            std::env::temp_dir().join(format!("hushid-proxy-sse-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = read_http(&mut stream).unwrap();
            let text = String::from_utf8_lossy(&request.body);
            let marker = "\"content\":\"";
            let start = text.find(marker).unwrap() + marker.len();
            let end = start + text[start..].find('"').unwrap();
            let content = &text[start..end];
            let at = content.find("h1_").unwrap();
            let cut = at + "h1_".len();
            let left = &content[..cut];
            let right = &content[cut..];
            let sse = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{left}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"{right}\"}}}}]}}\n\ndata: [DONE]\n\n"
            );
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sse}",
                sse.len()
            );
            let _ = stream.write_all(raw.as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            br#"{"model":"local","messages":[{"role":"user","content":"ada@example.com"}]}"#,
        ));
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert_eq!(response.matches("ada@example.com").count(), 1, "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        assert!(response.contains("data: [DONE]"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_token_split_across_streamed_tool_arguments_is_restored() {
        let dir =
            std::env::temp_dir().join(format!("hushid-proxy-sse-args-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = read_http(&mut stream).unwrap();
            let text = String::from_utf8_lossy(&request.body);
            let marker = "\"content\":\"";
            let start = text.find(marker).unwrap() + marker.len();
            let end = start + text[start..].find('"').unwrap();
            let content = &text[start..end];
            let at = content.find("h1_").unwrap();
            let cut = at + "h1_".len();
            let left = &content[..cut];
            let right = &content[cut..];
            let sse = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{left}\"}}}}]}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{right}\"}}}}]}}}}]}}\n\ndata: [DONE]\n\n"
            );
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sse}",
                sse.len()
            );
            let _ = stream.write_all(raw.as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            br#"{"model":"local","messages":[{"role":"user","content":"ada@example.com"}]}"#,
        ));
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert_eq!(response.matches("ada@example.com").count(), 1, "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        assert!(response.contains("data: [DONE]"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_token_split_across_three_stream_deltas_is_restored() {
        let dir =
            std::env::temp_dir().join(format!("hushid-proxy-sse-split3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = read_http(&mut stream).unwrap();
            let text = String::from_utf8_lossy(&request.body);
            let marker = "\"content\":\"";
            let start = text.find(marker).unwrap() + marker.len();
            let end = start + text[start..].find('"').unwrap();
            let content = &text[start..end];
            let at = content.find("h1_").unwrap();
            let kind = "h1_email_";
            assert!(content[at..].starts_with(kind), "{content}");
            let mid = at + kind.len();
            let left = &content[..at + "h1_".len()];
            let middle = &content[at + "h1_".len()..mid];
            let right = &content[mid..];
            let sse = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{left}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"{middle}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"{right}\"}}}}]}}\n\ndata: [DONE]\n\n"
            );
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sse}",
                sse.len()
            );
            let _ = stream.write_all(raw.as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            br#"{"model":"local","messages":[{"role":"user","content":"ada@example.com"}]}"#,
        ));
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert!(!response.contains("{\"error\":\"restore\"}"), "{response}");
        assert_eq!(response.matches("ada@example.com").count(), 1, "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        assert!(response.contains("data: [DONE]"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_token_split_across_three_streamed_tool_arguments_is_restored() {
        let dir =
            std::env::temp_dir().join(format!("hushid-proxy-sse-args3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = read_http(&mut stream).unwrap();
            let text = String::from_utf8_lossy(&request.body);
            let marker = "\"content\":\"";
            let start = text.find(marker).unwrap() + marker.len();
            let end = start + text[start..].find('"').unwrap();
            let content = &text[start..end];
            let at = content.find("h1_").unwrap();
            let kind = "h1_email_";
            assert!(content[at..].starts_with(kind), "{content}");
            let mid = at + kind.len();
            let left = &content[..at + "h1_".len()];
            let middle = &content[at + "h1_".len()..mid];
            let right = &content[mid..];
            let sse = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{left}\"}}}}]}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{middle}\"}}}}]}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{right}\"}}}}]}}}}]}}\n\ndata: [DONE]\n\n"
            );
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sse}",
                sse.len()
            );
            let _ = stream.write_all(raw.as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            br#"{"model":"local","messages":[{"role":"user","content":"ada@example.com"}]}"#,
        ));
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert!(!response.contains("{\"error\":\"restore\"}"), "{response}");
        assert_eq!(response.matches("ada@example.com").count(), 1, "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        assert!(response.contains("data: [DONE]"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn streamed_argument_pieces_that_are_not_a_token_stay_apart() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"reach\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1_score\"}}]}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let vault = Vault::new();
        let joined = reassemble_streamed_deltas(body, &vault);
        let restored = restore_chat(&joined, &vault).expect(&joined);
        assert!(restored.contains("reach"), "{restored}");
        assert!(restored.contains("1_score"), "{restored}");
        assert!(!restored.contains("h1_"), "{restored}");
    }

    #[test]
    fn a_split_token_this_vault_did_not_mint_stays_an_error() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"h1_\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"email_AAAAAAAAA\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let vault = Vault::new();
        let joined = reassemble_streamed_deltas(body, &vault);
        assert!(restore_chat(&joined, &vault).is_err(), "{joined}");
        assert!(joined.contains("data: [DONE]"), "{joined}");
    }

    #[test]
    fn a_bad_escape_before_a_non_ascii_byte_does_not_panic() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"\\\u{00e9}\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"tail\"}}]}\n\n"
        );
        let vault = Vault::new();
        let joined = reassemble_streamed_deltas(body, &vault);
        let _ = restore_chat(&joined, &vault);
        assert!(joined.contains("tail"), "{joined}");
    }

    #[test]
    fn a_trailing_h_is_not_glued_onto_the_next_delta() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"reach\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"1_score\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let vault = Vault::new();
        let joined = reassemble_streamed_deltas(body, &vault);
        let restored = restore_chat(&joined, &vault).expect(&joined);
        assert!(restored.contains("reach"), "{restored}");
        assert!(restored.contains("1_score"), "{restored}");
        assert!(!restored.contains("h1_"), "{restored}");
    }

    #[test]
    fn a_token_split_into_four_stream_deltas_is_restored() {
        let mut vault = Vault::new();
        let (token, _) =
            hushid::shield_text(&mut vault, &Glossary::empty(), "ada@example.com").unwrap();
        let kind = "h1_email_";
        assert!(token.starts_with(kind), "{token}");
        let parts = [
            &token[..1],
            &token[1..3],
            &token[3..kind.len()],
            &token[kind.len()..],
        ];
        let mut body = String::new();
        for (index, part) in parts.iter().enumerate() {
            let text = if index == 0 {
                format!("Note {part}")
            } else {
                (*part).to_string()
            };
            body.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{text}\"}}}}]}}\n\n"
            ));
        }
        body.push_str("data: [DONE]\n\n");
        let joined = reassemble_streamed_deltas(&body, &vault);
        let restored = restore_chat(&joined, &vault).expect(&joined);
        assert!(restored.contains("Note "), "{restored}");
        assert_eq!(restored.matches("ada@example.com").count(), 1, "{restored}");
        assert!(!restored.contains("h1_email_"), "{restored}");
        assert!(restored.contains("data: [DONE]"), "{restored}");
    }

    #[test]
    fn an_empty_stream_delta_between_token_pieces_is_restored() {
        let mut vault = Vault::new();
        let (token, _) =
            hushid::shield_text(&mut vault, &Glossary::empty(), "ada@example.com").unwrap();
        let kind = "h1_email_";
        assert!(token.starts_with(kind), "{token}");
        let left = &token[.."h1_".len()];
        let middle = &token["h1_".len()..kind.len()];
        let right = &token[kind.len()..];
        let body = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{left}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"\"}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"{middle}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"{right}\"}}}}]}}\n\ndata: [DONE]\n\n"
        );
        let joined = reassemble_streamed_deltas(&body, &vault);
        let restored = restore_chat(&joined, &vault).expect(&joined);
        assert_eq!(restored.matches("ada@example.com").count(), 1, "{restored}");
        assert!(!restored.contains("h1_email_"), "{restored}");
    }

    #[test]
    fn three_stream_pieces_that_are_not_a_token_stay_apart() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"h1_\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"email_\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"nope\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let vault = Vault::new();
        let joined = reassemble_streamed_deltas(body, &vault);
        assert!(joined.contains("\"content\":\"h1_\""), "{joined}");
        assert!(joined.contains("\"content\":\"email_\""), "{joined}");
        assert!(joined.contains("\"content\":\"nope\""), "{joined}");
        assert!(joined.contains("data: [DONE]"), "{joined}");
    }

    #[test]
    fn an_empty_content_type_stays_json() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-type-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = read_http(&mut stream);
            let raw = b"HTTP/1.1 200 OK\r\nContent-Type:\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
            let _ = stream.write_all(raw);
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            b"{}",
        ));
        assert!(
            response.contains("Content-Type: application/json\r\n"),
            "{response}"
        );
        assert!(response.contains("{\"ok\":true}"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rate_limit_keeps_its_reason_and_restores_the_email() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-429-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = read_http(&mut stream).unwrap();
            let text = String::from_utf8_lossy(&request.body);
            let marker = "\"content\":\"";
            let start = text.find(marker).unwrap() + marker.len();
            let end = start + text[start..].find('"').unwrap();
            let content = &text[start..end];
            let body =
                format!("{{\"error\":{{\"message\":\"rate limit while reading {content}\"}}}}");
            let raw = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(raw.as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            br#"{"model":"local","messages":[{"role":"user","content":"Write ada@example.com"}]}"#,
        ));
        assert!(
            response.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
            "{response}"
        );
        assert!(response.contains("ada@example.com"), "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_token_in_the_reply_is_not_forwarded() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = read_http(&mut stream);
            let body = br#"{"completion":"h1_email_AAAAAAAAR"}"#;
            let _ = stream.write_all(http_response(200, body).as_bytes());
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            b"{}",
        ));
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(response.contains("restore"), "{response}");
        assert!(!response.contains("h1_email_"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readers_refuse_a_broken_frame_and_a_body_past_the_cap() {
        assert!(read_http(&mut Cursor::new(b"")).is_err());
        assert!(read_http(&mut Cursor::new(b"GET /\xff HTTP/1.1\r\n\r\n")).is_err());
        assert!(read_http(&mut Cursor::new(
            b"POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n"
        ))
        .is_err());
        let empty = read_http(&mut Cursor::new(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ))
        .unwrap();
        assert!(empty.body.is_empty());
        let huge = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(read_http(&mut Cursor::new(huge.into_bytes())).is_err());
        assert!(read_until_close(&mut Cursor::new(Vec::new()), vec![0; MAX_BODY + 1]).is_err());
        let mut flood = Cursor::new(vec![b'a'; MAX_BODY + 64]);
        assert!(read_until_close(&mut flood, Vec::new()).is_err());
        assert!(decode_chunked(&mut Cursor::new(Vec::new()), &[b'A'; 65]).is_err());
        assert!(decode_chunked(&mut Cursor::new(b"zz\r\n"), b"").is_err());
        assert!(decode_chunked(&mut Cursor::new(Vec::new()), b"1\r\n").is_err());
        assert!(decode_chunked(&mut Cursor::new(Vec::new()), b"1\r\nXQQ").is_err());
        assert!(decode_chunked(&mut Cursor::new(Vec::new()), b"100001\r\n").is_err());
        let mut raw = Vec::new();
        let mut filled = MAX_BODY + 64;
        assert!(read_more(&mut Cursor::new([1u8]), &mut raw, &mut filled).is_err());
        let mut stream = Mem {
            inbound: Cursor::new(b"HTTP/1.1 nope\r\nContent-Length: 0\r\n\r\n".to_vec()),
            outbound: Vec::new(),
        };
        assert!(exchange(
            &mut stream,
            "/v1/chat/completions",
            "host:80",
            "{}",
            Some("Bearer z")
        )
        .is_err());
        assert!(String::from_utf8(stream.outbound)
            .unwrap()
            .contains("Authorization"));
    }

    #[test]
    fn mcp_methods_and_string_escapes_round_trip() {
        let dir = std::env::temp_dir().join(format!("hushid-mcp-edge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let glossary = Glossary::empty();
        let ping = mcp_message(&dir, &glossary, r#"{"jsonrpc":"2.0","method":"ping"}"#).unwrap();
        assert!(ping.contains("result"), "{ping}");
        let unknown = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#,
        )
        .unwrap();
        assert!(unknown.contains("method"), "{unknown}");
        let listed = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        )
        .unwrap();
        assert!(listed.contains("shield"), "{listed}");
        let tool = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"other","arguments":{"session":"demo","text":"hi"}}}"#,
        )
        .unwrap();
        assert!(tool.contains("tool"), "{tool}");
        let emoji = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"\uD83D\uDE00"}}}"#,
        )
        .unwrap();
        assert!(emoji.contains("😀") || emoji.contains("\\ud83d"), "{emoji}");
        let escapes = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"\"\\\b\f\r\/"}}}"#,
        )
        .unwrap();
        assert!(escapes.contains("\\u0008"), "{escapes}");
        assert!(escapes.contains("\\u000c"), "{escapes}");
        assert!(escapes.contains("\\r/"), "{escapes}");
        assert!(escapes.contains("\\\""), "{escapes}");
        assert!(escapes.contains("\\\\"), "{escapes}");
        assert!(!escapes.contains("isError"), "{escapes}");
        assert!(decode_json_string(r#"\q"#).is_err());
        assert!(decode_json_string(r#"\uD800\uD800"#).is_err());
        assert!(decode_json_string(r#"\"#).is_err());
        assert_eq!(decode_json_string(r#"\uD83D\uDE00"#).unwrap(), "😀");
        let bad_method = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":9,"method":"\uDC00"}"#,
        );
        let bad_method = bad_method.expect("a bad method still answers");
        assert!(bad_method.contains("escape"), "{bad_method}");
        let bad_name = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"\q","arguments":{"session":"demo","text":"hi"}}}"#,
        )
        .unwrap();
        assert!(bad_name.contains("escape"), "{bad_name}");
        assert!(!bad_name.contains("\"tool\""), "{bad_name}");
        let bad_session = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"shield","arguments":{"session":"\q","text":"hi"}}}"#,
        )
        .unwrap();
        assert!(bad_session.contains("escape"), "{bad_session}");
        assert!(!bad_session.contains("\"session\""), "{bad_session}");
        let bad_text = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"\q"}}}"#,
        )
        .unwrap();
        assert!(bad_text.contains("escape"), "{bad_text}");
        assert!(!bad_text.contains("\"text\":\"text\""), "{bad_text}");
        assert!(decode_json_string(r#"\uDC00"#).is_err());
        assert!(decode_json_string(r#"\uZZZZ"#).is_err());
        assert!(decode_json_string("\u{0001}").is_err());
        assert!(json_raw_field(r#"{"a":"unterminated}"#, "a").is_none());
        assert!(json_raw_field(r#"{"a":{"b":1"#, "a").is_none());
        assert!(json_object_field(r#"{"arguments":"no"}"#, "arguments").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dropped_client_is_body_and_a_failed_write_is_upstream() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-serve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let proxy =
            Proxy::bind("127.0.0.1:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
        let addr = proxy.local_addr().unwrap();
        let handle = thread::spawn(move || proxy.serve_one());
        let client = TcpStream::connect(addr).unwrap();
        drop(client);
        let err = handle.join().unwrap().unwrap_err();
        assert_eq!(err.to_string(), "body", "{err}");

        struct FailSecond {
            writes: usize,
        }
        impl Read for FailSecond {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        impl Write for FailSecond {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                if self.writes > 1 {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
                } else {
                    Ok(buf.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        match exchange(
            &mut FailSecond { writes: 0 },
            "/v1/chat/completions",
            "host:80",
            "{}",
            None,
        ) {
            Err(err) => assert_eq!(err.to_string(), "upstream"),
            Ok(_) => panic!("a failed upstream write was accepted"),
        }
        assert!(completions_url("http://?x=1").is_err());
        assert!(decode_chunked(&mut Cursor::new(Vec::new()), b"5").is_err());
        assert!(decode_chunked(&mut Cursor::new(Vec::new()), b"\xff\r\n").is_err());
        let mut flood = vec![b'A'; MAX_BODY + 8];
        assert!(read_http(&mut Cursor::new(flood.as_mut_slice())).is_err());
        let upstream = spawn_upstream(b"{\"ok\":true}").unwrap();
        let reply = forward(&upstream, "{}", None).unwrap();
        assert_eq!(reply.status, 200);
        assert!(reply.body.windows(2).any(|window| window == b"ok"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_vault_is_not_a_bad_session() {
        let dir = std::env::temp_dir().join(format!("hushid-proxy-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("demo.vault"), "not-a-vault\n").unwrap();
        let proxy =
            Proxy::bind("127.0.0.1:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "demo")],
            b"{}",
        ));
        assert!(response.starts_with("HTTP/1.1 500"), "{response}");
        assert!(response.contains("vault"), "{response}");
        assert!(!response.contains("bad session"), "{response}");
        let bad = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[("X-Hushid-Session", "bad/id")],
            b"{}",
        ));
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
        assert!(bad.contains("bad session"), "{bad}");
        let glossary = Glossary::empty();
        let vault_text = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shield","arguments":{"session":"demo","text":"hi"}}}"#,
        )
        .expect("mcp reply");
        assert!(vault_text.contains("\"vault\""), "{vault_text}");
        assert!(!vault_text.contains("bad session"), "{vault_text}");
        let session_text = mcp_message(
            &dir,
            &glossary,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shield","arguments":{"session":"bad/id","text":"hi"}}}"#,
        )
        .expect("mcp reply");
        assert!(session_text.contains("\"session\""), "{session_text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_chunked_request_is_shielded() {
        let dir = std::env::temp_dir().join(format!(
            "hushid-proxy-chunk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let Ok((mut stream, _)) = upstream.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(read) = stream.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n")
                else {
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
            let _ = tx.send(buf);
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        });
        let proxy = Proxy::bind(
            "127.0.0.1:0",
            &format!("http://127.0.0.1:{port}"),
            &dir,
            Glossary::empty(),
        )
        .unwrap();
        let addr = proxy.local_addr().unwrap();
        let serve = thread::spawn(move || proxy.serve_one());
        let json = br#"{"a":"ada@example.com"}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nX-Hushid-Session: demo\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
            json.len(),
            std::str::from_utf8(json).unwrap()
        );
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("ok"), "{response}");
        assert!(!response.contains("ada@example.com"), "{response}");
        let forwarded_bytes = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded_bytes);
        assert!(forwarded.contains("h1_email_"), "{forwarded}");
        assert!(!forwarded.contains("ada@example.com"), "{forwarded}");
        assert!(serve.join().unwrap().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_invalid_chunked_request_is_http_400() {
        let dir = std::env::temp_dir().join(format!(
            "hushid-proxy-bad-chunk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let proxy =
            Proxy::bind("127.0.0.1:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
        let addr = proxy.local_addr().unwrap();
        let serve = thread::spawn(move || proxy.serve_one());
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\xff\r\n",
            )
            .unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("\"body\""), "{response}");
        assert!(!response.contains("upstream"), "{response}");
        assert!(serve.join().unwrap().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_length_is_http_400_and_the_process_stays_up() {
        let dir = std::env::temp_dir().join(format!(
            "hushid-proxy-bad-length-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let proxy =
            Proxy::bind("127.0.0.1:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
        let addr = proxy.local_addr().unwrap();
        let serve = thread::spawn(move || proxy.serve_one());
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\nContent-Length: no\r\n\r\n",
            )
            .unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("\"length\""), "{response}");
        assert!(!response.contains("upstream"), "{response}");
        assert!(serve.join().unwrap().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newline_in_authorization_is_headers_not_upstream() {
        let dir = std::env::temp_dir().join(format!(
            "hushid-proxy-auth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let proxy =
            Proxy::bind("127.0.0.1:0", "http://127.0.0.1:9", &dir, Glossary::empty()).unwrap();
        let response = proxy.handle(&request(
            "POST",
            "/v1/chat/completions",
            &[
                ("x-hushid-session", "demo"),
                ("authorization", "Bearer a\nX: y"),
            ],
            b"{}",
        ));
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("\"headers\""), "{response}");
        assert!(!response.contains("upstream"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
