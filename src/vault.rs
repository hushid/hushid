use crate::token::{
    find_h1, format_token, parse_token_at, random_token, secret_mark_at, Kind, TokenError,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

const HEADER: &str = "hushid-vault 1";

/// Maps a canonical token to the exact surface bytes.
///
/// Loading a missing file is an error. This type has no method that
/// rebuilds the map by scanning a clear transcript.
#[derive(Clone)]
struct Entry {
    surface: Vec<u8>,
    /// The surface was a JSON number. Restore writes it back without quotes.
    json_number: bool,
}

#[derive(Clone)]
pub struct Vault {
    entries: BTreeMap<String, Entry>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum VaultError {
    Missing,
    Corrupt,
    Io(io::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Missing => write!(f, "vault file is missing"),
            VaultError::Corrupt => write!(f, "vault file is corrupt"),
            VaultError::Io(err) => write!(f, "vault file error: {err}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::NotFound {
            VaultError::Missing
        } else {
            VaultError::Io(err)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    Unresolved { at: usize },
    SecretMark { at: usize },
    NotUtf8 { at: usize },
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoreError::Unresolved { at } => write!(f, "unresolved h1_ token at byte {at}"),
            RestoreError::SecretMark { at } => write!(f, "secret mark remains at byte {at}"),
            RestoreError::NotUtf8 { at } => write!(f, "vault surface is not utf-8 at byte {at}"),
        }
    }
}

impl std::error::Error for RestoreError {}

impl Vault {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn issue(&mut self, kind: Kind, surface: &[u8]) -> Result<String, TokenError> {
        self.insert(kind, surface, false)
    }

    pub(crate) fn issue_json_number(
        &mut self,
        kind: Kind,
        surface: &[u8],
    ) -> Result<String, TokenError> {
        self.insert(kind, surface, true)
    }

    fn insert(
        &mut self,
        kind: Kind,
        surface: &[u8],
        json_number: bool,
    ) -> Result<String, TokenError> {
        let token = random_token(kind)?;
        self.entries.insert(
            token.clone(),
            Entry {
                surface: surface.to_vec(),
                json_number,
            },
        );
        Ok(token)
    }

    /// Insert a caller-chosen payload. Tests and hosts use this when the
    /// payload must be stable. A second call with the same canonical token
    /// keeps the first surface.
    pub fn issue_payload(
        &mut self,
        kind: Kind,
        payload: &str,
        surface: &[u8],
    ) -> Result<String, TokenError> {
        let token = format_token(kind, payload)?;
        self.entries.entry(token.clone()).or_insert_with(|| Entry {
            surface: surface.to_vec(),
            json_number: false,
        });
        Ok(token)
    }

    pub fn get(&self, token: &str) -> Option<&[u8]> {
        let parsed = parse_token_at(token, 0)?;
        if parsed.end != token.len() || !parsed.check_ok {
            return None;
        }
        self.entries
            .get(&parsed.canonical)
            .map(|entry| entry.surface.as_slice())
    }

    pub(crate) fn is_json_number_token(&self, token: &str) -> bool {
        let Some(parsed) = parse_token_at(token, 0) else {
            return false;
        };
        if parsed.end != token.len() || !parsed.check_ok {
            return false;
        }
        self.entries
            .get(&parsed.canonical)
            .is_some_and(|entry| entry.json_number)
    }

    pub fn holds_surface(&self, bytes: &[u8]) -> bool {
        self.entries.values().any(|entry| entry.surface == bytes)
    }

    pub fn restore_display(&self, text: &str) -> String {
        match walk(text, self, false) {
            Ok(restored) => restored,
            Err(_) => text.to_string(),
        }
    }

    pub fn restore_write(&self, text: &str) -> Result<String, RestoreError> {
        walk(text, self, true)
    }

    /// Write the map to `path` as mode `0600` on Unix.
    /// The host leaves this file out of support bundles and share exports.
    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let mut body = String::from(HEADER);
        body.push('\n');
        for (token, entry) in &self.entries {
            body.push_str(token);
            body.push(' ');
            body.push_str(&hex_encode(&entry.surface));
            if entry.json_number {
                body.push_str(" n");
            }
            body.push('\n');
        }
        write_private(path, body.as_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let text = fs::read_to_string(path)?;
        let mut lines = text.lines();
        let header = lines.next().ok_or(VaultError::Corrupt)?;
        if header != HEADER {
            return Err(VaultError::Corrupt);
        }
        let mut entries = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split(' ');
            let token = parts.next().ok_or(VaultError::Corrupt)?;
            let hex = parts.next().ok_or(VaultError::Corrupt)?;
            let json_number = match parts.next() {
                None => false,
                Some("n") => true,
                Some(_) => return Err(VaultError::Corrupt),
            };
            if parts.next().is_some() {
                return Err(VaultError::Corrupt);
            }
            let parsed = parse_token_at(token, 0).ok_or(VaultError::Corrupt)?;
            if parsed.end != token.len() || !parsed.check_ok || parsed.canonical != token {
                return Err(VaultError::Corrupt);
            }
            let surface = hex_decode(hex).ok_or(VaultError::Corrupt)?;
            entries.insert(
                token.to_string(),
                Entry {
                    surface,
                    json_number,
                },
            );
        }
        Ok(Self { entries })
    }
}

fn walk(text: &str, vault: &Vault, strict: bool) -> Result<String, RestoreError> {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        let Some(at) = find_h1(text, index) else {
            out.push_str(&text[index..]);
            break;
        };
        out.push_str(&text[index..at]);
        if let Some(end) = secret_mark_at(text, at) {
            if strict {
                return Err(RestoreError::SecretMark { at });
            }
            out.push_str(&text[at..end]);
            index = end;
            continue;
        }
        if let Some(parsed) = parse_token_at(text, at) {
            if parsed.check_ok {
                if let Some(entry) = vault.entries.get(&parsed.canonical) {
                    let surface = std::str::from_utf8(&entry.surface)
                        .map_err(|_| RestoreError::NotUtf8 { at })?;
                    out.push_str(surface);
                    index = parsed.end;
                    continue;
                }
            }
            if strict {
                return Err(RestoreError::Unresolved { at });
            }
            out.push_str(&text[at..parsed.end]);
            index = parsed.end;
            continue;
        }
        if strict {
            return Err(RestoreError::Unresolved { at });
        }
        out.push_str(&text[at..at + 3]);
        index = at + 3;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_val(bytes[index])?;
        let lo = hex_val(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        // mode() is masked by umask. Set the mode again so the file is 0600.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }
}
