use crate::token::{
    find_h1, format_token, parse_token_at, random_token, secret_mark_at, Kind, TokenError,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

const HEADER: &str = "hushid-vault 1";

/// One issued surface. The map key on [`Vault`] is the canonical token.
#[derive(Clone)]
struct Entry {
    surface: Vec<u8>,
    /// The surface was a JSON number. Restore writes it back without quotes.
    json_number: bool,
    /// Stand-in that appears in the shielded text. The map key stays
    /// the token so an older vault file still loads. Digit and surrogate
    /// stand-ins share this field.
    digits: Option<String>,
}

/// Maps each issued token to the exact surface bytes.
///
/// Loading a missing file is an error. This type has no method that
/// rebuilds the map by scanning a clear transcript.
#[derive(Clone)]
pub struct Vault {
    entries: BTreeMap<String, Entry>,
    /// Stand-in text to the original surface. Restore walks this before `h1_`.
    digits: BTreeMap<String, String>,
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
            RestoreError::NotUtf8 { at } => {
                write!(f, "stored surface for the token at byte {at} is not utf-8")
            }
        }
    }
}

impl std::error::Error for RestoreError {}

impl Vault {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            digits: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn issue(&mut self, kind: Kind, surface: &[u8]) -> Result<String, TokenError> {
        self.insert(kind, surface, false, None)
    }

    pub(crate) fn issue_json_number(
        &mut self,
        kind: Kind,
        surface: &[u8],
    ) -> Result<String, TokenError> {
        self.insert(kind, surface, true, None)
    }

    pub(crate) fn issue_digits(
        &mut self,
        kind: Kind,
        surface: &[u8],
        stand_in: &str,
    ) -> Result<String, TokenError> {
        if stand_in.is_empty() || self.digits.contains_key(stand_in) {
            return Err(TokenError::Digits);
        }
        self.insert(kind, surface, false, Some(stand_in.to_string()))
    }

    fn insert(
        &mut self,
        kind: Kind,
        surface: &[u8],
        json_number: bool,
        digits: Option<String>,
    ) -> Result<String, TokenError> {
        let token = random_token(kind)?;
        if let Some(stand_in) = &digits {
            let text = std::str::from_utf8(surface).map_err(|_| TokenError::Payload)?;
            self.digits.insert(stand_in.clone(), text.to_string());
        }
        let shown = digits.clone().unwrap_or_else(|| token.clone());
        self.entries.insert(
            token,
            Entry {
                surface: surface.to_vec(),
                json_number,
                digits,
            },
        );
        Ok(shown)
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
            digits: None,
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
        write_private(path, self.encode().as_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let text = fs::read_to_string(path)?;
        Self::decode(&text)
    }

    pub(crate) fn known_surfaces(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter_map(|(token, entry)| {
                let text = String::from_utf8(entry.surface.clone()).ok()?;
                Some((token.clone(), text))
            })
            .collect()
    }

    pub(crate) fn encode(&self) -> String {
        let mut body = String::from(HEADER);
        body.push('\n');
        for (token, entry) in &self.entries {
            body.push_str(token);
            body.push(' ');
            body.push_str(&hex_encode(&entry.surface));
            if entry.json_number {
                body.push_str(" n");
            }
            if let Some(stand_in) = &entry.digits {
                body.push_str(" d ");
                body.push_str(&hex_encode(stand_in.as_bytes()));
            }
            body.push('\n');
        }
        body
    }

    pub(crate) fn decode(text: &str) -> Result<Self, VaultError> {
        // Every record ends with a newline. A torn write has no final
        // newline, and an even-length hex fragment would otherwise load
        // as a shorter surface.
        if text.is_empty() || !text.ends_with('\n') {
            return Err(VaultError::Corrupt);
        }
        let mut lines = text.lines();
        let header = lines.next().ok_or(VaultError::Corrupt)?;
        if header != HEADER {
            return Err(VaultError::Corrupt);
        }
        let mut entries = BTreeMap::new();
        let mut digits = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split(' ');
            let token = parts.next().ok_or(VaultError::Corrupt)?;
            let hex = parts.next().ok_or(VaultError::Corrupt)?;
            let mut json_number = false;
            let mut stand_in = None;
            while let Some(flag) = parts.next() {
                match flag {
                    "n" => json_number = true,
                    "d" => {
                        if stand_in.is_some() {
                            return Err(VaultError::Corrupt);
                        }
                        let encoded = parts.next().ok_or(VaultError::Corrupt)?;
                        let bytes = hex_decode(encoded).ok_or(VaultError::Corrupt)?;
                        let text = String::from_utf8(bytes).map_err(|_| VaultError::Corrupt)?;
                        if text.is_empty() {
                            return Err(VaultError::Corrupt);
                        }
                        stand_in = Some(text);
                    }
                    _ => return Err(VaultError::Corrupt),
                }
            }
            let parsed = parse_token_at(token, 0).ok_or(VaultError::Corrupt)?;
            if parsed.end != token.len() || !parsed.check_ok || parsed.canonical != token {
                return Err(VaultError::Corrupt);
            }
            let surface = hex_decode(hex).ok_or(VaultError::Corrupt)?;
            if let Some(stand_in) = &stand_in {
                let text = std::str::from_utf8(&surface).map_err(|_| VaultError::Corrupt)?;
                if digits.insert(stand_in.clone(), text.to_string()).is_some() {
                    return Err(VaultError::Corrupt);
                }
            }
            entries.insert(
                token.to_string(),
                Entry {
                    surface,
                    json_number,
                    digits: stand_in,
                },
            );
        }
        Ok(Self { entries, digits })
    }
}

fn stand_in_bounded(text: &str, start: usize, end: usize) -> bool {
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return false;
    }
    if text[..start]
        .chars()
        .next_back()
        .is_some_and(|ch| ch.is_alphanumeric())
    {
        return false;
    }
    if text[end..]
        .chars()
        .next()
        .is_some_and(|ch| ch.is_alphanumeric())
    {
        return false;
    }
    true
}

fn next_digit(vault: &Vault, text: &str, index: usize) -> Option<usize> {
    let mut best = None;
    for stand_in in vault.digits.keys() {
        let mut from = index;
        while let Some(rest) = text.get(from..) {
            let Some(found) = rest.find(stand_in) else {
                break;
            };
            let at = from + found;
            let end = at + stand_in.len();
            if stand_in_bounded(text, at, end) {
                best = Some(best.map_or(at, |earlier: usize| earlier.min(at)));
                break;
            }
            if end <= from {
                break;
            }
            from = end;
        }
    }
    best
}

fn digit_match<'a>(vault: &'a Vault, text: &str, index: usize) -> Option<(usize, &'a str)> {
    let rest = text.get(index..)?;
    let mut best: Option<(&str, &str)> = None;
    for (stand_in, surface) in &vault.digits {
        let end = index + stand_in.len();
        if rest.starts_with(stand_in) && stand_in_bounded(text, index, end) {
            let longer = best.is_none_or(|(previous, _)| stand_in.len() > previous.len());
            if longer {
                best = Some((stand_in.as_str(), surface.as_str()));
            }
        }
    }
    best.map(|(stand_in, surface)| (index + stand_in.len(), surface))
}

fn walk(text: &str, vault: &Vault, strict: bool) -> Result<String, RestoreError> {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if let Some(digit_at) = next_digit(vault, text, index) {
            let h1_at = find_h1(text, index);
            if h1_at.is_none_or(|at| digit_at < at) {
                out.push_str(&text[index..digit_at]);
                let (end, surface) = digit_match(vault, text, digit_at)
                    .ok_or(RestoreError::Unresolved { at: digit_at })?;
                out.push_str(surface);
                index = end;
                continue;
            }
        }
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
    // Write a new file, then rename it over the vault. Truncating the
    // only copy first drops the map when the write fails or the process
    // stops mid-write.
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault");
    let tmp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    if let Err(err) = write_new_file(&tmp, data) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

fn write_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
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
