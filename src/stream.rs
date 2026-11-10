use crate::sink::{judge, Judgment};
use crate::token::{
    is_hold_symbol, parse_token_at, secret_mark_at, Kind, PAYLOAD_LEN, SECRET_MARK,
};
use crate::vault::Vault;
use std::sync::LazyLock;

/// Holds a suffix that can still grow into an `h1_` token.
///
/// A trailing `h` or `h1` is held too, so a token split across chunks
/// stays in one piece. `finish` releases whatever is left, complete or not.
#[derive(Clone, Debug, Default)]
pub struct HeldStream {
    buf: String,
}

impl HeldStream {
    pub fn new() -> Self {
        Self { buf: String::new() }
    }

    pub fn push(&mut self, chunk: &str) -> String {
        self.buf.push_str(chunk);
        let hold = hold_len(&self.buf);
        let split = self.buf.len() - hold;
        debug_assert!(self.buf.is_char_boundary(split));
        let emit = self.buf[..split].to_string();
        self.buf.drain(..split);
        emit
    }

    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.buf)
    }

    pub fn push_restore(&mut self, chunk: &str, vault: &Vault) -> String {
        let stable = self.push(chunk);
        vault.restore_display(&stable)
    }

    pub fn finish_restore(&mut self, vault: &Vault) -> String {
        let tail = self.finish();
        vault.restore_display(&tail)
    }
}

/// Tool-argument deltas stay buffered until the host calls [`ArgumentBuffer::judge`].
#[derive(Clone, Debug, Default)]
pub struct ArgumentBuffer {
    text: String,
}

impl ArgumentBuffer {
    pub fn new() -> Self {
        Self {
            text: String::new(),
        }
    }

    pub fn push(&mut self, delta: &str) {
        self.text.push_str(delta);
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn judge(&self, name: &str, mcp: bool, vault: &Vault) -> Judgment {
        judge(vault, name, &self.text, mcp)
    }
}

fn hold_len(text: &str) -> usize {
    // A finished token can end in `H` or `H1`. Those bytes also start `h1_`.
    // Consume the finished span first. Holding that tail emits the token
    // without its check character, so restore cannot put the bytes back.
    let mut index = 0;
    while index < text.len() {
        if let Some(end) = secret_mark_at(text, index) {
            index = end;
            continue;
        }
        if let Some(parsed) = parse_token_at(text, index) {
            index = parsed.end;
            continue;
        }
        if is_incomplete_prefix(&text[index..]) {
            return text.len() - index;
        }
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        index += ch.len_utf8();
    }
    0
}

fn is_incomplete_prefix(suffix: &str) -> bool {
    // Only the first token's worth of bytes can still be incomplete.
    // Lowercasing the whole suffix at every byte makes one large chunk
    // quadratic. A longer body is not this prefix.
    let mut end = peek_limit().min(suffix.len());
    while end > 0 && !suffix.is_char_boundary(end) {
        end -= 1;
    }
    let lower = suffix[..end].to_ascii_lowercase();
    if lower == SECRET_MARK {
        return false;
    }
    if SECRET_MARK.starts_with(&lower) {
        return true;
    }
    for head in HEADS.iter() {
        if head.starts_with(&lower) && lower.len() < head.len() {
            return true;
        }
        if let Some(rest) = lower.strip_prefix(head.as_str()) {
            return rest.len() < PAYLOAD_LEN + 1 && rest.bytes().all(is_hold_symbol);
        }
    }
    false
}

fn peek_limit() -> usize {
    let longest_head = HEADS.iter().map(String::len).max().unwrap_or(0);
    longest_head.max(SECRET_MARK.len()) + PAYLOAD_LEN + 1 + 1
}

static HEADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    [
        Kind::Email,
        Kind::Phone,
        Kind::Card,
        Kind::Sin,
        Kind::Ramq,
        Kind::Postal,
        Kind::Address,
        Kind::Birth,
        Kind::Glossary,
    ]
    .into_iter()
    .map(|kind| format!("h1_{}_", kind.as_str()))
    .collect()
});
