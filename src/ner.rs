//! Person names after a title.
//!
//! The default build does not compile this module. The model file is a
//! local ONNX graph. A glossary hit still wins when the spans overlap.
//! A name with no title stays as written. This does not claim that every
//! name is found.

use crate::detect::Hit;
use crate::token::Kind;
use std::fs;
use std::path::Path;

const BUCKETS: usize = 128;
const TITLES: &[&str] = &["M.", "Mme", "Mme.", "Mr.", "Mrs.", "Ms."];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NerError;

impl std::fmt::Display for NerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("name model is not a one-hot Gemm")
    }
}

impl std::error::Error for NerError {}

#[derive(Clone, Debug)]
pub struct Ner {
    weights: Vec<f32>,
    bias: f32,
}

impl Ner {
    pub fn load(path: &Path) -> Result<Self, NerError> {
        let bytes = fs::read(path).map_err(|_| NerError)?;
        let graph = field_bytes(&bytes, 7).ok_or(NerError)?;
        let mut saw_gemm = false;
        let mut weights = None;
        let mut bias = None;
        for (field, payload) in messages(&graph) {
            if field == 1 && field_string(&payload, 4).as_deref() == Some("Gemm") {
                saw_gemm = true;
            }
            if field == 5 {
                let name = field_string(&payload, 8).unwrap_or_default();
                let values = raw_f32(&payload).ok_or(NerError)?;
                if name == "W" {
                    weights = Some(values);
                } else if name == "B" {
                    bias = Some(values);
                }
            }
        }
        let weights = weights.ok_or(NerError)?;
        let bias = bias.ok_or(NerError)?;
        if !saw_gemm || weights.len() != BUCKETS || bias.len() != 1 {
            return Err(NerError);
        }
        Ok(Self {
            weights,
            bias: bias[0],
        })
    }

    pub fn find(&self, text: &str) -> Vec<Hit> {
        let words = words(text);
        let mut hits = Vec::new();
        for pair in words.windows(2) {
            let (title_start, title_end) = pair[0];
            let (name_start, name_end) = pair[1];
            let title = &text[title_start..title_end];
            if !TITLES.iter().any(|cue| cue.eq_ignore_ascii_case(title)) {
                continue;
            }
            let name = &text[name_start..name_end];
            if !person_shape(name) || self.score(name) <= 0.0 {
                continue;
            }
            hits.push(Hit::Reversible {
                kind: Kind::Glossary,
                start: name_start,
                end: name_end,
            });
        }
        hits
    }

    fn score(&self, word: &str) -> f32 {
        let slot = name_bucket(word);
        self.weights[slot] + self.bias
    }
}

fn person_shape(word: &str) -> bool {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_uppercase() && chars.clone().count() >= 1 && chars.all(|ch| ch.is_alphabetic())
}

fn name_bucket(word: &str) -> usize {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in word.bytes() {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash % BUCKETS as u64) as usize
}

fn words(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let start = index;
        while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let mut end = index;
        while end > start {
            let ch = text[start..end].chars().next_back().unwrap();
            if matches!(ch, ',' | ';' | ':' | '!' | '?' | '"' | '\'' | ')') {
                end -= ch.len_utf8();
            } else {
                break;
            }
        }
        if end > start {
            out.push((start, end));
        }
    }
    out
}

fn messages(bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut cursor = Proto::new(bytes);
    while let Some((field, payload)) = cursor.message_field() {
        out.push((field, payload));
    }
    out
}

fn field_bytes(bytes: &[u8], want: u64) -> Option<Vec<u8>> {
    messages(bytes)
        .into_iter()
        .find(|(field, _)| *field == want)
        .map(|(_, payload)| payload)
}

fn field_string(bytes: &[u8], want: u64) -> Option<String> {
    let payload = field_bytes(bytes, want)?;
    String::from_utf8(payload).ok()
}

fn raw_f32(bytes: &[u8]) -> Option<Vec<f32>> {
    let payload = field_bytes(bytes, 9)?;
    if payload.len() % 4 != 0 {
        return None;
    }
    Some(
        payload
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect(),
    )
}

struct Proto<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Proto<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn message_field(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.index >= self.bytes.len() {
            return None;
        }
        let key = self.varint()?;
        let field = key >> 3;
        let wire = key & 7;
        let payload = match wire {
            0 => {
                let value = self.varint()?;
                value.to_le_bytes().to_vec()
            }
            1 => self.take(8)?.to_vec(),
            2 => {
                let len = self.varint()? as usize;
                self.take(len)?.to_vec()
            }
            5 => self.take(4)?.to_vec(),
            _ => return None,
        };
        Some((field, payload))
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.bytes.get(self.index)?;
            self.index += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.index.checked_add(len)?;
        let slice = self.bytes.get(self.index..end)?;
        self.index = end;
        Some(slice)
    }
}
