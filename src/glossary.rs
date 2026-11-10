use regex::Regex;
use std::fs;
use std::io;
use std::path::Path;

/// Words the host wrote down. Matching uses word boundaries and the
/// entry text as written, including case.
#[derive(Clone, Debug)]
pub struct Glossary {
    terms: Vec<String>,
    pattern: Option<Regex>,
}

impl Default for Glossary {
    fn default() -> Self {
        Self::empty()
    }
}

impl Glossary {
    pub fn empty() -> Self {
        Self {
            terms: Vec::new(),
            pattern: None,
        }
    }

    pub fn from_terms<I, S>(terms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let terms = terms
            .into_iter()
            .map(Into::into)
            .map(|term| term.trim().to_string())
            .filter(|term| !term.is_empty())
            .collect::<Vec<_>>();
        Self::from_vec(terms)
    }

    /// One entry per line. Blank lines and `#` comments are skipped.
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Ok(Self::parse(&text))
    }

    /// The published USA, Canada, and Quebec name list, compiled into this crate.
    /// Shielding does not use it unless the host calls this function.
    pub fn popular_names() -> Self {
        Self::parse(include_str!("../glossary/popular-names.txt"))
    }

    fn parse(text: &str) -> Self {
        let mut terms = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            terms.push(line.to_string());
        }
        Self::from_vec(terms)
    }

    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    pub fn find(&self, text: &str) -> Vec<(usize, usize)> {
        let Some(pattern) = &self.pattern else {
            return Vec::new();
        };
        pattern
            .find_iter(text)
            .map(|hit| (hit.start(), hit.end()))
            .collect()
    }

    fn from_vec(terms: Vec<String>) -> Self {
        let pattern = compile(&terms);
        Self { terms, pattern }
    }
}

fn compile(terms: &[String]) -> Option<Regex> {
    if terms.is_empty() {
        return None;
    }
    let mut ordered = terms.to_vec();
    ordered.sort_by_key(|term| std::cmp::Reverse(term.len()));
    let body = ordered
        .iter()
        .map(|term| regex::escape(term))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(r"\b(?:{body})\b");
    Some(Regex::new(&pattern).expect("escaped glossary terms form a valid pattern"))
}
