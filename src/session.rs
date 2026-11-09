use crate::audit::AuditRecord;
use crate::glossary::Glossary;
use crate::shield::shield_text;
use crate::token::TokenError;
use crate::vault::{Vault, VaultError};
use std::fmt;
use std::path::Path;

/// One shielded message. `thinking` is the provider's bytes, unmodified.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub projection: String,
    pub thinking: Option<Vec<u8>>,
}

impl fmt::Debug for StoredMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredMessage")
            .field("projection", &self.projection)
            .field(
                "thinking_len",
                &self.thinking.as_ref().map(|bytes| bytes.len()),
            )
            .finish()
    }
}

/// Shield each new message once. [`Session::replay`] returns those projections.
/// It does not detect the history again.
pub struct Session {
    vault: Vault,
    glossary: Glossary,
    messages: Vec<StoredMessage>,
    audits: Vec<AuditRecord>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("messages", &self.messages.len())
            .field("vault", &self.vault)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError;

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message index is out of range")
    }
}

impl std::error::Error for SessionError {}

impl Session {
    pub fn new(glossary: Glossary) -> Self {
        Self::open(Vault::new(), glossary)
    }

    pub fn open(vault: Vault, glossary: Glossary) -> Self {
        Self {
            vault,
            glossary,
            messages: Vec::new(),
            audits: Vec::new(),
        }
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn audits(&self) -> &[AuditRecord] {
        &self.audits
    }

    pub fn replay(&self) -> &[StoredMessage] {
        &self.messages
    }

    pub fn shield_message(&mut self, text: &str) -> Result<usize, TokenError> {
        let (projection, audit) = shield_text(&mut self.vault, &self.glossary, text)?;
        self.audits.push(audit);
        self.messages.push(StoredMessage {
            projection,
            thinking: None,
        });
        Ok(self.messages.len() - 1)
    }

    /// Store provider thinking bytes. The bytes are not scanned or rewritten.
    pub fn store_thinking(&mut self, index: usize, bytes: &[u8]) -> Result<(), SessionError> {
        let message = self.messages.get_mut(index).ok_or(SessionError)?;
        message.thinking = Some(bytes.to_vec());
        Ok(())
    }

    pub fn save_vault(&self, path: &Path) -> Result<(), VaultError> {
        self.vault.save(path)
    }
}
