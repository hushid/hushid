use crate::token::Kind;
use std::fmt;

pub const DETECTOR_VERSION: u32 = 1;

/// Counts for one shield call. The record has no original values.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub detector_version: u32,
    pub email: u32,
    pub phone: u32,
    pub card: u32,
    pub sin: u32,
    pub ramq: u32,
    pub postal: u32,
    pub address: u32,
    pub birth: u32,
    pub secret: u32,
    pub glossary: u32,
}

impl Default for AuditRecord {
    fn default() -> Self {
        Self {
            detector_version: DETECTOR_VERSION,
            email: 0,
            phone: 0,
            card: 0,
            sin: 0,
            ramq: 0,
            postal: 0,
            address: 0,
            birth: 0,
            secret: 0,
            glossary: 0,
        }
    }
}

impl AuditRecord {
    pub fn bump(&mut self, kind: Kind) {
        match kind {
            Kind::Email => self.email += 1,
            Kind::Phone => self.phone += 1,
            Kind::Card => self.card += 1,
            Kind::Sin => self.sin += 1,
            Kind::Ramq => self.ramq += 1,
            Kind::Postal => self.postal += 1,
            Kind::Address => self.address += 1,
            Kind::Birth => self.birth += 1,
            Kind::Glossary => self.glossary += 1,
        }
    }

    pub fn merge(&mut self, other: &AuditRecord) {
        self.email += other.email;
        self.phone += other.phone;
        self.card += other.card;
        self.sin += other.sin;
        self.ramq += other.ramq;
        self.postal += other.postal;
        self.address += other.address;
        self.birth += other.birth;
        self.secret += other.secret;
        self.glossary += other.glossary;
    }
}

impl fmt::Debug for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("detector_version", &self.detector_version)
            .field("email", &self.email)
            .field("phone", &self.phone)
            .field("card", &self.card)
            .field("sin", &self.sin)
            .field("ramq", &self.ramq)
            .field("postal", &self.postal)
            .field("address", &self.address)
            .field("birth", &self.birth)
            .field("secret", &self.secret)
            .field("glossary", &self.glossary)
            .finish()
    }
}
