//! The ICC profile reader.

use crate::error::Result;
use crate::profile::{IccProfile, decode_entry, read_profile_index};
use crate::{Signature, TagData};

/// Reader for an ICC profile, with parse options.
///
/// `IccReader::new().parse(bytes)` is equivalent to [`IccProfile::parse`]. Enable
/// [`strict`](IccReader::strict) to additionally reject non-conformant inputs that the lenient
/// default tolerates (nonzero reserved header bytes; tags whose data overlaps the header or tag
/// table).
#[derive(Debug, Clone, Default)]
pub struct IccReader {
    strict: bool,
}

impl IccReader {
    /// A reader with lenient parsing (the default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to reject non-conformant inputs in addition to malformed ones.
    #[must_use]
    pub fn strict(mut self, yes: bool) -> Self {
        self.strict = yes;
        self
    }

    /// Parses an ICC profile from its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IccError::Malformed`](crate::IccError::Malformed) if the profile is malformed, or
    /// — in strict mode — non-conformant.
    pub fn parse(&self, bytes: &[u8]) -> Result<IccProfile> {
        IccProfile::parse_with(bytes, self.strict)
    }

    /// Decode one tag after validating the profile header and tag table.
    /// Other tag payloads are not decoded. This does not validate the complete profile.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid header, table or selected tag. Strict mode
    /// also rejects reserved header bytes and a selected tag overlapping the table.
    pub fn read_tag(
        &self,
        bytes: &[u8],
        signature: impl Into<Signature>,
    ) -> Result<Option<TagData>> {
        let (_, entries) = read_profile_index(bytes, self.strict)?;
        let data_start = crate::tags::tag_table_end(entries.len());
        let signature = signature.into();
        entries
            .into_iter()
            .find(|entry| entry.signature == signature)
            .map(|entry| decode_entry(bytes, entry, self.strict, data_start))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indexed_tags() -> Vec<u8> {
        let mut bytes = vec![0; 156];
        bytes[12..16].copy_from_slice(b"mntr");
        bytes[16..20].copy_from_slice(b"RGB ");
        bytes[20..24].copy_from_slice(b"XYZ ");
        bytes[36..40].copy_from_slice(b"acsp");
        bytes[128..132].copy_from_slice(&2u32.to_be_bytes());
        bytes[132..136].copy_from_slice(b"cprt");
        bytes[136..140].copy_from_slice(&156u32.to_be_bytes());
        bytes[140..144].copy_from_slice(&12u32.to_be_bytes());
        bytes[144..148].copy_from_slice(b"desc");
        bytes[148..152].copy_from_slice(&168u32.to_be_bytes());
        bytes[152..156].copy_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(b"text\0\0\0\0yes\0desc\0\0\0\0");
        bytes
    }

    #[test]
    fn read_tag_is_independent_of_other_payload_errors() {
        let bytes = indexed_tags();
        let reader = IccReader::new();
        assert!(reader.parse(&bytes).is_err());
        assert!(matches!(
            reader.read_tag(&bytes, *b"cprt").unwrap(),
            Some(TagData::Text(_))
        ));
        assert!(reader.read_tag(&bytes, *b"desc").is_err());
        assert!(reader.read_tag(&bytes, *b"A2B1").unwrap().is_none());
    }

    #[test]
    fn read_tag_enforces_index_and_selected_payload_bounds() {
        let reader = IccReader::new();
        let bytes = indexed_tags();
        assert!(reader.read_tag(&bytes[..150], *b"cprt").is_err());
        assert!(reader.read_tag(&bytes[..160], *b"cprt").is_err());
        let mut duplicate = bytes.clone();
        duplicate[144..148].copy_from_slice(b"cprt");
        assert!(reader.read_tag(&duplicate, *b"cprt").is_err());
        let mut reserved = bytes;
        reserved[100] = 1;
        assert!(reader.read_tag(&reserved, *b"cprt").is_ok());
        assert!(reader.strict(true).read_tag(&reserved, *b"cprt").is_err());
    }
}
