//! Typed ICC profile identity.

use crate::{ColorSpace, DeviceClass, IccProfile, ProfileId, ProfileVersion, Result, Signature};

/// Stable identity and header facts for one encoded ICC profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IccProfileIdentity {
    /// Embedded profile ID when present, otherwise the ICC canonical digest.
    pub canonical_id: ProfileId,
    /// MD5 of the encoded profile bytes without header canonicalisation.
    pub checksum: ProfileId,
    /// Profile/device class.
    pub device_class: DeviceClass,
    /// Data colour space.
    pub data_color_space: ColorSpace,
    /// Profile connection space.
    pub pcs: ColorSpace,
    /// Encoded ICC version.
    pub version: ProfileVersion,
}

impl IccProfileIdentity {
    /// Parse an encoded ICC profile and project its stable identity facts.
    ///
    /// # Errors
    ///
    /// Returns an error when [`IccProfile::parse`] rejects the profile.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let profile = IccProfile::parse(bytes)?;
        let header = &profile.header;
        let canonical_id = ProfileId::from_profile_bytes(bytes)?;
        Ok(Self {
            canonical_id,
            checksum: ProfileId::checksum(bytes),
            device_class: header.device_class,
            data_color_space: header.data_color_space,
            pcs: header.pcs,
            version: header.version,
        })
    }

    /// Number of device components represented by the profile.
    #[must_use]
    pub fn component_count(self) -> u8 {
        self.data_color_space.channel_count()
    }

    /// Four-byte ICC device-class signature.
    #[must_use]
    pub fn device_class_signature(self) -> Signature {
        self.device_class.into()
    }

    /// Four-byte ICC data-colour-space signature.
    #[must_use]
    pub fn color_space_signature(self) -> Signature {
        self.data_color_space.into()
    }
}
