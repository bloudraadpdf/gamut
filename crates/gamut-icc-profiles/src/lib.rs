//! Licensed standard ICC profile assets with typed identities.

#![forbid(unsafe_code)]

use gamut_icc::{IccProfileIdentity, Result};

/// A reviewed ICC profile embedded by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandardProfile {
    /// ICC sRGB 2014 v2 monitor profile.
    SrgbV2,
    /// Compact sGrey v2 monitor profile.
    SgreyV2,
    /// CGATS21 CRPC6 v4 CMYK output profile.
    #[cfg(feature = "cmyk")]
    Cgats21Crpc6,
    /// ISO Coated v2 ECI CMYK output profile.
    #[cfg(feature = "cmyk")]
    IsoCoatedV2Eci,
}

impl StandardProfile {
    /// Complete catalogue in stable declaration order.
    pub const ALL: &'static [Self] = &[
        Self::SrgbV2,
        Self::SgreyV2,
        #[cfg(feature = "cmyk")]
        Self::Cgats21Crpc6,
        #[cfg(feature = "cmyk")]
        Self::IsoCoatedV2Eci,
    ];

    /// Resolve a conventional profile name to a catalogue entry.
    ///
    /// The accepted aliases are the names commonly stored in PDF output
    /// intents and colour-management configuration. Matching is ASCII
    /// case-insensitive.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|profile| {
            profile
                .aliases()
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
        })
    }

    /// Conventional names that resolve to this profile.
    const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::SrgbV2 => &["sRGB IEC61966-2.1", "sRGB"],
            Self::SgreyV2 => &["sGrey-v2-magic", "sGrey"],
            #[cfg(feature = "cmyk")]
            Self::Cgats21Crpc6 => &["CGATS21_CRPC6", "CGATS21 CRPC6"],
            #[cfg(feature = "cmyk")]
            Self::IsoCoatedV2Eci => &[
                "ISOcoated_v2_eci",
                "ISO Coated v2 ECI",
                "Coated FOGRA39 ICC v2",
            ],
        }
    }

    /// Stable canonical profile name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SrgbV2 => "sRGB IEC61966-2.1",
            Self::SgreyV2 => "sGrey-v2-magic",
            #[cfg(feature = "cmyk")]
            Self::Cgats21Crpc6 => "CGATS21_CRPC6",
            #[cfg(feature = "cmyk")]
            Self::IsoCoatedV2Eci => "ISOcoated_v2_eci",
        }
    }

    /// Exact encoded ICC profile bytes.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::SrgbV2 => include_bytes!("../assets/sRGB2014.icc"),
            Self::SgreyV2 => include_bytes!("../assets/sGrey-v2-magic.icc"),
            #[cfg(feature = "cmyk")]
            Self::Cgats21Crpc6 => include_bytes!("../assets/CGATS21_CRPC6.icc"),
            #[cfg(feature = "cmyk")]
            Self::IsoCoatedV2Eci => include_bytes!("../assets/ISOcoated_v2_eci.icc"),
        }
    }

    /// Parsed identity and header facts for this profile.
    ///
    /// # Errors
    ///
    /// Returns an error if a committed profile no longer parses as ICC.
    pub fn identity(self) -> Result<IccProfileIdentity> {
        IccProfileIdentity::from_bytes(self.bytes())
    }
}

#[cfg(test)]
mod tests {
    use gamut_icc::{ColorSpace, DeviceClass, ProfileId};

    use super::StandardProfile;

    #[test]
    fn catalogue_pins_bytes_and_typed_identity() {
        let expected = [
            (
                StandardProfile::SrgbV2,
                3_024,
                ColorSpace::Rgb,
                DeviceClass::Display,
            ),
            (
                StandardProfile::SgreyV2,
                616,
                ColorSpace::Gray,
                DeviceClass::Display,
            ),
            #[cfg(feature = "cmyk")]
            (
                StandardProfile::Cgats21Crpc6,
                3_462_316,
                ColorSpace::Cmyk,
                DeviceClass::Output,
            ),
            #[cfg(feature = "cmyk")]
            (
                StandardProfile::IsoCoatedV2Eci,
                1_829_077,
                ColorSpace::Cmyk,
                DeviceClass::Output,
            ),
        ];

        for (profile, byte_len, color_space, device_class) in expected {
            let identity = profile.identity().unwrap();
            assert_eq!(profile.bytes().len(), byte_len);
            assert_eq!(identity.data_color_space, color_space);
            assert_eq!(identity.device_class, device_class);
            assert_eq!(identity.component_count(), color_space.channel_count());
        }
    }

    #[test]
    fn catalogue_pins_encoded_checksums() {
        let expected = [
            (StandardProfile::SrgbV2, "3947129e0967089c736f91a2989d89d8"),
            (StandardProfile::SgreyV2, "ef6221686b517e4665480639202dacd5"),
            #[cfg(feature = "cmyk")]
            (
                StandardProfile::Cgats21Crpc6,
                "f788f997cde13840dad9365c9df5eb0f",
            ),
            #[cfg(feature = "cmyk")]
            (
                StandardProfile::IsoCoatedV2Eci,
                "bda07efcacf5377e91edacb0454ea7e5",
            ),
        ];

        for (profile, checksum) in expected {
            assert_eq!(ProfileId::checksum(profile.bytes()).to_string(), checksum);
        }
    }

    #[test]
    fn conventional_names_resolve_to_typed_profiles() {
        let cases = [
            ("sRGB IEC61966-2.1", StandardProfile::SrgbV2),
            ("SRGB", StandardProfile::SrgbV2),
            ("sGrey", StandardProfile::SgreyV2),
            #[cfg(feature = "cmyk")]
            ("CGATS21 CRPC6", StandardProfile::Cgats21Crpc6),
            #[cfg(feature = "cmyk")]
            ("ISO Coated v2 ECI", StandardProfile::IsoCoatedV2Eci),
            #[cfg(feature = "cmyk")]
            ("Coated FOGRA39 ICC v2", StandardProfile::IsoCoatedV2Eci),
        ];

        for (name, expected) in cases {
            assert_eq!(StandardProfile::from_name(name), Some(expected));
        }
        assert_eq!(StandardProfile::from_name("unknown profile"), None);
    }
}
