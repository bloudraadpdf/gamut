# gamut-icc-profiles — standard ICC profile catalogue status

This crate is the neutral owner of reusable standard ICC profile assets. It embeds reviewed bytes
and exposes each entry through a typed [`StandardProfile`](src/lib.rs) identity. `gamut-icc` owns
profile parsing and validation. `gamut-cmm` owns colour transforms. Format and document crates own
the policy that selects a profile.

## Catalogue

| Profile | Data colour space | Device class | Status |
| --- | --- | --- | --- |
| sRGB 2014 v2 | RGB | Display | included |
| sGrey v2 magic | Grey | Display | included |
| CGATS21 CRPC6 | CMYK | Output | included |
| ISO Coated v2 ECI | CMYK | Output | included |

The tests pin each asset's encoded checksum, byte length, colour space, device class, and component
count. Asset redistribution notices are in [`assets/LICENSE-ICC.txt`](assets/LICENSE-ICC.txt).

## Boundary

- The crate does not resolve caller-provided strings to profiles.
- The crate does not choose an output intent for a document or image.
- The crate does not parse document containers or apply colour transforms.
