# gamut-icc-profiles

`gamut-icc-profiles` supplies a typed catalogue of licensed standard ICC profiles. It is the one
asset owner shared by image, PDF, and document-authoring callers. `gamut-icc` parses their identity;
this crate only embeds the exact reviewed bytes and records their redistribution terms.

Callers select a [`StandardProfile`] value or supply their own ICC bytes. The API does not resolve
free-form profile names.

## Features

| Feature | Default | Profiles |
| ------- | ------- | -------- |
| (none)  | —       | `SrgbV2` (3 KB), `SgreyV2` (0.6 KB) |
| `cmyk`  | yes     | `Cgats21Crpc6` (3.5 MB), `IsoCoatedV2Eci` (1.8 MB) |

Without `cmyk`, the CMYK variants do not exist and their bytes are not embedded. A build that must
stay small, such as WebAssembly, disables default features and takes CMYK profiles from its caller.

## Licence

The Rust source is licensed under MIT or Apache-2.0. The embedded profiles retain the terms and
notices in [`assets/LICENSE-ICC.txt`](assets/LICENSE-ICC.txt).
