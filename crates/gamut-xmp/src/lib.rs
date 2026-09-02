//! `gamut-xmp` — XMP (Extensible Metadata Platform) parsing and canonical serialization.
//!
//! XMP is the RDF/XML metadata packet embedded in images (the WebP `XMP ` chunk, the AVIF/HEIF
//! `mime` item of type `application/rdf+xml`, a JPEG `APP1` segment), wrapped in an `<?xpacket?>`
//! processing instruction. This crate parses such a packet into the [`XmpMeta`] property graph —
//! simple, structured, and `Bag`/`Seq`/`Alt` array values, with qualifiers and language
//! alternatives — and serializes a graph back to **canonical RDF/XML** (Part 1 §7), which fixes the
//! element-vs-attribute encoding, namespace placement, and array/struct nesting so output is
//! stable, diffable, and round-trippable.
//!
//! Implemented from the **Adobe XMP Specification, Parts 1–3** (equivalent to ISO 16684-1/-2;
//! `references/xmp`).
//!
//! # Quick start
//!
//! [`XmpMeta::from_packet`] reads a packet; [`XmpMeta::to_packet`] writes one. [`XmpEdit`] changes
//! an existing packet while preserving its encoding and envelope. Accessors like
//! [`XmpMeta::get_text`] / [`XmpMeta::set_text`] and [`XmpMeta::get_lang_alt`] /
//! [`XmpMeta::set_lang_alt`] cover the common cases; [`WellKnownNs`] supplies the standard schema
//! URIs so you do not hand-write them.
//!
//! ```
//! use gamut_xmp::{WellKnownNs, XmpMeta};
//!
//! let dc = WellKnownNs::DublinCore.uri();
//! let xmp = WellKnownNs::Xmp.uri();
//!
//! let mut meta = XmpMeta::new();
//! meta.set_lang_alt(dc, "title", "x-default", "My Photo");
//! meta.set_text(xmp, "CreatorTool", "gamut");
//!
//! // Serialize to an embeddable packet, then read it back.
//! let packet = meta.to_packet();
//! let parsed = XmpMeta::from_packet(&packet)?;
//!
//! assert_eq!(parsed.get_lang_alt(dc, "title", "x-default"), Some("My Photo"));
//! assert_eq!(parsed.get_text(xmp, "CreatorTool"), Some("gamut"));
//! # Ok::<(), gamut_xmp::XmpError>(())
//! ```
//!
//! # Design notes
//!
//! - **Reads more than it writes.** The parser accepts the broad RDF/XML input XMP permits (Part 1
//!   Annex C / §7.9 — attribute or element form, `rdf:parseType="Resource"`, abbreviations); the
//!   serializer emits one fixed canonical form.
//! - **Transparent graph.** The model types expose public fields — the graph is data. The
//!   accessors maintain the canonical invariants (unique names, unique `Alt` languages,
//!   `x-default` first); direct field mutation can bypass them, and the infallible writer
//!   serializes what the graph says without validating (see [`model`]).
//! - **All XMP text encodings on read.** UTF-8, UTF-16, and UTF-32 are detected from a BOM or the
//!   XML leading-byte pattern. New packets use UTF-8; [`XmpEdit`] retains an existing packet's
//!   encoding and BOM choice.
//! - **`quick-xml` is internal.** The XML lexer is an implementation detail and does not appear in
//!   the public API (errors are surfaced via [`XmpError`]), so it can be changed without a breaking
//!   change.
//! - **Memory-safe on hostile input.** `#![forbid(unsafe_code)]` — XMP is XML from untrusted files.
#![forbid(unsafe_code)]

pub mod edit;
pub mod error;
pub mod model;
pub mod namespace;
pub mod packet;
pub mod repair;
pub mod writer;
// The reader has no configuration — `XmpMeta::from_packet` is the entry point and auto-detects the
// wrapper, encoding, and input form — so the module carries only that `impl` and stays private.
mod reader;

pub use edit::XmpEdit;
pub use error::{Result, XmpError};
pub use model::{XmpArray, XmpItem, XmpMeta, XmpProperty, XmpValue};
pub use namespace::{Namespace, RDF_NAMESPACE, WellKnownNs, XML_NAMESPACE, XMPMETA_NAMESPACE};
pub use packet::{
    DecodedXmpPacket, XmpEncoding, XmpEnvelope, XmpPacket, XmpSourceSpan, rdf_prefix_case_mismatch,
    repair_rdf_prefix_case,
};
pub use reader::{
    XmpDescriptionLocation, XmpDocument, XmpNamespaceBinding, XmpPropertyForm, XmpPropertyLocation,
};
pub use repair::{
    CANONICAL_BEGIN, CANONICAL_PACKET_ID, canonicalise_xmp_packet, close_xmp_wrappers,
    repair_xmp_serialisation,
};
pub use writer::XmpWriter;
