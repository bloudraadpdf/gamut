//! The XMP packet wrapper (Adobe XMP Part 1 §7.3.2).
//!
//! An embedded XMP packet is the RDF/XML body bracketed by `<?xpacket?>` processing instructions:
//! `<?xpacket begin="…" id="…"?>` … body … optional whitespace padding … `<?xpacket end='r'|'w'?>`.
//! [`XmpPacket::scan`] recovers the body and the `writable`/`padding` details from raw bytes, and
//! [`XmpPacket::parse`] turns the body into a graph — [`crate::XmpMeta::from_packet`] is exactly
//! that composition. Scanning first is how an in-place editor honors the envelope: parse, modify,
//! then re-serialize with the original `writable`/`padding` on a [`crate::XmpWriter`].

use crate::error::{Result, XmpError};
use crate::namespace::RDF_NAMESPACE;

/// The UTF-8 byte-order mark (`U+FEFF`). Tolerated as a leading prefix on read; never emitted.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Character encoding carried by an XMP packet (Adobe XMP Part 1 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XmpEncoding {
    /// UTF-8, with or without its optional byte-order mark.
    Utf8,
    /// Big-endian UTF-16.
    Utf16Be,
    /// Little-endian UTF-16.
    Utf16Le,
    /// Big-endian UTF-32.
    Utf32Be,
    /// Little-endian UTF-32.
    Utf32Le,
}

impl XmpEncoding {
    /// Detects an XMP packet's text encoding from its BOM or XML leading-byte pattern.
    #[must_use]
    pub fn detect(bytes: &[u8]) -> Self {
        detect_encoding(bytes).0
    }
}

/// Half-open byte range in the decoded UTF-8 packet text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmpSourceSpan {
    /// First byte belonging to the construct.
    pub start: usize,
    /// First byte after the construct.
    pub end: usize,
}

/// Exact packet-envelope locations in decoded UTF-8 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmpEnvelope {
    /// Opening `xpacket` processing instruction, when present.
    pub header: Option<XmpSourceSpan>,
    /// Exact body region between the packet instructions, including padding.
    pub body: XmpSourceSpan,
    /// RDF/XML content after trimming its surrounding packet whitespace.
    pub content: XmpSourceSpan,
    /// Trailing padding within [`Self::body`].
    pub padding: XmpSourceSpan,
    /// Closing `xpacket` processing instruction, when present.
    pub trailer: Option<XmpSourceSpan>,
}

/// An encoding-aware packet scan with exact decoded-source locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedXmpPacket {
    /// Parsed packet envelope and RDF/XML body.
    pub packet: XmpPacket,
    /// Encoding detected from the byte-order mark or XML leading-byte pattern.
    pub encoding: XmpEncoding,
    /// Whether the source began with the byte-order mark for [`Self::encoding`].
    pub had_bom: bool,
    /// Complete packet transcoded to UTF-8. Source spans index this string.
    pub decoded: String,
    /// Packet instruction, body, and padding spans in [`Self::decoded`].
    pub envelope: XmpEnvelope,
}

impl DecodedXmpPacket {
    /// Returns a decoded attribute from the opening `xpacket` instruction.
    ///
    /// Both XML quote styles are accepted. `None` means either that the packet is bare or the
    /// requested attribute is absent or malformed.
    #[must_use]
    pub fn header_attribute(&self, name: &str) -> Option<String> {
        let header = self.envelope.header?;
        processing_instruction_attribute(&self.decoded[header.start..header.end], name)
    }
}

fn processing_instruction_attribute(instruction: &str, name: &str) -> Option<String> {
    let mut rest = instruction.strip_prefix("<?xpacket")?;
    loop {
        rest = rest.trim_start();
        if rest.starts_with("?>") || rest.is_empty() {
            return None;
        }
        let name_end =
            rest.find(|character: char| character.is_ascii_whitespace() || character == '=')?;
        let candidate = &rest[..name_end];
        rest = rest[name_end..].trim_start();
        rest = rest.strip_prefix('=')?.trim_start();
        let quote = rest.chars().next()?;
        if !matches!(quote, '\'' | '"') {
            return None;
        }
        rest = &rest[quote.len_utf8()..];
        let value_end = rest.find(quote)?;
        let value = &rest[..value_end];
        rest = &rest[value_end + quote.len_utf8()..];
        if candidate == name {
            return Some(value.to_owned());
        }
    }
}

/// The serialized form of an XMP packet — the RDF/XML body inside its `<?xpacket?>` wrapper.
///
/// XMP is embedded as an `<?xpacket begin=… id=…?>` processing instruction, the `x:xmpmeta` /
/// `rdf:RDF` body, then `<?xpacket end='r'|'w'?>`. A writable (`'w'`) packet carries trailing
/// whitespace padding so it can be edited in place without rewriting the whole file. Build one from
/// bytes with [`XmpPacket::scan`], parse its body into a graph with [`XmpPacket::parse`], and
/// produce packet bytes from a graph with [`crate::XmpMeta::to_packet`] or a configured
/// [`crate::XmpWriter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmpPacket {
    /// The RDF/XML body between the opening and closing `xpacket` instructions, with surrounding
    /// whitespace trimmed.
    pub body: String,
    /// Whether the packet is writable in place (`end='w'`) versus read-only (`end='r'`).
    pub writable: bool,
    /// The number of trailing padding bytes reserved for in-place edits.
    pub padding: usize,
}

impl XmpPacket {
    /// Recovers the packet structure from raw bytes.
    ///
    /// Decodes the packet, locates the `<?xpacket?>` wrapper (if present), and
    /// records whether the packet is writable and how much trailing padding it carries. If there is
    /// no wrapper the whole input is taken as the body (`writable = false`, `padding = 0`).
    ///
    /// # Errors
    ///
    /// Returns [`XmpError::Encoding`] if the bytes are malformed in their detected UTF encoding or
    /// if an opening `<?xpacket` instruction is unterminated.
    pub fn scan(bytes: &[u8]) -> Result<XmpPacket> {
        Ok(Self::scan_with_source(bytes)?.packet)
    }

    /// Decodes and scans a packet while retaining its encoding and exact envelope locations.
    ///
    /// UTF-8, UTF-16, and UTF-32 in either byte order are accepted. A byte-order mark is used
    /// when present; otherwise the XML leading-byte patterns from XML 1.0 §4.3.3 identify wide
    /// encodings. Locations are byte offsets in the returned UTF-8 [`DecodedXmpPacket::decoded`]
    /// string, so they remain directly sliceable even when the source used a wide encoding.
    ///
    /// # Errors
    ///
    /// Returns [`XmpError::Encoding`] for malformed code units, invalid Unicode scalar values, or
    /// bytes that are not valid in the detected encoding.
    pub fn scan_with_source(bytes: &[u8]) -> Result<DecodedXmpPacket> {
        let (encoding, had_bom, decoded) = decode_packet(bytes)?;
        let split = split_packet(decoded.as_bytes())?;
        let exact_body = &decoded[split.body.start..split.body.end];
        let body = exact_body.trim().to_owned();
        let leading = exact_body.len() - exact_body.trim_start().len();
        let content = XmpSourceSpan {
            start: split.body.start + leading,
            end: split.body.start + leading + body.len(),
        };
        let padding = trailing_whitespace(exact_body.as_bytes());
        let padding_start = split.body.end.saturating_sub(padding);
        Ok(DecodedXmpPacket {
            packet: XmpPacket {
                body,
                writable: split.writable,
                padding,
            },
            encoding,
            had_bom,
            decoded,
            envelope: XmpEnvelope {
                header: split.header,
                body: split.body,
                content,
                padding: XmpSourceSpan {
                    start: padding_start,
                    end: split.body.end,
                },
                trailer: split.trailer,
            },
        })
    }

    /// Transcodes a packet to UTF-8 while leaving an existing UTF-8 byte sequence untouched.
    ///
    /// Packet instructions, RDF/XML spelling, and padding are preserved. This is intended for
    /// repair operations that require a UTF-8 representation but must not parse and re-emit the
    /// property graph merely to change its character encoding.
    ///
    /// # Errors
    ///
    /// Returns [`XmpError::Encoding`] when the source has malformed code units.
    pub fn transcode_to_utf8(bytes: &[u8]) -> Result<Vec<u8>> {
        let encoding = XmpEncoding::detect(bytes);
        if encoding == XmpEncoding::Utf8 {
            Self::scan_with_source(bytes)?;
            return Ok(bytes.to_vec());
        }
        let decoded = match Self::scan_with_source(bytes) {
            Ok(decoded) => decoded,
            Err(original_error) => {
                let unit = match encoding {
                    XmpEncoding::Utf16Be | XmpEncoding::Utf16Le => 2,
                    XmpEncoding::Utf32Be | XmpEncoding::Utf32Le => 4,
                    XmpEncoding::Utf8 => unreachable!(),
                };
                let remainder = bytes.len() % unit;
                if remainder == 0 {
                    return Err(original_error);
                }
                Self::scan_with_source(&bytes[..bytes.len() - remainder])?
            }
        };
        if decoded.encoding == XmpEncoding::Utf8 {
            Ok(bytes.to_vec())
        } else {
            Ok(decoded.decoded.into_bytes())
        }
    }

    /// Removes named attributes from the opening `xpacket` processing instruction.
    ///
    /// Both XML quote styles and arbitrary XML whitespace are accepted. The packet's source
    /// encoding and every byte outside the removed attribute spans are preserved. A bare RDF/XML
    /// document is returned unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`XmpError::Encoding`] when the packet cannot be decoded or its header is
    /// unterminated.
    pub fn remove_header_attributes(bytes: &[u8], names: &[&str]) -> Result<Vec<u8>> {
        let decoded = Self::scan_with_source(bytes)?;
        let Some(header) = decoded.envelope.header else {
            return Ok(bytes.to_vec());
        };
        let instruction = &decoded.decoded[header.start..header.end];
        let Some(rewritten) = remove_processing_instruction_attributes(instruction, names) else {
            return Ok(bytes.to_vec());
        };
        let mut text = String::with_capacity(decoded.decoded.len());
        text.push_str(&decoded.decoded[..header.start]);
        text.push_str(&rewritten);
        text.push_str(&decoded.decoded[header.end..]);
        Ok(encode_packet(&text, decoded.encoding, decoded.had_bom))
    }
}

fn remove_processing_instruction_attributes(instruction: &str, names: &[&str]) -> Option<String> {
    let prefix = "<?xpacket";
    let mut cursor = prefix.len();
    let mut removals = Vec::new();
    while cursor < instruction.len() {
        let whitespace_start = cursor;
        while instruction
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if instruction[cursor..].starts_with("?>") {
            break;
        }
        let name_start = cursor;
        while instruction
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && !matches!(*byte, b'=' | b'?' | b'>'))
        {
            cursor += 1;
        }
        let name = &instruction[name_start..cursor];
        while instruction
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if instruction.as_bytes().get(cursor) != Some(&b'=') {
            return None;
        }
        cursor += 1;
        while instruction
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        let quote = *instruction.as_bytes().get(cursor)?;
        if !matches!(quote, b'\'' | b'"') {
            return None;
        }
        cursor += 1;
        cursor += instruction.as_bytes()[cursor..]
            .iter()
            .position(|byte| *byte == quote)?
            + 1;
        if names.contains(&name) {
            removals.push(whitespace_start..cursor);
        }
    }
    if removals.is_empty() {
        return None;
    }
    let mut output = String::with_capacity(instruction.len());
    let mut copied = 0;
    for removal in removals {
        output.push_str(&instruction[copied..removal.start]);
        copied = removal.end;
    }
    output.push_str(&instruction[copied..]);
    Some(output)
}

/// Detects a recoverable case-only spelling error on the `rdf:RDF` root prefix.
///
/// This operates before namespace resolution because `<RDF:RDF>` with only a lowercase
/// `xmlns:rdf` binding is not namespace-well-formed. A mismatch is reported only when the
/// wrong-case opening and closing names balance and the opening tag declares the canonical
/// lowercase RDF binding.
#[must_use]
pub fn rdf_prefix_case_mismatch(bytes: &[u8]) -> Option<String> {
    let (_, _, decoded) = decode_packet(bytes).ok()?;
    let source = decoded.as_bytes();
    let mut cursor = 0usize;
    while cursor + 5 < source.len() {
        let open = cursor + source[cursor..].iter().position(|byte| *byte == b'<')? + 1;
        if open < source.len() && matches!(source[open], b'?' | b'!' | b'/') {
            cursor = open + 1;
            continue;
        }
        let mut end = open;
        while end < source.len()
            && !matches!(source[end], b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/')
        {
            end += 1;
        }
        let qname = &source[open..end];
        let Some(colon) = qname.iter().position(|byte| *byte == b':') else {
            cursor = end.max(open + 1);
            continue;
        };
        let prefix = &qname[..colon];
        if &qname[colon + 1..] != b"RDF" {
            cursor = end.max(open + 1);
            continue;
        }
        if prefix.len() != 3 || !prefix.eq_ignore_ascii_case(b"rdf") || prefix == b"rdf" {
            return None;
        }
        let tag_close = end + source[end..].iter().position(|byte| *byte == b'>')?;
        let attributes = &source[end..tag_close];
        let double = format!("xmlns:rdf=\"{RDF_NAMESPACE}\"");
        let single = format!("xmlns:rdf='{RDF_NAMESPACE}'");
        if find(attributes, double.as_bytes()).is_none()
            && find(attributes, single.as_bytes()).is_none()
        {
            return None;
        }
        let close = format!("</{}:RDF>", String::from_utf8_lossy(prefix));
        find(&source[tag_close..], close.as_bytes())?;
        return Some(String::from_utf8_lossy(prefix).into_owned());
    }
    None
}

/// Repairs a balanced, case-only spelling error on the `rdf:RDF` root prefix.
///
/// Detection follows [`rdf_prefix_case_mismatch`]. Only the root opening and closing qualified
/// names are changed; the packet envelope, character encoding, padding, and inner RDF spelling
/// remain intact.
///
/// # Errors
///
/// Returns [`XmpError::Encoding`] when the packet cannot be decoded.
pub fn repair_rdf_prefix_case(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(wrong_case) = rdf_prefix_case_mismatch(bytes) else {
        return Ok(None);
    };
    let decoded = XmpPacket::scan_with_source(bytes)?;
    let open = format!("<{wrong_case}:RDF");
    let close = format!("</{wrong_case}:RDF>");
    let Some(open_start) = find(decoded.decoded.as_bytes(), open.as_bytes()) else {
        return Ok(None);
    };
    let after_open = open_start + open.len();
    if !decoded
        .decoded
        .as_bytes()
        .get(after_open)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/'))
    {
        return Ok(None);
    }
    let Some(close_start) = find(&decoded.decoded.as_bytes()[after_open..], close.as_bytes())
        .map(|relative| after_open + relative)
    else {
        return Ok(None);
    };
    let mut text = String::with_capacity(decoded.decoded.len());
    text.push_str(&decoded.decoded[..open_start]);
    text.push_str("<rdf:RDF");
    text.push_str(&decoded.decoded[after_open..close_start]);
    text.push_str("</rdf:RDF>");
    text.push_str(&decoded.decoded[close_start + close.len()..]);
    Ok(Some(encode_packet(
        &text,
        decoded.encoding,
        decoded.had_bom,
    )))
}

/// The result of locating the body inside a packet's wrapper.
struct SplitPacket {
    header: Option<XmpSourceSpan>,
    body: XmpSourceSpan,
    trailer: Option<XmpSourceSpan>,
    /// Whether the trailer requested in-place writability (`end='w'`).
    writable: bool,
}

/// Locates the packet body in decoded UTF-8 text.
///
/// # Errors
///
/// Returns [`XmpError::Encoding`] when an opening packet instruction is unterminated.
fn split_packet(bytes: &[u8]) -> Result<SplitPacket> {
    let Some(header) = find(bytes, b"<?xpacket") else {
        // Bare RDF/XML (no wrapper) — e.g. some WebP/AVIF payloads.
        return Ok(SplitPacket {
            header: None,
            body: XmpSourceSpan {
                start: 0,
                end: bytes.len(),
            },
            trailer: None,
            writable: false,
        });
    };

    // Body starts after the header PI's closing "?>".
    let Some(rel) = find(&bytes[header..], b"?>") else {
        return Err(XmpError::Encoding("unterminated <?xpacket?> header"));
    };
    let body_start = header + rel + 2;

    // The trailer is the next "<?xpacket" after the body; the packet is writable only when its
    // `end` attribute says so (`end="w"` in either quote style, Part 1 §7.3.2) — an unrelated `w`
    // byte elsewhere in the instruction must not count.
    let (body_end, trailer, writable) = match find(&bytes[body_start..], b"<?xpacket") {
        Some(rel) => {
            let trailer = body_start + rel;
            let trailer_end =
                find(&bytes[trailer..], b"?>").map_or(bytes.len(), |e| trailer + e + 2);
            let pi = &bytes[trailer..trailer_end];
            let writable = find(pi, b"end=\"w\"").is_some() || find(pi, b"end='w'").is_some();
            (
                trailer,
                Some(XmpSourceSpan {
                    start: trailer,
                    end: trailer_end,
                }),
                writable,
            )
        }
        None => (bytes.len(), None, false),
    };

    Ok(SplitPacket {
        header: Some(XmpSourceSpan {
            start: header,
            end: body_start,
        }),
        body: XmpSourceSpan {
            start: body_start,
            end: body_end,
        },
        trailer,
        writable,
    })
}

fn decode_packet(bytes: &[u8]) -> Result<(XmpEncoding, bool, String)> {
    let (encoding, had_bom, body) = detect_encoding(bytes);
    let decoded = match encoding {
        XmpEncoding::Utf8 => core::str::from_utf8(body)
            .map_err(|_| XmpError::Encoding("packet is not valid UTF-8"))?
            .to_owned(),
        XmpEncoding::Utf16Be => decode_utf16(body, u16::from_be_bytes)?,
        XmpEncoding::Utf16Le => decode_utf16(body, u16::from_le_bytes)?,
        XmpEncoding::Utf32Be => decode_utf32(body, u32::from_be_bytes)?,
        XmpEncoding::Utf32Le => decode_utf32(body, u32::from_le_bytes)?,
    };
    Ok((encoding, had_bom, decoded))
}

fn detect_encoding(bytes: &[u8]) -> (XmpEncoding, bool, &[u8]) {
    if let Some(rest) = bytes.strip_prefix(&[0x00, 0x00, 0xFE, 0xFF]) {
        (XmpEncoding::Utf32Be, true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE, 0x00, 0x00]) {
        (XmpEncoding::Utf32Le, true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        (XmpEncoding::Utf16Be, true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        (XmpEncoding::Utf16Le, true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&UTF8_BOM) {
        (XmpEncoding::Utf8, true, rest)
    } else if bytes.starts_with(&[0x00, 0x00, 0x00, b'<']) {
        (XmpEncoding::Utf32Be, false, bytes)
    } else if bytes.starts_with(&[b'<', 0x00, 0x00, 0x00]) {
        (XmpEncoding::Utf32Le, false, bytes)
    } else if bytes.starts_with(&[0x00, b'<', 0x00, b'?']) {
        (XmpEncoding::Utf16Be, false, bytes)
    } else if bytes.starts_with(&[b'<', 0x00, b'?', 0x00]) {
        (XmpEncoding::Utf16Le, false, bytes)
    } else {
        (XmpEncoding::Utf8, false, bytes)
    }
}

pub(crate) fn encode_packet(text: &str, encoding: XmpEncoding, with_bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    match encoding {
        XmpEncoding::Utf8 => {
            if with_bom {
                bytes.extend_from_slice(&UTF8_BOM);
            }
            bytes.extend_from_slice(text.as_bytes());
        }
        XmpEncoding::Utf16Be | XmpEncoding::Utf16Le => {
            if with_bom {
                bytes.extend_from_slice(if encoding == XmpEncoding::Utf16Be {
                    &[0xFE, 0xFF]
                } else {
                    &[0xFF, 0xFE]
                });
            }
            for unit in text.encode_utf16() {
                let encoded = if encoding == XmpEncoding::Utf16Be {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                };
                bytes.extend_from_slice(&encoded);
            }
        }
        XmpEncoding::Utf32Be | XmpEncoding::Utf32Le => {
            if with_bom {
                bytes.extend_from_slice(if encoding == XmpEncoding::Utf32Be {
                    &[0x00, 0x00, 0xFE, 0xFF]
                } else {
                    &[0xFF, 0xFE, 0x00, 0x00]
                });
            }
            for character in text.chars() {
                let scalar = u32::from(character);
                let encoded = if encoding == XmpEncoding::Utf32Be {
                    scalar.to_be_bytes()
                } else {
                    scalar.to_le_bytes()
                };
                bytes.extend_from_slice(&encoded);
            }
        }
    }
    bytes
}

fn decode_utf16(bytes: &[u8], read: fn([u8; 2]) -> u16) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(XmpError::Encoding("UTF-16 packet has an odd byte length"));
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(read)
        .collect::<Vec<_>>();
    String::from_utf16(&units)
        .map_err(|_| XmpError::Encoding("UTF-16 packet contains an invalid surrogate"))
}

fn decode_utf32(bytes: &[u8], read: fn([u8; 4]) -> u32) -> Result<String> {
    if !bytes.len().is_multiple_of(4) {
        return Err(XmpError::Encoding(
            "UTF-32 packet has an incomplete code unit",
        ));
    }
    let mut decoded = String::new();
    for chunk in bytes.as_chunks::<4>().0.iter().copied() {
        let scalar = read(chunk);
        let character = char::from_u32(scalar).ok_or(XmpError::Encoding(
            "UTF-32 packet contains an invalid Unicode scalar",
        ))?;
        decoded.push(character);
    }
    Ok(decoded)
}

/// The number of trailing ASCII-whitespace bytes in `bytes`.
fn trailing_whitespace(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_whitespace())
        .count()
}

/// The index of the first occurrence of `needle` in `haystack`, if any.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRAPPED: &str = concat!(
        "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>",
        "<rdf:RDF/>",
        "   \n  ", // 3 spaces + newline + 2 spaces = 6 padding bytes
        "<?xpacket end=\"w\"?>",
    );

    #[test]
    fn scans_writable_wrapper_with_exact_padding() {
        let pkt = XmpPacket::scan(WRAPPED.as_bytes()).unwrap();
        assert_eq!(pkt.body, "<rdf:RDF/>");
        assert!(pkt.writable);
        assert_eq!(pkt.padding, 6);
    }

    #[test]
    fn read_only_trailer_is_not_writable() {
        let s = "<?xpacket begin=\"\" id=\"x\"?><rdf:RDF/><?xpacket end=\"r\"?>";
        let pkt = XmpPacket::scan(s.as_bytes()).unwrap();
        assert!(!pkt.writable);
        assert_eq!(pkt.padding, 0);
    }

    #[test]
    fn bare_rdf_without_wrapper_is_accepted() {
        let pkt = XmpPacket::scan(b"<rdf:RDF/>").unwrap();
        assert_eq!(pkt.body, "<rdf:RDF/>");
        assert!(!pkt.writable);
    }

    #[test]
    fn strips_utf8_bom() {
        let mut bytes = UTF8_BOM.to_vec();
        bytes.extend_from_slice(b"<rdf:RDF/>");
        let pkt = XmpPacket::scan(&bytes).unwrap();
        assert_eq!(pkt.body, "<rdf:RDF/>");
    }

    #[test]
    fn decodes_utf16_bom() {
        let bytes = encode_utf16("<rdf:RDF/>", true, true);
        let decoded = XmpPacket::scan_with_source(&bytes).unwrap();
        assert_eq!(decoded.encoding, XmpEncoding::Utf16Be);
        assert_eq!(decoded.packet.body, "<rdf:RDF/>");
    }

    #[test]
    fn decodes_utf16_le_and_utf32_both_orders() {
        let text = "<?xpacket begin='' id='x'?><rdf:RDF/>  <?xpacket end='w'?>";
        for (bytes, expected) in [
            (encode_utf16(text, false, true), XmpEncoding::Utf16Le),
            (encode_utf32(text, true, true), XmpEncoding::Utf32Be),
            (encode_utf32(text, false, true), XmpEncoding::Utf32Le),
        ] {
            let decoded = XmpPacket::scan_with_source(&bytes).unwrap();
            assert_eq!(decoded.encoding, expected);
            assert_eq!(decoded.packet.body, "<rdf:RDF/>");
            assert_eq!(decoded.packet.padding, 2);
            assert!(decoded.packet.writable);
        }
    }

    #[test]
    fn detects_wide_encoding_without_a_bom() {
        let utf16 = encode_utf16("<?xml version='1.0'?><rdf:RDF/>", false, false);
        let utf32 = encode_utf32("<?xml version='1.0'?><rdf:RDF/>", true, false);
        assert_eq!(
            XmpPacket::scan_with_source(&utf16).unwrap().encoding,
            XmpEncoding::Utf16Le
        );
        assert_eq!(
            XmpPacket::scan_with_source(&utf32).unwrap().encoding,
            XmpEncoding::Utf32Be
        );
    }

    #[test]
    fn single_quoted_trailer_is_detected() {
        // §7.3.2 examples use double quotes, but XML permits either style.
        let writable = "<?xpacket begin='' id='x'?><rdf:RDF/><?xpacket end='w'?>";
        assert!(XmpPacket::scan(writable.as_bytes()).unwrap().writable);
        let read_only = "<?xpacket begin='' id='x'?><rdf:RDF/><?xpacket end='r'?>";
        assert!(!XmpPacket::scan(read_only.as_bytes()).unwrap().writable);
    }

    #[test]
    fn unrelated_w_byte_in_the_trailer_is_not_writable() {
        // Writability comes from the end attribute alone — a stray `w` elsewhere in the
        // instruction (here in a nonstandard extra attribute) must not flip it.
        let s = "<?xpacket begin=\"\" id=\"x\"?><rdf:RDF/><?xpacket end=\"r\" note=\"w\"?>";
        assert!(!XmpPacket::scan(s.as_bytes()).unwrap().writable);
    }

    #[test]
    fn detects_balanced_wrong_case_rdf_prefix_before_xml_parsing() {
        let packet = concat!(
            "<x:xmpmeta xmlns:x='adobe:ns:meta/'>",
            "<RDF:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>",
            "<rdf:Description rdf:about=''/></RDF:RDF></x:xmpmeta>"
        );
        assert_eq!(
            rdf_prefix_case_mismatch(packet.as_bytes()).as_deref(),
            Some("RDF")
        );
    }

    #[test]
    fn header_without_trailer_is_read_only() {
        // A truncated wrapper (header but no trailer) still yields the body, as read-only.
        let pkt = XmpPacket::scan(b"<?xpacket begin=\"\" id=\"x\"?><rdf:RDF/>").unwrap();
        assert_eq!(pkt.body, "<rdf:RDF/>");
        assert!(!pkt.writable);
    }

    #[test]
    fn unterminated_header_is_rejected() {
        assert!(matches!(
            XmpPacket::scan(b"<?xpacket begin=\"\"<rdf:RDF/>"),
            Err(XmpError::Encoding("unterminated <?xpacket?> header"))
        ));
    }

    #[test]
    fn accepts_bom_character_in_the_begin_attribute() {
        // §7.3.2 recommends begin="\u{FEFF}" — packets from Adobe tools carry the BOM character
        // inside the attribute value, which must not confuse body extraction.
        let s = "<?xpacket begin=\"\u{FEFF}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\
                 <rdf:RDF/><?xpacket end=\"r\"?>";
        let pkt = XmpPacket::scan(s.as_bytes()).unwrap();
        assert_eq!(pkt.body, "<rdf:RDF/>");
        assert!(!pkt.writable);
    }

    #[test]
    fn find_handles_edges() {
        assert_eq!(find(b"xy<?xpacket", b"<?xpacket"), Some(2));
        // An exact-length match must be found (guards the `>` length check).
        assert_eq!(find(b"abc", b"abc"), Some(0));
        // A needle longer than the haystack is absent.
        assert_eq!(find(b"ab", b"abc"), None);
        // An empty needle is never found (and must not panic on `windows(0)`).
        assert_eq!(find(b"abc", b""), None);
    }

    #[test]
    fn rejects_non_utf8_body() {
        let mut bytes = b"<rdf:RDF>".to_vec();
        bytes.push(0xFF); // invalid UTF-8 in the body
        assert!(matches!(
            XmpPacket::scan(&bytes),
            Err(XmpError::Encoding(_))
        ));
    }

    #[test]
    fn exposes_exact_decoded_envelope_spans() {
        let decoded = XmpPacket::scan_with_source(WRAPPED.as_bytes()).unwrap();
        let envelope = decoded.envelope;
        let header = envelope.header.unwrap();
        let trailer = envelope.trailer.unwrap();
        assert!(decoded.decoded[header.start..header.end].starts_with("<?xpacket"));
        assert_eq!(
            &decoded.decoded[envelope.body.start..envelope.padding.start],
            "<rdf:RDF/>"
        );
        assert_eq!(
            &decoded.decoded[envelope.content.start..envelope.content.end],
            "<rdf:RDF/>"
        );
        assert_eq!(
            &decoded.decoded[envelope.padding.start..envelope.padding.end],
            "   \n  "
        );
        assert_eq!(
            &decoded.decoded[trailer.start..trailer.end],
            "<?xpacket end=\"w\"?>"
        );
    }

    #[test]
    fn reads_header_attributes_without_substring_false_matches() {
        let decoded = XmpPacket::scan_with_source(
            b"<?xpacket begin='' id='x' bytes='12'?>X<?xpacket end='r'?>",
        )
        .unwrap();
        assert_eq!(decoded.header_attribute("bytes").as_deref(), Some("12"));
        assert_eq!(decoded.header_attribute("byte"), None);
    }

    #[test]
    fn transcodes_a_wide_packet_without_rewriting_its_xml() {
        let source = encode_utf16(
            "<?xpacket begin='' id='x'?><rdf:RDF/> <?xpacket end='w'?>",
            false,
            true,
        );
        assert_eq!(
            String::from_utf8(XmpPacket::transcode_to_utf8(&source).unwrap()).unwrap(),
            "<?xpacket begin='' id='x'?><rdf:RDF/> <?xpacket end='w'?>"
        );
    }

    #[test]
    fn transcode_tolerates_an_incomplete_trailing_wide_code_unit() {
        let mut source = encode_utf32("<rdf:RDF/>", true, false);
        source.extend_from_slice(b"\r\n");
        assert_eq!(
            XmpPacket::transcode_to_utf8(&source).unwrap(),
            b"<rdf:RDF/>"
        );
    }

    #[test]
    fn removes_only_selected_packet_header_attributes() {
        let source =
            b"<?xpacket begin='' id='x' bytes = \"42\" encoding='UTF-8' keep='yes'?><rdf:RDF/>";
        let output = XmpPacket::remove_header_attributes(source, &["bytes", "encoding"]).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "<?xpacket begin='' id='x' keep='yes'?><rdf:RDF/>"
        );
    }

    #[test]
    fn repairs_only_the_wrong_case_rdf_root_names() {
        let packet = concat!(
            "<x:xmpmeta xmlns:x='adobe:ns:meta/'>",
            "<RDF:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>",
            "<rdf:Description rdf:about='' note='RDF:RDF'/></RDF:RDF></x:xmpmeta>"
        );
        let repaired = repair_rdf_prefix_case(packet.as_bytes()).unwrap().unwrap();
        assert_eq!(
            String::from_utf8(repaired).unwrap(),
            packet
                .replacen("<RDF:RDF", "<rdf:RDF", 1)
                .replacen("</RDF:RDF>", "</rdf:RDF>", 1)
        );
    }

    fn encode_utf16(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
        let mut bytes = if bom {
            if big_endian {
                vec![0xFE, 0xFF]
            } else {
                vec![0xFF, 0xFE]
            }
        } else {
            Vec::new()
        };
        for unit in text.encode_utf16() {
            let encoded = if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    fn encode_utf32(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
        let mut bytes = if bom {
            if big_endian {
                vec![0x00, 0x00, 0xFE, 0xFF]
            } else {
                vec![0xFF, 0xFE, 0x00, 0x00]
            }
        } else {
            Vec::new()
        };
        for character in text.chars() {
            let scalar = u32::from(character);
            let encoded = if big_endian {
                scalar.to_be_bytes()
            } else {
                scalar.to_le_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }
}
