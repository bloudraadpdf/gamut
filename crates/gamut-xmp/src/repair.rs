//! Encoding-aware repair of XMP packet envelopes and recoverable XML spelling defects.

use crate::error::{Result, XmpError};
use crate::packet::{XmpPacket, encode_packet};

/// The fixed packet identifier from Adobe XMP Part 1 §7.3.2.
pub const CANONICAL_PACKET_ID: &str = "W5M0MpCehiHzreSzNTczkc9d";
/// The canonical `begin` value, U+FEFF.
pub const CANONICAL_BEGIN: &str = "\u{FEFF}";

/// Canonicalises the packet instructions and character encoding, while retaining the body XML.
///
/// UTF-8, UTF-16, and UTF-32 input is accepted. Recoverable missing outer close tags and
/// case-only close-tag mismatches are repaired before the canonical UTF-8 packet is emitted.
///
/// # Errors
///
/// Returns [`XmpError::Encoding`] when either packet instruction is absent or the input encoding
/// is malformed.
pub fn canonicalise_xmp_packet(bytes: &[u8]) -> Result<Vec<u8>> {
    let decoded = XmpPacket::scan_with_source(bytes)?;
    let Some(header) = decoded.envelope.header else {
        return Err(XmpError::Encoding("XMP packet header is missing"));
    };
    let Some(trailer) = decoded.envelope.trailer else {
        return Err(XmpError::Encoding("XMP packet trailer is missing"));
    };
    let body = &decoded.decoded[header.end..trailer.start];
    let body = repair_body(body.as_bytes()).unwrap_or_else(|| body.as_bytes().to_vec());
    let end = if decoded.packet.writable { 'w' } else { 'r' };
    let output = format!(
        "<?xpacket begin='{CANONICAL_BEGIN}' id='{CANONICAL_PACKET_ID}'?>{}<?xpacket end='{end}'?>",
        String::from_utf8_lossy(&body)
    )
    .into_bytes();
    if output == bytes {
        Ok(bytes.to_vec())
    } else {
        Ok(output)
    }
}

/// Inserts missing `rdf:RDF` and `x:xmpmeta` close tags in an otherwise retained packet.
///
/// The source encoding and packet instructions are preserved. `None` means the wrappers were
/// already balanced or no safe insertion was identified.
///
/// # Errors
///
/// Returns [`XmpError::Encoding`] when the packet cannot be decoded.
pub fn close_xmp_wrappers(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    rewrite_body(bytes, close_unclosed_wrappers)
}

/// Repairs missing outer closes and case-only close-tag mismatches in the RDF/XML body.
///
/// The source encoding and packet instructions are preserved. `None` means no supported defect
/// was present.
///
/// # Errors
///
/// Returns [`XmpError::Encoding`] when the packet cannot be decoded.
pub fn repair_xmp_serialisation(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    rewrite_body(bytes, repair_body)
}

fn rewrite_body(
    bytes: &[u8],
    repair: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let decoded = XmpPacket::scan_with_source(bytes)?;
    let (Some(header), Some(trailer)) = (decoded.envelope.header, decoded.envelope.trailer) else {
        return Ok(None);
    };
    let body = &decoded.decoded.as_bytes()[header.end..trailer.start];
    let Some(repaired) = repair(body) else {
        return Ok(None);
    };
    let mut text = Vec::with_capacity(decoded.decoded.len() + repaired.len() - body.len());
    text.extend_from_slice(&decoded.decoded.as_bytes()[..header.end]);
    text.extend_from_slice(&repaired);
    text.extend_from_slice(&decoded.decoded.as_bytes()[trailer.start..]);
    let text =
        String::from_utf8(text).map_err(|_| XmpError::Encoding("repair produced invalid UTF-8"))?;
    Ok(Some(encode_packet(
        &text,
        decoded.encoding,
        decoded.had_bom,
    )))
}

fn repair_body(body: &[u8]) -> Option<Vec<u8>> {
    let wrappers = close_unclosed_wrappers(body);
    let working = wrappers.as_deref().unwrap_or(body);
    repair_close_tag_case(working).or(wrappers)
}

fn close_unclosed_wrappers(body: &[u8]) -> Option<Vec<u8>> {
    let xmpmeta = element_balance(body, b"x:xmpmeta");
    let rdf = element_balance(body, b"rdf:RDF");
    if xmpmeta <= 0 && rdf <= 0 {
        return None;
    }
    let insertion = body
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |position| position + 1);
    let mut output = Vec::with_capacity(body.len() + 32);
    output.extend_from_slice(&body[..insertion]);
    if rdf > 0 {
        output.extend_from_slice(b"</rdf:RDF>");
    }
    if xmpmeta > 0 {
        output.extend_from_slice(b"</x:xmpmeta>");
    }
    output.extend_from_slice(&body[insertion..]);
    Some(output)
}

fn element_balance(body: &[u8], name: &[u8]) -> i32 {
    let mut balance = 0;
    let mut cursor = 0;
    while let Some(relative) = body[cursor..].iter().position(|byte| *byte == b'<') {
        let open = cursor + relative;
        let is_close = body.get(open + 1) == Some(&b'/');
        let name_start = open + if is_close { 2 } else { 1 };
        let name_end = name_start + name.len();
        if body.get(name_start..name_end) != Some(name)
            || !body
                .get(name_end)
                .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(*byte, b'>' | b'/'))
        {
            cursor = name_start.min(body.len());
            continue;
        }
        let Some(tag_end) = body[name_end..]
            .iter()
            .position(|byte| *byte == b'>')
            .map(|relative| name_end + relative)
        else {
            break;
        };
        let self_closing = body[..tag_end]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|position| body[position] == b'/');
        if is_close {
            balance -= 1;
        } else if !self_closing {
            balance += 1;
        }
        cursor = tag_end + 1;
    }
    balance
}

fn repair_close_tag_case(body: &[u8]) -> Option<Vec<u8>> {
    let mut output = body.to_vec();
    let mut changed = false;
    let mut stack = Vec::<(usize, usize)>::new();
    let mut cursor = 0;
    while let Some(relative) = body[cursor..].iter().position(|byte| *byte == b'<') {
        let open = cursor + relative;
        match body.get(open + 1) {
            Some(b'?' | b'!') => {
                cursor = body[open + 2..]
                    .iter()
                    .position(|byte| *byte == b'>')
                    .map_or(body.len(), |relative| open + 3 + relative);
                continue;
            }
            None => break,
            _ => {}
        }
        let is_close = body.get(open + 1) == Some(&b'/');
        let name_start = open + if is_close { 2 } else { 1 };
        let mut name_end = name_start;
        while body
            .get(name_end)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && !matches!(*byte, b'>' | b'/'))
        {
            name_end += 1;
        }
        let Some(tag_end) = body[name_end..]
            .iter()
            .position(|byte| *byte == b'>')
            .map(|relative| name_end + relative)
        else {
            break;
        };
        let self_closing = body[..tag_end]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|position| body[position] == b'/');
        if is_close {
            if let Some((start, end)) = stack.pop() {
                let opened = &body[start..end];
                let closed = &body[name_start..name_end];
                if opened != closed && opened.eq_ignore_ascii_case(closed) {
                    output[name_start..name_end].copy_from_slice(opened);
                    changed = true;
                }
            }
        } else if !self_closing {
            stack.push((name_start, name_end));
        }
        cursor = tag_end + 1;
    }
    changed.then_some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_missing_outer_wrapper_without_changing_packet_instructions() {
        let packet =
            b"<?xpacket begin='' id='x'?><x:xmpmeta><rdf:RDF></rdf:RDF>  <?xpacket end='w'?>";
        let repaired = close_xmp_wrappers(packet).unwrap().unwrap();
        assert_eq!(
            repaired,
            b"<?xpacket begin='' id='x'?><x:xmpmeta><rdf:RDF></rdf:RDF></x:xmpmeta>  <?xpacket end='w'?>"
        );
    }

    #[test]
    fn repairs_case_only_close_mismatch() {
        let packet = b"<?xpacket begin='' id='x'?><x:xmpmeta><rdf:RDF><dc:title>x</dc:Title></rdf:RDF></x:xmpmeta><?xpacket end='r'?>";
        let repaired = repair_xmp_serialisation(packet).unwrap().unwrap();
        assert!(String::from_utf8(repaired).unwrap().contains("</dc:title>"));
    }

    #[test]
    fn canonicalises_packet_envelope() {
        let packet =
            b"<?xpacket begin='' id='other' bytes='12'?><rdf:RDF/><?xpacket end='w' note='x'?>";
        let canonical = canonicalise_xmp_packet(packet).unwrap();
        let text = String::from_utf8(canonical).unwrap();
        assert!(text.starts_with("<?xpacket begin='\u{FEFF}' id='W5M0MpCehiHzreSzNTczkc9d'?>"));
        assert!(text.ends_with("<?xpacket end='w'?>"));
    }
}
