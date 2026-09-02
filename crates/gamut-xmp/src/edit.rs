//! Encoding- and envelope-preserving XMP edit transactions.

use crate::error::Result;
use crate::model::{XmpArray, XmpItem, XmpMeta, XmpProperty, XmpValue};
use crate::namespace::{Namespace, XMPMETA_NAMESPACE};
use crate::packet::{DecodedXmpPacket, XmpPacket, encode_packet};
use crate::writer::XmpWriter;

/// A parsed XMP packet that can be changed as one deterministic transaction.
///
/// The original bytes are returned exactly when the graph is unchanged. When it is changed, the
/// RDF graph is emitted in gamut's canonical form while the source packet instructions, padding,
/// text encoding, and byte-order-mark choice are retained. This prevents independent product
/// layers from implementing their own packet scanners and serializers.
#[derive(Debug, Clone)]
pub struct XmpEdit {
    original: Vec<u8>,
    decoded: DecodedXmpPacket,
    original_meta: XmpMeta,
    meta: XmpMeta,
    namespaces: Vec<Namespace>,
}

impl XmpEdit {
    /// Parses `bytes` and starts an edit transaction.
    ///
    /// # Errors
    ///
    /// Returns an [`crate::XmpError`] when the packet encoding, wrapper, XML, or XMP graph is
    /// malformed or ambiguous.
    pub fn from_packet(bytes: &[u8]) -> Result<Self> {
        let decoded = XmpPacket::scan_with_source(bytes)?;
        let document = decoded.parse()?;
        let namespaces = document
            .namespaces
            .iter()
            .filter_map(|binding| {
                binding
                    .prefix
                    .as_ref()
                    .map(|prefix| Namespace::new(&binding.namespace, prefix))
            })
            .collect();
        let meta = document.meta;
        Ok(Self {
            original: bytes.to_vec(),
            decoded,
            original_meta: meta.clone(),
            meta,
            namespaces,
        })
    }

    /// The transaction's current property graph.
    #[must_use]
    pub fn meta(&self) -> &XmpMeta {
        &self.meta
    }

    /// Mutable access to the transaction's property graph.
    ///
    /// Prefer [`Self::set`], [`Self::remove`], or [`Self::merge`] for common operations. Direct
    /// mutation remains available because [`XmpMeta`] is intentionally a transparent graph.
    pub fn meta_mut(&mut self) -> &mut XmpMeta {
        &mut self.meta
    }

    /// Inserts or replaces one top-level property.
    pub fn set(&mut self, property: XmpProperty) {
        self.meta.set(property);
    }

    /// Removes one top-level property and reports whether it existed.
    pub fn remove(&mut self, namespace: &str, name: &str) -> bool {
        self.meta.remove(namespace, name).is_some()
    }

    /// Replaces one namespace URI throughout property names and qualifiers.
    ///
    /// The lexical prefix that was bound to `from` is retained as the preferred prefix for `to`.
    /// The return value is the number of expanded names changed; zero leaves the transaction
    /// byte-identical when no other edit was made.
    pub fn remap_namespace(&mut self, from: &str, to: &str) -> usize {
        if from == to {
            return 0;
        }
        for namespace in &mut self.namespaces {
            if namespace.uri == from {
                namespace.uri = to.to_owned();
            }
        }
        remap_properties(&mut self.meta.properties, from, to)
    }

    /// Merges all top-level properties from `other`, replacing equal expanded names.
    pub fn merge(&mut self, other: &XmpMeta) {
        for property in &other.properties {
            self.meta.set(property.clone());
        }
    }

    /// Registers a preferred serialization prefix for a namespace URI.
    ///
    /// Registrations affect changed packets only. An unchanged transaction still returns the
    /// exact source bytes. Prefixes are subject to the same validation and collision rules as
    /// [`XmpWriter::with_namespace`].
    pub fn register_namespace(&mut self, namespace: impl Into<Namespace>) {
        self.namespaces.push(namespace.into());
    }

    /// Completes the transaction.
    ///
    /// An unchanged transaction is byte-identical to its input. A changed transaction preserves
    /// the original encoding, BOM choice, packet instructions, and padding while replacing only
    /// the RDF/XML content region with deterministic canonical serialization.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        if self.meta == self.original_meta {
            return self.original;
        }

        let content = self.decoded.envelope.content;
        let wrap_xmpmeta = packet_uses_xmpmeta(&self.decoded.decoded[content.start..content.end]);
        let writer = self
            .namespaces
            .into_iter()
            .fold(XmpWriter::new(), XmpWriter::with_namespace)
            .wrap_xmpmeta(wrap_xmpmeta);
        let body = writer.serialize_body(&self.meta);
        let mut rewritten = String::with_capacity(
            self.decoded.decoded.len() - (content.end - content.start) + body.len(),
        );
        rewritten.push_str(&self.decoded.decoded[..content.start]);
        rewritten.push_str(&body);
        rewritten.push_str(&self.decoded.decoded[content.end..]);
        encode_packet(&rewritten, self.decoded.encoding, self.decoded.had_bom)
    }
}

fn remap_properties(properties: &mut [XmpProperty], from: &str, to: &str) -> usize {
    properties
        .iter_mut()
        .map(|property| {
            let mut changed = usize::from(property.namespace == from);
            if property.namespace == from {
                property.namespace = to.to_owned();
            }
            changed += remap_properties(&mut property.qualifiers, from, to);
            changed + remap_value(&mut property.value, from, to)
        })
        .sum()
}

fn remap_value(value: &mut XmpValue, from: &str, to: &str) -> usize {
    match value {
        XmpValue::Simple(_) | XmpValue::Uri(_) => 0,
        XmpValue::Structured(properties) => remap_properties(properties, from, to),
        XmpValue::Array(array) => {
            let items = match array {
                XmpArray::Bag(items) | XmpArray::Seq(items) | XmpArray::Alt(items) => items,
            };
            items
                .iter_mut()
                .map(|item| remap_item(item, from, to))
                .sum()
        }
    }
}

fn remap_item(item: &mut XmpItem, from: &str, to: &str) -> usize {
    remap_properties(&mut item.qualifiers, from, to) + remap_value(&mut item.value, from, to)
}

fn packet_uses_xmpmeta(content: &str) -> bool {
    let mut reader = quick_xml::Reader::from_str(content);
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(start))
            | Ok(quick_xml::events::Event::Empty(start)) => {
                let name = start.name();
                return name.local_name().as_ref() == b"xmpmeta"
                    && start
                        .attributes()
                        .filter_map(core::result::Result::ok)
                        .any(|attr| {
                            attr.key.as_ref().starts_with(b"xmlns")
                                && attr.value.as_ref() == XMPMETA_NAMESPACE.as_bytes()
                        });
            }
            Ok(quick_xml::events::Event::Eof) | Err(_) => return false,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WellKnownNs, XmpEncoding, XmpValue};

    const PACKET: &str = concat!(
        "<?xpacket begin='' id='custom'?>\n",
        "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#' ",
        "xmlns:xmp='http://ns.adobe.com/xap/1.0/'>",
        "<rdf:Description rdf:about=''><xmp:Rating>3</xmp:Rating></rdf:Description>",
        "</rdf:RDF>\n   <?xpacket end='w'?>",
    );

    #[test]
    fn unchanged_transaction_returns_exact_source_bytes() {
        let bytes = PACKET.as_bytes();
        assert_eq!(XmpEdit::from_packet(bytes).unwrap().finish(), bytes);
    }

    #[test]
    fn changed_transaction_preserves_envelope_and_padding() {
        let mut edit = XmpEdit::from_packet(PACKET.as_bytes()).unwrap();
        edit.set(XmpProperty::new(
            WellKnownNs::Xmp.uri(),
            "Rating",
            XmpValue::Simple("5".into()),
        ));
        let output = edit.finish();
        let decoded = XmpPacket::scan_with_source(&output).unwrap();
        assert_eq!(decoded.packet.padding, 4);
        assert!(decoded.packet.writable);
        assert_eq!(
            decoded
                .packet
                .parse()
                .unwrap()
                .get_text(WellKnownNs::Xmp.uri(), "Rating"),
            Some("5")
        );
        assert!(
            decoded
                .decoded
                .starts_with("<?xpacket begin='' id='custom'?>")
        );
        assert!(decoded.decoded.ends_with("<?xpacket end='w'?>"));
    }

    #[test]
    fn changed_transaction_retains_wide_encoding_and_bom() {
        let source = encode_packet(PACKET, XmpEncoding::Utf16Le, true);
        let mut edit = XmpEdit::from_packet(&source).unwrap();
        edit.set(XmpProperty::new(
            WellKnownNs::Xmp.uri(),
            "Rating",
            XmpValue::Simple("4".into()),
        ));
        let output = edit.finish();
        assert!(output.starts_with(&[0xFF, 0xFE]));
        let decoded = XmpPacket::scan_with_source(&output).unwrap();
        assert_eq!(decoded.encoding, XmpEncoding::Utf16Le);
        assert!(decoded.had_bom);
        assert_eq!(
            decoded
                .packet
                .parse()
                .unwrap()
                .get_text(WellKnownNs::Xmp.uri(), "Rating"),
            Some("4")
        );
    }

    #[test]
    fn merge_and_remove_are_composable() {
        let mut edit = XmpEdit::from_packet(PACKET.as_bytes()).unwrap();
        let mut additions = XmpMeta::new();
        additions.set_text(WellKnownNs::DublinCore.uri(), "format", "application/pdf");
        edit.merge(&additions);
        assert!(edit.remove(WellKnownNs::Xmp.uri(), "Rating"));
        let parsed = XmpMeta::from_packet(&edit.finish()).unwrap();
        assert!(parsed.get(WellKnownNs::Xmp.uri(), "Rating").is_none());
        assert_eq!(
            parsed.get_text(WellKnownNs::DublinCore.uri(), "format"),
            Some("application/pdf")
        );
    }

    #[test]
    fn changed_transaction_uses_registered_namespace_prefix() {
        let mut edit = XmpEdit::from_packet(PACKET.as_bytes()).unwrap();
        edit.register_namespace(crate::Namespace::new("urn:example:invoice", "invoice"));
        edit.set(XmpProperty::new(
            "urn:example:invoice",
            "Kind",
            XmpValue::Simple("credit-note".into()),
        ));

        let output = String::from_utf8(edit.finish()).unwrap();
        assert!(output.contains("xmlns:invoice=\"urn:example:invoice\""));
        assert!(output.contains("<invoice:Kind>credit-note</invoice:Kind>"));
    }

    #[test]
    fn remaps_namespace_recursively_and_retains_its_prefix() {
        let packet = concat!(
            "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>",
            "<rdf:Description xmlns:old='urn:old'>",
            "<old:Root rdf:parseType='Resource'><old:Child>value</old:Child></old:Root>",
            "</rdf:Description></rdf:RDF>"
        );
        let mut edit = XmpEdit::from_packet(packet.as_bytes()).unwrap();
        assert_eq!(edit.remap_namespace("urn:old", "urn:new"), 2);
        let output = String::from_utf8(edit.finish()).unwrap();
        assert!(output.contains("xmlns:old=\"urn:new\""));
        let meta = XmpMeta::from_packet(output.as_bytes()).unwrap();
        assert!(meta.get("urn:new", "Root").is_some());
        assert!(meta.get("urn:old", "Root").is_none());
    }
}
