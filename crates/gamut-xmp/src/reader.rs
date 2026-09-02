//! The XMP reader: an `<?xpacket?>`-wrapped (or bare) RDF/XML packet → an [`XmpMeta`] graph.
//!
//! Parsing is two phases. Phase 1 ([`build_tree`]) turns the RDF/XML into a small owned tree using
//! `quick-xml`, resolving namespace prefixes to URIs and folding entity references into text — this
//! confines every `quick-xml` interaction to one place. Phase 2 ([`interpret`]) walks that tree and
//! applies the RDF/XML-for-XMP mapping (Part 1 §7, Annex C), which is pure Rust over owned data and
//! so is straightforward to test.
//!
//! The reader is deliberately permissive: it accepts the equivalent input forms XMP allows (Part 1
//! §7.9 — attribute or element form, `rdf:parseType="Resource"`, abbreviated forms, either quote
//! style, any prefix), and rejects the forms the spec prohibits (`rdf:parseType="Literal"` etc.,
//! `rdf:_n` array items, a top-level typed node) with a typed [`XmpError`].

use quick_xml::NsReader;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::{LocalName, QName, ResolveResult};

use crate::XmpSourceSpan;
use crate::error::{Result, XmpError};
use crate::model::{XmpArray, XmpItem, XmpMeta, XmpProperty, XmpValue};
use crate::namespace::{RDF_NAMESPACE, XML_NAMESPACE, XMPMETA_NAMESPACE};
use crate::packet::{DecodedXmpPacket, XmpPacket};

/// Lexical form used by a top-level XMP property declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XmpPropertyForm {
    /// An XML attribute on `rdf:Description`.
    Attribute,
    /// A child element of `rdf:Description`.
    Element,
}

/// Source location and lexical name of one top-level XMP property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmpPropertyLocation {
    /// Expanded namespace URI.
    pub namespace: String,
    /// Local property name.
    pub name: String,
    /// Prefix used by this declaration, without the colon.
    pub prefix: Option<String>,
    /// Declaration form.
    pub form: XmpPropertyForm,
    /// Exact element span, or the containing start-tag span for attribute form.
    pub span: XmpSourceSpan,
}

/// One namespace declaration encountered in the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmpNamespaceBinding {
    /// Declared prefix, or `None` for the default namespace.
    pub prefix: Option<String>,
    /// Bound namespace URI.
    pub namespace: String,
    /// Span of the start tag carrying the declaration.
    pub span: XmpSourceSpan,
}

/// Source and subject spelling of one top-level `rdf:Description`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmpDescriptionLocation {
    /// Full element span.
    pub span: XmpSourceSpan,
    /// Value of `rdf:about` or `rdf:ID`, when either is present.
    pub subject: Option<String>,
    /// Prefix used on the subject attribute.
    pub subject_prefix: Option<String>,
}

/// An XMP graph together with the lexical facts needed by validation and editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmpDocument {
    /// Namespace-neutral property graph.
    pub meta: XmpMeta,
    /// Top-level property declarations in document order.
    pub properties: Vec<XmpPropertyLocation>,
    /// Every namespaced XMP data node, including nested structure fields and attributes.
    pub nodes: Vec<XmpPropertyLocation>,
    /// Namespace bindings in document order.
    pub namespaces: Vec<XmpNamespaceBinding>,
    /// Top-level resource descriptions in document order.
    pub descriptions: Vec<XmpDescriptionLocation>,
    /// Prefix used on the `rdf:RDF` element.
    pub rdf_prefix: Option<String>,
    /// Whether `rdf:RDF` is wrapped in an `x:xmpmeta` element by namespace identity.
    pub root_is_xmpmeta: bool,
}

impl XmpMeta {
    /// Parses an XMP packet into a property graph.
    ///
    /// Accepts a packet with or without the `<?xpacket?>` wrapper (so it works on a WebP `XMP `
    /// chunk, an AVIF `mime` item, a JPEG `APP1` payload, or a bare `rdf:RDF` / `x:xmpmeta` body),
    /// decoding UTF-8, UTF-16, or UTF-32 in either byte order.
    ///
    /// This is exactly [`XmpPacket::scan`] followed by [`XmpPacket::parse`]; scan first instead
    /// when the envelope matters (its writability and padding drive in-place editing).
    ///
    /// # Errors
    ///
    /// Returns an [`XmpError`] if the packet encoding or XML is malformed, there is no `rdf:RDF`
    /// element, the same expanded top-level property is declared twice, or the RDF/XML uses a
    /// construct XMP does not permit.
    pub fn from_packet(bytes: &[u8]) -> Result<XmpMeta> {
        Ok(XmpPacket::scan_with_source(bytes)?.parse()?.meta)
    }
}

impl DecodedXmpPacket {
    /// Parses the decoded packet into its property graph and lexical source layout.
    ///
    /// Every span indexes [`Self::decoded`], including for packets transcoded from UTF-16/32.
    ///
    /// # Errors
    ///
    /// Returns an [`XmpError`] if the XML or XMP data model is malformed or ambiguous.
    pub fn parse(&self) -> Result<XmpDocument> {
        let content = self.envelope.content;
        parse_document(&self.decoded[content.start..content.end], content.start)
    }
}

impl XmpPacket {
    /// Parses this packet's RDF/XML body into a property graph.
    ///
    /// # Examples
    ///
    /// Inspect the envelope, then edit in place, preserving the packet's writability and padding:
    ///
    /// ```
    /// use gamut_xmp::{WellKnownNs, XmpPacket, XmpWriter};
    ///
    /// # let original = gamut_xmp::XmpMeta::new().to_packet();
    /// let packet = XmpPacket::scan(&original)?;
    /// let mut meta = packet.parse()?;
    /// meta.set_text(WellKnownNs::Xmp.uri(), "CreatorTool", "gamut");
    /// let rewritten = XmpWriter::new()
    ///     .writable(packet.writable)
    ///     .padding(packet.padding)
    ///     .serialize(&meta);
    /// # assert!(!rewritten.is_empty());
    /// # Ok::<(), gamut_xmp::XmpError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an [`XmpError`] if the body is malformed XML, has no `rdf:RDF` element, or uses an
    /// RDF/XML construct XMP does not permit.
    pub fn parse(&self) -> Result<XmpMeta> {
        Ok(parse_document(&self.body, 0)?.meta)
    }
}

// ---------------------------------------------------------------------------------------------------
// Phase 1: a small owned XML tree.
// ---------------------------------------------------------------------------------------------------

/// An XML element with namespace-resolved names, owned so phase 2 needs no `quick-xml` lifetimes.
struct Element {
    /// Exact element span in decoded UTF-8 source bytes.
    span: XmpSourceSpan,
    /// Prefix used by the element name, without the colon.
    prefix: Option<String>,
    /// The element's namespace URI, or `None` if it is in no namespace.
    ns: Option<String>,
    /// The element's local name.
    local: String,
    /// Resolved attributes, excluding `xmlns` declarations.
    attrs: Vec<Attr>,
    /// Namespace declarations carried by this element's start tag.
    bindings: Vec<XmpNamespaceBinding>,
    /// Child nodes in document order.
    children: Vec<Node>,
}

/// A child of an [`Element`]: a nested element or a run of text.
enum Node {
    /// A nested element.
    Element(Element),
    /// Character data (text, CDATA, and resolved entity references, concatenated).
    Text(String),
}

/// A namespace-resolved attribute.
struct Attr {
    /// Prefix used by the attribute name, without the colon.
    prefix: Option<String>,
    /// The attribute's namespace URI, or `None` for an unprefixed attribute.
    ns: Option<String>,
    /// The attribute's local name.
    local: String,
    /// The attribute's (unescaped) value.
    value: String,
}

/// Lexes `xml` into the top-level [`Element`] (`x:xmpmeta` or `rdf:RDF`).
fn build_tree(xml: &str, base: usize) -> Result<Element> {
    let mut reader = NsReader::from_str(xml);
    // `<x/>` and `<x></x>` then look the same to phase 2; whitespace is preserved (default config)
    // because it is significant inside a simple value (Part 1 §7.5).
    reader.config_mut().expand_empty_elements = true;

    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    loop {
        let event_start = base
            + usize::try_from(reader.buffer_position())
                .map_err(|_| XmpError::Xml("XML source position exceeds usize".into()))?;
        let event = reader.read_event().map_err(xml_error)?;
        let event_end = base
            + usize::try_from(reader.buffer_position())
                .map_err(|_| XmpError::Xml("XML source position exceeds usize".into()))?;
        if matches!(event, Event::Eof) {
            break;
        }
        match event {
            Event::Start(e) => stack.push(start_element(&reader, &e, event_start, event_end)?),
            Event::End(_) => {
                let mut done = stack
                    .pop()
                    .ok_or_else(|| XmpError::Xml("unbalanced end tag".into()))?;
                done.span.end = event_end;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(done)),
                    None if root.is_some() => {
                        return Err(XmpError::Xml("multiple root elements".into()));
                    }
                    None => root = Some(done),
                }
            }
            Event::Text(t) => {
                let text = t.decode().map_err(|e| XmpError::Xml(e.to_string()))?;
                push_text(&mut stack, &text);
            }
            Event::CData(c) => {
                let text = c.decode().map_err(|e| XmpError::Xml(e.to_string()))?;
                push_text(&mut stack, &text);
            }
            Event::GeneralRef(r) => push_text(&mut stack, &resolve_entity(&r)?),
            // Declaration, processing instructions, comments, and DOCTYPE carry no XMP data
            // (Eof exited above).
            _ => {}
        }
    }

    root.ok_or(XmpError::MissingRdf)
}

/// Builds an owned [`Element`] from a start tag, resolving its name and attributes.
fn start_element<R>(
    reader: &NsReader<R>,
    e: &BytesStart,
    start: usize,
    end: usize,
) -> Result<Element> {
    let (ns, local) = resolve_element(reader, e.name())?;
    let prefix = lexical_prefix(e.name().as_ref());
    let mut attrs = Vec::new();
    let mut bindings = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| XmpError::Xml(err.to_string()))?;
        // `xmlns`/`xmlns:*` are namespace declarations, not data; the resolver already consumed them.
        if attr.key.0 == b"xmlns" || attr.key.0.starts_with(b"xmlns:") {
            bindings.push(XmpNamespaceBinding {
                prefix: attr.key.0.strip_prefix(b"xmlns:").map(decode),
                namespace: decode(attr.value.as_ref()),
                span: XmpSourceSpan { start, end },
            });
            continue;
        }
        let (ans, alocal) = resolve_attribute(reader, attr.key)?;
        // XML normalizes attribute values (entities resolved, tab/CR/LF → space); XMP packets are
        // XML 1.0 with no explicit declaration.
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|err| XmpError::Xml(err.to_string()))?
            .into_owned();
        attrs.push(Attr {
            prefix: lexical_prefix(attr.key.as_ref()),
            ns: ans,
            local: alocal,
            value,
        });
    }
    Ok(Element {
        span: XmpSourceSpan { start, end },
        prefix,
        ns,
        local,
        attrs,
        bindings,
        children: Vec::new(),
    })
}

fn lexical_prefix(name: &[u8]) -> Option<String> {
    let colon = name.iter().position(|byte| *byte == b':')?;
    Some(decode(&name[..colon]))
}

/// Resolves an element's qualified name to `(namespace URI, local name)`.
fn resolve_element<R>(reader: &NsReader<R>, name: QName) -> Result<(Option<String>, String)> {
    let (resolved, local) = reader.resolver().resolve_element(name);
    finish_resolve(resolved, local)
}

/// Resolves an attribute's qualified name. Unlike elements, an unprefixed attribute is in no
/// namespace (the default namespace does not apply to attributes).
fn resolve_attribute<R>(reader: &NsReader<R>, name: QName) -> Result<(Option<String>, String)> {
    let (resolved, local) = reader.resolver().resolve_attribute(name);
    finish_resolve(resolved, local)
}

/// Turns a resolution result into owned strings, surfacing an undeclared prefix as a typed error.
fn finish_resolve(resolved: ResolveResult, local: LocalName) -> Result<(Option<String>, String)> {
    let ns = match resolved {
        ResolveResult::Bound(ns) => Some(decode(ns.as_ref())),
        ResolveResult::Unbound => None,
        ResolveResult::Unknown(prefix) => return Err(XmpError::UnknownPrefix(decode(&prefix))),
    };
    Ok((ns, decode(local.as_ref())))
}

/// Resolves a general/character entity reference (`&amp;`, `&#x41;`, …) to its text.
fn resolve_entity(reference: &BytesRef) -> Result<String> {
    let name = reference
        .decode()
        .map_err(|e| XmpError::Xml(e.to_string()))?;
    quick_xml::escape::unescape(&format!("&{name};"))
        .map(|cow| cow.into_owned())
        .map_err(|e| XmpError::Xml(e.to_string()))
}

/// Appends a text run to the innermost open element. Consecutive runs (split by entity references)
/// stay as separate nodes; [`text_content`] concatenates them, so the split is invisible.
fn push_text(stack: &mut [Element], text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(elem) = stack.last_mut() {
        elem.children.push(Node::Text(text.to_owned()));
    }
}

/// UTF-8 bytes → `String`. The packet is validated as UTF-8 before lexing, so this never loses data.
fn decode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Maps a `quick-xml` lexing error into an [`XmpError`] without exposing the `quick-xml` type.
fn xml_error(err: quick_xml::Error) -> XmpError {
    XmpError::Xml(err.to_string())
}

// ---------------------------------------------------------------------------------------------------
// Phase 2: interpret the tree as XMP (Part 1 §7, Annex C).
// ---------------------------------------------------------------------------------------------------

/// Walks the parsed tree into an [`XmpMeta`].
fn parse_document(xml: &str, base: usize) -> Result<XmpDocument> {
    interpret(&build_tree(xml, base)?)
}

fn interpret(root: &Element) -> Result<XmpDocument> {
    let rdf = find_rdf(root)?;
    let mut meta = XmpMeta::new();
    let mut seen = Vec::new();
    let mut properties = Vec::new();
    let mut descriptions = Vec::new();
    for desc in rdf.children.iter().filter_map(node_element) {
        if is(desc, RDF_NAMESPACE, "Description") {
            let subject = desc.attrs.iter().find(|attribute| {
                attribute.ns.as_deref() == Some(RDF_NAMESPACE)
                    && matches!(attribute.local.as_str(), "about" | "ID")
            });
            descriptions.push(XmpDescriptionLocation {
                span: desc.span,
                subject: subject.map(|attribute| attribute.value.clone()),
                subject_prefix: subject.and_then(|attribute| attribute.prefix.clone()),
            });
            parse_description(desc, &mut meta, &mut seen, &mut properties)?;
        } else {
            // A top-level typed node is prohibited in XMP (Part 1 §7.9.2.5).
            return Err(XmpError::Prohibited(format!(
                "top-level <{}> is not rdf:Description",
                desc.local
            )));
        }
    }
    let mut namespaces = Vec::new();
    collect_bindings(root, &mut namespaces);
    let mut nodes = Vec::new();
    collect_data_nodes(root, &mut nodes);
    Ok(XmpDocument {
        meta,
        properties,
        nodes,
        namespaces,
        descriptions,
        rdf_prefix: rdf.prefix.clone(),
        root_is_xmpmeta: is(root, XMPMETA_NAMESPACE, "xmpmeta"),
    })
}

fn collect_data_nodes(element: &Element, output: &mut Vec<XmpPropertyLocation>) {
    for attribute in &element.attrs {
        if let Some(property) = data_attr_property(attribute) {
            output.push(XmpPropertyLocation {
                namespace: property.namespace,
                name: property.name,
                prefix: attribute.prefix.clone(),
                form: XmpPropertyForm::Attribute,
                span: element.span,
            });
        }
    }
    for child in element.children.iter().filter_map(node_element) {
        if let Some(namespace) = &child.ns
            && namespace != RDF_NAMESPACE
            && namespace != XMPMETA_NAMESPACE
        {
            output.push(XmpPropertyLocation {
                namespace: namespace.clone(),
                name: child.local.clone(),
                prefix: child.prefix.clone(),
                form: XmpPropertyForm::Element,
                span: child.span,
            });
        }
        collect_data_nodes(child, output);
    }
}

fn collect_bindings(element: &Element, output: &mut Vec<XmpNamespaceBinding>) {
    output.extend(element.bindings.iter().cloned());
    for child in element.children.iter().filter_map(node_element) {
        collect_bindings(child, output);
    }
}

/// Finds the `rdf:RDF` element, looking inside an optional `x:xmpmeta` wrapper (Part 1 §7.3.3).
fn find_rdf(root: &Element) -> Result<&Element> {
    if is(root, RDF_NAMESPACE, "RDF") {
        return Ok(root);
    }
    if is(root, XMPMETA_NAMESPACE, "xmpmeta")
        && let Some(rdf) = root
            .children
            .iter()
            .filter_map(node_element)
            .find(|e| is(e, RDF_NAMESPACE, "RDF"))
    {
        return Ok(rdf);
    }
    Err(XmpError::MissingRdf)
}

/// Reads one `rdf:Description`'s properties (both attribute and element forms) into `meta`.
fn parse_description(
    desc: &Element,
    meta: &mut XmpMeta,
    seen: &mut Vec<((String, String), XmpSourceSpan)>,
    locations: &mut Vec<XmpPropertyLocation>,
) -> Result<()> {
    // Simple unqualified properties may be written as attributes on the Description (Part 1
    // §7.9.2.2); `rdf:about`/`rdf:ID` and `xml:lang` are not data and are skipped.
    for attr in &desc.attrs {
        let Some(prop) = data_attr_property(attr) else {
            continue;
        };
        let location = XmpPropertyLocation {
            namespace: prop.namespace.clone(),
            name: prop.name.clone(),
            prefix: attr.prefix.clone(),
            form: XmpPropertyForm::Attribute,
            span: desc.span,
        };
        insert_unique(meta, seen, prop, desc.span)?;
        locations.push(location);
    }
    for child in desc.children.iter().filter_map(node_element) {
        let property = parse_property(child)?;
        let location = XmpPropertyLocation {
            namespace: property.namespace.clone(),
            name: property.name.clone(),
            prefix: child.prefix.clone(),
            form: XmpPropertyForm::Element,
            span: child.span,
        };
        insert_unique(meta, seen, property, child.span)?;
        locations.push(location);
    }
    Ok(())
}

fn insert_unique(
    meta: &mut XmpMeta,
    seen: &mut Vec<((String, String), XmpSourceSpan)>,
    property: XmpProperty,
    span: XmpSourceSpan,
) -> Result<()> {
    let key = (property.namespace.clone(), property.name.clone());
    if let Some((_, first)) = seen.iter().find(|(candidate, _)| candidate == &key) {
        return Err(XmpError::DuplicateProperty {
            namespace: key.0,
            name: key.1,
            first: *first,
            duplicate: span,
        });
    }
    seen.push((key, span));
    meta.set(property);
    Ok(())
}

/// Parses a property element into an [`XmpProperty`].
fn parse_property(elem: &Element) -> Result<XmpProperty> {
    let namespace = elem.ns.clone().ok_or_else(|| {
        XmpError::Prohibited(format!("property <{}> has no namespace", elem.local))
    })?;
    let (value, qualifiers) = parse_value(elem)?;
    Ok(XmpProperty {
        namespace,
        name: elem.local.clone(),
        value,
        qualifiers,
    })
}

/// Determines a property/field/item's value and qualifiers from its element, following the Annex C
/// disambiguation (by attributes and content, not element name).
fn parse_value(elem: &Element) -> Result<(XmpValue, Vec<XmpProperty>)> {
    // 1. `rdf:parseType` — only "Resource" (the concise struct form, §7.9.2.3) is allowed.
    if let Some(parse_type) = attr(elem, RDF_NAMESPACE, "parseType") {
        if parse_type == "Resource" {
            return Ok((
                XmpValue::Structured(struct_fields(elem)?),
                lang_qualifier(elem),
            ));
        }
        return Err(XmpError::UnsupportedForm(format!(
            "rdf:parseType=\"{parse_type}\" on <{}> (only \"Resource\" is allowed)",
            elem.local
        )));
    }

    // 2. Resource form: a single nested node element (a struct, array, or qualified value, §7.6–7.8).
    let mut child_elements = elem.children.iter().filter_map(node_element);
    if let Some(node) = child_elements.next() {
        if child_elements.next().is_some() {
            return Err(XmpError::Prohibited(format!(
                "<{}> has multiple child elements; expected one rdf:Bag/Seq/Alt or rdf:Description",
                elem.local
            )));
        }
        let (value, node_qualifiers) = parse_node(node)?;
        let mut qualifiers = element_qualifiers(elem);
        qualifiers.extend(node_qualifiers);
        return Ok((value, qualifiers));
    }

    // 3. No child elements — an attribute-driven or literal form (Annex C.2.7, C.2.12).
    if let Some(uri) = attr(elem, RDF_NAMESPACE, "resource") {
        return Ok((XmpValue::Uri(uri.to_owned()), element_qualifiers(elem)));
    }
    if let Some(value) = attr(elem, RDF_NAMESPACE, "value") {
        return Ok((XmpValue::Simple(value.to_owned()), element_qualifiers(elem)));
    }

    let text = text_content(elem);
    let data_attrs: Vec<XmpProperty> = elem.attrs.iter().filter_map(data_attr_property).collect();
    if data_attrs.is_empty() {
        // Plain literal (or empty) value; only `xml:lang` can qualify it.
        Ok((XmpValue::Simple(text), lang_qualifier(elem)))
    } else if text.trim().is_empty() {
        // Empty element with data attributes → a structure whose fields are those attributes
        // (Annex C.2.12 rule 4).
        Ok((XmpValue::Structured(data_attrs), lang_qualifier(elem)))
    } else {
        // Literal value carrying qualifiers as attributes (Annex C.2.7).
        Ok((XmpValue::Simple(text), element_qualifiers(elem)))
    }
}

/// Parses the nested node of a resource-form property: an array, a structure, or — when the node is
/// an `rdf:Description` holding an `rdf:value` — a value with general qualifiers (Part 1 §7.8).
fn parse_node(node: &Element) -> Result<(XmpValue, Vec<XmpProperty>)> {
    if is(node, RDF_NAMESPACE, "Bag") {
        return Ok((
            XmpValue::Array(XmpArray::Bag(parse_items(node)?)),
            Vec::new(),
        ));
    }
    if is(node, RDF_NAMESPACE, "Seq") {
        return Ok((
            XmpValue::Array(XmpArray::Seq(parse_items(node)?)),
            Vec::new(),
        ));
    }
    if is(node, RDF_NAMESPACE, "Alt") {
        let items = parse_items(node)?;
        check_unique_langs(&items)?;
        return Ok((XmpValue::Array(XmpArray::Alt(items)), Vec::new()));
    }
    if is(node, RDF_NAMESPACE, "Description") {
        return parse_description_node(node);
    }

    // Any other element where a node is expected is a typed node (Part 1 §7.9.2.5): a structure
    // with an `rdf:type` qualifier naming the type's URI.
    let type_ns = node.ns.as_deref().ok_or_else(|| {
        XmpError::Prohibited(format!("typed node <{}> has no namespace", node.local))
    })?;
    let type_uri = format!("{type_ns}{}", node.local);
    let qualifiers = vec![XmpProperty::new(
        RDF_NAMESPACE,
        "type",
        XmpValue::Uri(type_uri),
    )];
    Ok((XmpValue::Structured(struct_fields(node)?), qualifiers))
}

/// Interprets an `rdf:Description` node as a structure, or as a qualified value when it carries an
/// `rdf:value` child (Part 1 §7.8).
fn parse_description_node(node: &Element) -> Result<(XmpValue, Vec<XmpProperty>)> {
    let value_child = node
        .children
        .iter()
        .filter_map(node_element)
        .find(|e| is(e, RDF_NAMESPACE, "value"));

    let Some(value_elem) = value_child else {
        return Ok((XmpValue::Structured(struct_fields(node)?), Vec::new()));
    };

    let (value, value_qualifiers) = parse_value(value_elem)?;
    if !value_qualifiers.is_empty() {
        return Err(XmpError::Prohibited(
            "rdf:value must not carry xml:lang or nested qualifiers (Part 1 §7.8)".into(),
        ));
    }
    let mut qualifiers = Vec::new();
    for child in node.children.iter().filter_map(node_element) {
        if !is(child, RDF_NAMESPACE, "value") {
            qualifiers.push(parse_property(child)?);
        }
    }
    qualifiers.extend(node.attrs.iter().filter_map(data_attr_property));
    Ok((value, qualifiers))
}

/// Parses the `rdf:li` items of an array container.
fn parse_items(container: &Element) -> Result<Vec<XmpItem>> {
    let mut items = Vec::new();
    for child in container.children.iter().filter_map(node_element) {
        if is(child, RDF_NAMESPACE, "li") {
            let (value, qualifiers) = parse_value(child)?;
            items.push(XmpItem { value, qualifiers });
        } else if child.ns.as_deref() == Some(RDF_NAMESPACE) && child.local.starts_with('_') {
            return Err(XmpError::Prohibited(format!(
                "rdf:{} array item (use rdf:li, Part 1 §7.9.3.3)",
                child.local
            )));
        } else {
            return Err(XmpError::Prohibited(format!(
                "<{}> in an rdf array (expected rdf:li)",
                child.local
            )));
        }
    }
    Ok(items)
}

/// The struct fields of an element: data attributes (Part 1 §7.9.2.4) followed by child elements.
fn struct_fields(elem: &Element) -> Result<Vec<XmpProperty>> {
    let mut fields: Vec<XmpProperty> = elem.attrs.iter().filter_map(data_attr_property).collect();
    for child in elem.children.iter().filter_map(node_element) {
        fields.push(parse_property(child)?);
    }
    Ok(fields)
}

/// An element's qualifiers in forms where attributes annotate the value: `xml:lang` plus every data
/// attribute (Annex C.2.7 / C.2.12).
fn element_qualifiers(elem: &Element) -> Vec<XmpProperty> {
    let mut qualifiers = lang_qualifier(elem);
    qualifiers.extend(elem.attrs.iter().filter_map(data_attr_property));
    qualifiers
}

/// Just the `xml:lang` qualifier of an element, if present.
fn lang_qualifier(elem: &Element) -> Vec<XmpProperty> {
    attr(elem, XML_NAMESPACE, "lang")
        .map(|lang| XmpProperty::new(XML_NAMESPACE, "lang", XmpValue::Simple(lang.to_owned())))
        .into_iter()
        .collect()
}

/// A data attribute (one in a real schema namespace, not `rdf:`/`xml:`) as a simple property —
/// used both as a struct field and as a qualifier depending on context.
fn data_attr_property(attr: &Attr) -> Option<XmpProperty> {
    let ns = attr.ns.as_deref()?;
    if ns == RDF_NAMESPACE || ns == XML_NAMESPACE {
        return None;
    }
    Some(XmpProperty::new(
        ns,
        attr.local.clone(),
        XmpValue::Simple(attr.value.clone()),
    ))
}

/// Rejects an `rdf:Alt` with two items sharing an `xml:lang` (Part 1 §8.2.2.4 requires uniqueness).
fn check_unique_langs(items: &[XmpItem]) -> Result<()> {
    let mut seen: Vec<String> = Vec::new();
    for item in items {
        if let Some(lang) = item.lang() {
            let normalized = lang.to_ascii_lowercase();
            if seen.contains(&normalized) {
                return Err(XmpError::DuplicateLang(lang.to_owned()));
            }
            seen.push(normalized);
        }
    }
    Ok(())
}

/// Whether `n` is an element node.
fn node_element(n: &Node) -> Option<&Element> {
    match n {
        Node::Element(e) => Some(e),
        Node::Text(_) => None,
    }
}

/// Whether `e` has the given namespace URI and local name.
fn is(e: &Element, ns: &str, local: &str) -> bool {
    e.ns.as_deref() == Some(ns) && e.local == local
}

/// The value of `e`'s attribute with the given namespace URI and local name, if present.
fn attr<'a>(e: &'a Element, ns: &str, local: &str) -> Option<&'a str> {
    e.attrs
        .iter()
        .find(|a| a.ns.as_deref() == Some(ns) && a.local == local)
        .map(|a| a.value.as_str())
}

/// The concatenated text content of an element's direct text children.
fn text_content(e: &Element) -> String {
    e.children
        .iter()
        .filter_map(|n| match n {
            Node::Text(t) => Some(t.as_str()),
            Node::Element(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DC: &str = "http://purl.org/dc/elements/1.1/";
    const XMP: &str = "http://ns.adobe.com/xap/1.0/";
    const FOO: &str = "http://example.com/foo/";

    fn parse(xml: &str) -> XmpMeta {
        XmpMeta::from_packet(xml.as_bytes()).expect("parse")
    }

    /// Wraps a body in a minimal `rdf:RDF` with the namespaces the tests use.
    fn rdf(body: &str) -> String {
        format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:dc=\"{DC}\" xmlns:xmp=\"{XMP}\" \
             xmlns:foo=\"{FOO}\">\
             <rdf:Description rdf:about=\"\">{body}</rdf:Description></rdf:RDF>"
        )
    }

    #[test]
    fn parses_simple_text_property() {
        let meta = parse(&rdf("<xmp:Rating>3</xmp:Rating>"));
        assert_eq!(meta.get_text(XMP, "Rating"), Some("3"));
    }

    #[test]
    fn parses_simple_property_in_attribute_form() {
        // Same graph as the element form (Part 1 §7.9.2.2).
        let meta = parse(&format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:xmp=\"{XMP}\">\
             <rdf:Description rdf:about=\"\" xmp:Rating=\"3\"/></rdf:RDF>"
        ));
        assert_eq!(meta.get_text(XMP, "Rating"), Some("3"));
    }

    #[test]
    fn uri_value_uses_rdf_resource() {
        let meta = parse(&rdf("<xmp:BaseURL rdf:resource=\"http://example.com/\"/>"));
        assert_eq!(
            meta.get(XMP, "BaseURL").map(|p| &p.value),
            Some(&XmpValue::Uri("http://example.com/".into()))
        );
    }

    #[test]
    fn entity_references_and_whitespace_are_preserved() {
        let meta = parse(&rdf("<dc:format>a &amp; b &lt; c</dc:format>"));
        assert_eq!(meta.get_text(DC, "format"), Some("a & b < c"));
        // Leading/trailing whitespace in a simple value is significant (Part 1 §7.5).
        let meta = parse(&rdf("<dc:format>  x  </dc:format>"));
        assert_eq!(meta.get_text(DC, "format"), Some("  x  "));
    }

    #[test]
    fn parses_bag_seq_alt_arrays() {
        let meta = parse(&rdf(
            "<dc:subject><rdf:Bag><rdf:li>a</rdf:li><rdf:li>b</rdf:li></rdf:Bag></dc:subject>",
        ));
        let XmpValue::Array(XmpArray::Bag(items)) = &meta.get(DC, "subject").unwrap().value else {
            panic!("expected Bag");
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].text(), Some("a"));
        assert_eq!(items[1].text(), Some("b"));
    }

    #[test]
    fn parses_language_alternative() {
        let meta = parse(&rdf("<dc:title><rdf:Alt>\
             <rdf:li xml:lang=\"x-default\">Hi</rdf:li>\
             <rdf:li xml:lang=\"fr\">Salut</rdf:li>\
             </rdf:Alt></dc:title>"));
        assert_eq!(meta.get_lang_alt(DC, "title", "x-default"), Some("Hi"));
        assert_eq!(meta.get_lang_alt(DC, "title", "fr"), Some("Salut"));
    }

    #[test]
    fn parses_structure_both_forms_to_same_graph() {
        let nested = parse(&rdf(
            "<xmp:Thumb><rdf:Description><xmp:w>9</xmp:w></rdf:Description></xmp:Thumb>",
        ));
        let concise = parse(&rdf(
            "<xmp:Thumb rdf:parseType=\"Resource\"><xmp:w>9</xmp:w></xmp:Thumb>",
        ));
        assert_eq!(nested.get(XMP, "Thumb"), concise.get(XMP, "Thumb"));
        let XmpValue::Structured(fields) = &nested.get(XMP, "Thumb").unwrap().value else {
            panic!("expected struct");
        };
        assert_eq!(fields[0].name, "w");
        assert_eq!(fields[0].text(), Some("9"));
    }

    #[test]
    fn parses_general_qualifier_form() {
        let meta = parse(&rdf("<dc:rights><rdf:Description>\
             <rdf:value>(c) Me</rdf:value>\
             <xmp:owner>Me</xmp:owner>\
             </rdf:Description></dc:rights>"));
        let prop = meta.get(DC, "rights").unwrap();
        assert_eq!(prop.value, XmpValue::Simple("(c) Me".into()));
        assert_eq!(prop.qualifiers.len(), 1);
        assert_eq!(prop.qualifiers[0].name, "owner");
        assert_eq!(prop.qualifiers[0].text(), Some("Me"));
    }

    #[test]
    fn xml_lang_attribute_becomes_a_qualifier() {
        let meta = parse(&rdf("<dc:format xml:lang=\"en\">text/plain</dc:format>"));
        let prop = meta.get(DC, "format").unwrap();
        assert_eq!(prop.lang(), Some("en"));
    }

    #[test]
    fn default_lang_on_description_is_ignored() {
        // A default xml:lang on rdf:Description is not propagated to the properties it scopes.
        // Adobe XMPCore behaves the same (pinned against the oracle in tests/oracle.rs); the
        // intentional skip is documented in STATUS.md.
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:dc=\"{DC}\">\
             <rdf:Description rdf:about=\"\" xml:lang=\"fr\">\
             <dc:format>text/plain</dc:format></rdf:Description></rdf:RDF>"
        );
        let meta = parse(&xml);
        let prop = meta.get(DC, "format").unwrap();
        assert_eq!(prop.text(), Some("text/plain"));
        assert!(
            prop.qualifiers.is_empty(),
            "no inherited xml:lang qualifier"
        );
    }

    #[test]
    fn finds_rdf_inside_xmpmeta_wrapper() {
        let meta = parse(&format!(
            "<x:xmpmeta xmlns:x=\"{XMPMETA_NAMESPACE}\">{}</x:xmpmeta>",
            rdf("<xmp:Rating>5</xmp:Rating>")
        ));
        assert_eq!(meta.get_text(XMP, "Rating"), Some("5"));
    }

    #[test]
    fn rejects_disallowed_parse_type() {
        let err =
            XmpMeta::from_packet(rdf("<dc:x rdf:parseType=\"Literal\"><b/></dc:x>").as_bytes())
                .unwrap_err();
        assert!(matches!(err, XmpError::UnsupportedForm(_)), "got {err:?}");
    }

    #[test]
    fn rejects_parse_type_collection() {
        // parseType="Collection" shares a branch with "Literal" but must surface its own name in
        // the diagnostic (Part 1 §7.9 allows only "Resource").
        let err = XmpMeta::from_packet(rdf("<dc:x rdf:parseType=\"Collection\"/>").as_bytes())
            .unwrap_err();
        assert!(
            matches!(&err, XmpError::UnsupportedForm(m) if m.contains("Collection")),
            "got {err:?}"
        );
    }

    #[test]
    fn rdf_id_nodeid_and_xml_base_are_ignored() {
        // The permissive read skips rdf:ID/rdf:nodeID/xml:base (RDF reification and base-URI
        // machinery XMP does not use) rather than folding them into data — the documented posture.
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:dc=\"{DC}\">\
             <rdf:Description rdf:about=\"\" rdf:ID=\"n1\" rdf:nodeID=\"n2\" \
             xml:base=\"http://example.com/\">\
             <dc:format rdf:ID=\"n3\">text/plain</dc:format>\
             </rdf:Description></rdf:RDF>"
        );
        let meta = parse(&xml);
        assert_eq!(meta.properties.len(), 1, "no spurious properties");
        let prop = meta.get(DC, "format").unwrap();
        assert_eq!(prop.text(), Some("text/plain"));
        assert!(
            prop.qualifiers.is_empty(),
            "rdf:ID must not become a qualifier: {:?}",
            prop.qualifiers
        );
    }

    #[test]
    fn multiple_descriptions_merge_into_one_graph() {
        // Part 1 §7.4: rdf:RDF may hold several rdf:Description elements about the same
        // resource; their properties form one graph.
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:dc=\"{DC}\" xmlns:xmp=\"{XMP}\">\
             <rdf:Description rdf:about=\"\"><dc:format>text/plain</dc:format></rdf:Description>\
             <rdf:Description rdf:about=\"\"><xmp:Rating>3</xmp:Rating></rdf:Description>\
             </rdf:RDF>"
        );
        let meta = parse(&xml);
        assert_eq!(meta.properties.len(), 2);
        assert_eq!(meta.get_text(DC, "format"), Some("text/plain"));
        assert_eq!(meta.get_text(XMP, "Rating"), Some("3"));
    }

    #[test]
    fn duplicate_element_properties_are_rejected_with_source_spans() {
        let xml = rdf("<dc:format>first</dc:format><dc:format>second</dc:format>");
        let err = XmpMeta::from_packet(xml.as_bytes()).unwrap_err();
        let XmpError::DuplicateProperty {
            namespace,
            name,
            first,
            duplicate,
        } = err
        else {
            panic!("expected duplicate-property diagnostic");
        };
        assert_eq!(namespace, DC);
        assert_eq!(name, "format");
        assert_eq!(&xml[first.start..first.end], "<dc:format>first</dc:format>");
        assert_eq!(
            &xml[duplicate.start..duplicate.end],
            "<dc:format>second</dc:format>"
        );
    }

    #[test]
    fn duplicate_properties_across_descriptions_are_rejected() {
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:dc=\"{DC}\">\
             <rdf:Description><dc:format>first</dc:format></rdf:Description>\
             <rdf:Description><dc:format>second</dc:format></rdf:Description>\
             </rdf:RDF>"
        );
        assert!(matches!(
            XmpMeta::from_packet(xml.as_bytes()),
            Err(XmpError::DuplicateProperty { .. })
        ));
    }

    #[test]
    fn attribute_and_element_forms_of_one_property_are_duplicates() {
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:xmp=\"{XMP}\">\
             <rdf:Description xmp:Rating=\"3\"><xmp:Rating>4</xmp:Rating></rdf:Description>\
             </rdf:RDF>"
        );
        assert!(matches!(
            XmpMeta::from_packet(xml.as_bytes()),
            Err(XmpError::DuplicateProperty { namespace, name, .. })
                if namespace == XMP && name == "Rating"
        ));
    }

    #[test]
    fn equal_local_names_in_distinct_namespaces_are_not_duplicates() {
        let meta = parse(&rdf("<dc:format>a</dc:format><foo:format>b</foo:format>"));
        assert_eq!(meta.get_text(DC, "format"), Some("a"));
        assert_eq!(meta.get_text(FOO, "format"), Some("b"));
    }

    #[test]
    fn decoded_document_exposes_property_and_namespace_layout() {
        let xml = format!(
            "<?xpacket begin='' id='x'?>{}<?xpacket end='r'?>",
            rdf("<dc:format>text/plain</dc:format>")
        );
        let decoded = XmpPacket::scan_with_source(xml.as_bytes()).unwrap();
        let document = decoded.parse().unwrap();
        assert_eq!(document.rdf_prefix.as_deref(), Some("rdf"));
        let property = document
            .properties
            .iter()
            .find(|property| property.namespace == DC && property.name == "format")
            .unwrap();
        assert_eq!(property.prefix.as_deref(), Some("dc"));
        assert_eq!(property.form, XmpPropertyForm::Element);
        assert_eq!(
            &decoded.decoded[property.span.start..property.span.end],
            "<dc:format>text/plain</dc:format>"
        );
        assert!(
            document
                .namespaces
                .iter()
                .any(|binding| binding.prefix.as_deref() == Some("dc") && binding.namespace == DC)
        );
    }

    #[test]
    fn attribute_property_layout_records_lexical_prefix_and_form() {
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:xmp=\"{XMP}\">\
             <rdf:Description xmp:Rating=\"3\"/></rdf:RDF>"
        );
        let decoded = XmpPacket::scan_with_source(xml.as_bytes()).unwrap();
        let document = decoded.parse().unwrap();
        let property = &document.properties[0];
        assert_eq!(property.prefix.as_deref(), Some("xmp"));
        assert_eq!(property.form, XmpPropertyForm::Attribute);
        assert!(decoded.decoded[property.span.start..property.span.end].contains("xmp:Rating"));
    }

    #[test]
    fn rejects_rdf_numbered_array_items() {
        let err = XmpMeta::from_packet(
            rdf("<dc:x><rdf:Bag><rdf:_1>a</rdf:_1></rdf:Bag></dc:x>").as_bytes(),
        )
        .unwrap_err();
        // The rdf:_n-specific diagnostic, not the generic "unexpected element" one.
        assert!(
            matches!(&err, XmpError::Prohibited(m) if m.contains("array item")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_language() {
        let err = XmpMeta::from_packet(
            rdf("<dc:title><rdf:Alt><rdf:li xml:lang=\"en\">a</rdf:li>\
                 <rdf:li xml:lang=\"EN\">b</rdf:li></rdf:Alt></dc:title>")
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, XmpError::DuplicateLang(_)), "got {err:?}");
    }

    #[test]
    fn missing_rdf_is_an_error() {
        assert!(matches!(
            XmpMeta::from_packet(b"<html></html>"),
            Err(XmpError::MissingRdf)
        ));
    }

    #[test]
    fn malformed_xml_is_an_error() {
        // Properly namespaced, but a mismatched end tag — a genuine lexing failure.
        let bad = format!("<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\"><rdf:Description></rdf:RDF>");
        assert!(matches!(
            XmpMeta::from_packet(bad.as_bytes()),
            Err(XmpError::Xml(_))
        ));
    }

    #[test]
    fn undeclared_prefix_is_an_error() {
        // `rdf:` is used without an xmlns:rdf declaration.
        assert!(matches!(
            XmpMeta::from_packet(b"<rdf:RDF><rdf:Description/></rdf:RDF>"),
            Err(XmpError::UnknownPrefix(_))
        ));
    }

    #[test]
    fn cdata_content_is_read_literally() {
        let meta = parse(&rdf("<dc:format><![CDATA[a < b & c]]></dc:format>"));
        assert_eq!(meta.get_text(DC, "format"), Some("a < b & c"));
    }

    #[test]
    fn rdf_value_attribute_is_a_simple_value() {
        // emptyPropertyElt with rdf:value (Annex C.2.12 rule 1).
        let meta = parse(&rdf("<dc:format rdf:value=\"text/plain\"/>"));
        assert_eq!(meta.get_text(DC, "format"), Some("text/plain"));
    }

    #[test]
    fn empty_element_with_data_attributes_is_a_structure() {
        // emptyPropertyElt with field attributes (Annex C.2.12 rule 4).
        let meta = parse(&rdf("<xmp:Thumb foo:w=\"9\" foo:h=\"6\"/>"));
        let XmpValue::Structured(fields) = &meta.get(XMP, "Thumb").unwrap().value else {
            panic!("expected struct");
        };
        assert_eq!(fields.len(), 2);
        assert!(
            fields
                .iter()
                .any(|f| f.name == "w" && f.text() == Some("9"))
        );
    }

    #[test]
    fn typed_node_becomes_struct_with_rdf_type_qualifier() {
        // An arbitrarily-named node where rdf:Description is expected (Part 1 §7.9.2.5).
        let meta = parse(&rdf(
            "<xmp:Thumb><foo:Image><foo:w>9</foo:w></foo:Image></xmp:Thumb>",
        ));
        let prop = meta.get(XMP, "Thumb").unwrap();
        let XmpValue::Structured(fields) = &prop.value else {
            panic!("expected struct");
        };
        assert_eq!(fields[0].name, "w");
        // The type's URI is the typed node's expanded name.
        assert_eq!(prop.qualifiers.len(), 1);
        assert_eq!(prop.qualifiers[0].namespace, RDF_NAMESPACE);
        assert_eq!(prop.qualifiers[0].name, "type");
        assert_eq!(
            prop.qualifiers[0].value,
            XmpValue::Uri(format!("{FOO}Image"))
        );
    }

    #[test]
    fn property_without_a_namespace_is_rejected() {
        // An unprefixed property element (no default namespace) has no namespace URI.
        let err = XmpMeta::from_packet(
            format!(
                "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\"><rdf:Description rdf:about=\"\">\
                 <plain>x</plain></rdf:Description></rdf:RDF>"
            )
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, XmpError::Prohibited(_)), "got {err:?}");
    }

    #[test]
    fn multiple_child_elements_are_rejected() {
        let err =
            XmpMeta::from_packet(rdf("<dc:x><foo:a/><foo:b/></dc:x>").as_bytes()).unwrap_err();
        assert!(matches!(err, XmpError::Prohibited(_)), "got {err:?}");
    }

    #[test]
    fn top_level_typed_node_is_rejected() {
        // rdf:RDF must contain rdf:Description, not a bare typed node (Part 1 §7.9.2.5).
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:foo=\"{FOO}\"><foo:Thing/></rdf:RDF>"
        );
        let err = XmpMeta::from_packet(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, XmpError::Prohibited(_)), "got {err:?}");
    }

    #[test]
    fn rdf_value_carrying_a_qualifier_is_rejected() {
        // rdf:value must not carry xml:lang or nested qualifiers (Part 1 §7.8).
        let err = XmpMeta::from_packet(
            rdf(
                "<dc:x><rdf:Description><rdf:value xml:lang=\"en\">v</rdf:value>\
                 </rdf:Description></dc:x>",
            )
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, XmpError::Prohibited(_)), "got {err:?}");
    }

    #[test]
    fn non_li_element_in_an_array_is_rejected() {
        let err =
            XmpMeta::from_packet(rdf("<dc:x><rdf:Bag><foo:item/></rdf:Bag></dc:x>").as_bytes())
                .unwrap_err();
        assert!(matches!(err, XmpError::Prohibited(_)), "got {err:?}");
    }

    #[test]
    fn rdf_namespaced_non_li_uses_the_generic_message() {
        // An rdf:-namespaced element that is neither rdf:li nor rdf:_n takes the generic branch,
        // not the rdf:_n one — so the condition truly needs both "rdf namespace" AND "starts with
        // '_'", not either alone.
        let err =
            XmpMeta::from_packet(rdf("<dc:x><rdf:Bag><rdf:foo/></rdf:Bag></dc:x>").as_bytes())
                .unwrap_err();
        let XmpError::Prohibited(msg) = &err else {
            panic!("expected Prohibited, got {err:?}");
        };
        assert!(
            msg.contains("in an rdf array"),
            "expected the generic message: {msg}"
        );
        assert!(
            !msg.contains("array item"),
            "rdf:foo is not an rdf:_n item: {msg}"
        );
    }

    #[test]
    fn multiple_root_elements_are_rejected() {
        // Two top-level rdf:RDF elements — only one root document is allowed.
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\"/><rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\"/>"
        );
        assert!(
            matches!(XmpMeta::from_packet(xml.as_bytes()), Err(XmpError::Xml(_))),
            "a second root element must be rejected, not silently replace the first"
        );
    }

    #[test]
    fn packet_parse_composes_with_scan() {
        // from_packet ≡ scan ∘ parse; the two-step form additionally exposes the envelope.
        let mut meta = XmpMeta::new();
        meta.set_text(DC, "format", "text/plain");
        let bytes = meta.to_packet();

        let packet = XmpPacket::scan(&bytes).expect("scan");
        assert!(packet.writable, "default writer output is writable");
        assert_eq!(
            packet.parse().expect("parse"),
            XmpMeta::from_packet(&bytes).expect("from_packet")
        );
    }

    #[test]
    fn packet_parse_reports_body_errors() {
        let packet = XmpPacket {
            body: "<html></html>".into(),
            writable: false,
            padding: 0,
        };
        assert!(matches!(packet.parse(), Err(XmpError::MissingRdf)));
    }

    #[test]
    fn xmlns_declarations_are_not_treated_as_properties() {
        // An xmlns declaration sitting on the Description must be skipped, not folded into a
        // spurious property.
        let xml = format!(
            "<rdf:RDF xmlns:rdf=\"{RDF_NAMESPACE}\" xmlns:dc=\"{DC}\">\
             <rdf:Description rdf:about=\"\" xmlns:unused=\"http://example.com/unused/\">\
             <dc:format>text/plain</dc:format></rdf:Description></rdf:RDF>"
        );
        let meta = parse(&xml);
        assert_eq!(
            meta.properties.len(),
            1,
            "only dc:format, no xmlns property"
        );
        assert_eq!(meta.get_text(DC, "format"), Some("text/plain"));
    }
}
