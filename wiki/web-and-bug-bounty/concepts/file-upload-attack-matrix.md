---
title: "File Upload Attack Surface & Object Storage Exploitation Matrix"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - bug-bounty
  - payload
  - api
  - rce
sources:
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
confidence: high
contested: false
contradictions: []
---
# File Upload Attack Surface & Object Storage Exploitation Matrix



<!-- TOC_START -->
## Table of Contents
- [Overview](#overview)
- [Architecture & Storage Models](#architecture-storage-models)
- [Functional Audit Checklist](#functional-audit-checklist)
  - [1. Form Action & Parameters](#1-form-action-parameters)
  - [2. Validation & Verification Bypasses](#2-validation-verification-bypasses)
  - [3. S3 & Object Storage Content-Type Overrides](#3-s3-object-storage-content-type-overrides)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Overview
File upload features represent a dual attack surface: executing remote code on server-side infrastructure and triggering client-side exploitation (Stored XSS, CSRF) via object storage buckets and content delivery networks.

## Architecture & Storage Models

1. **Document Root Execution (Legacy/Classic)**: Files are uploaded directly into web server directories (`/var/www/html/uploads/`). Uploading executable scripts (`.php`, `.jsp`, `.aspx`) leads to direct Remote Code Execution (RCE).
2. **Route-Based / Object Storage (Modern)**: Files are processed by microservices and dispatched to cloud object storage (Amazon S3, Google Cloud Storage, Cloudflare R2) via presigned URLs or backend proxies.

## Functional Audit Checklist

### 1. Form Action & Parameters
- [ ] **Separated vs All-in-One Parameters**: Test whether metadata (filename, content type, target folder) is sent alongside binary chunks or via separate REST API endpoints.
- [ ] **Mass Assignment**: Check if upload metadata allows injecting unexpected properties (e.g. `isAdmin: true`, `isPublic: true`, `bucketName: internal-backup`).
- [ ] **URL Uploaders (Fetch from URL)**: Test for Server-Side Request Forgery (SSRF) and Cloud Metadata exfiltration (`http://169.254.169.254/latest/meta-data/`).

### 2. Validation & Verification Bypasses
- [ ] **Extension Filtering**:
  - Double extensions: `exploit.php.jpg`, `exploit.php;.png`.
  - Null-byte truncation: `exploit.php%00.png`.
  - Case permutations: `exploit.pHp`, `exploit.pHTML`.
- [ ] **Magic Byte Verification**: Ensure files retain valid magic numbers (e.g. `GIF89a;` or `\xFF\xD8\xFF` for JPEG) while embedding code payloads in metadata sections:
  ```bash
  # Inject PHP payload into JPEG EXIF comment
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
  ```
- [ ] **SVG File Exploitation (SSRF & Stored XSS)**:
  SVG files are XML-based vector graphics parsed by browsers and image processors:
  ```xml
  <?xml version="1.0" standalone="no"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
    <script type="text/javascript">
      alert(document.domain);
    </script>
  </svg>
  ```
  - Test SSRF via SVG `<iframe>` or `<image href="http://169.254.169.254/">`.

### 3. S3 & Object Storage Content-Type Overrides
When files are hosted on Amazon S3 or cloud buckets:

> [!important] Dynamic Content-Type Reflection
> In many S3 implementations, whatever `Content-Type` is supplied by the client during file upload is echoed back verbatim in the `Content-Type` header upon download.

- [ ] **HTML Injection via Content-Type**: If an image extension (`.jpg`) is requested with `Content-Type: text/html`, browsers will render HTML and execute embedded JavaScript.
- [ ] **Checker Function Bypass**: Test whether front-end proxies enforce strict content-type validation or if checker functions can be confused by duplicate headers.
- [ ] **Content Security Policy (CSP) Audit**: Evaluate storage bucket response headers using the Google CSP Evaluator (`https://csp-evaluator.withgoogle.com/`). If the bucket domain lacks a restrictive CSP or is served on the primary application root domain, Stored XSS is achieved.

## Related Pages
- [[web-and-bug-bounty]]
- [[xss-and-waf-evasion-tradecraft]]
- [[bug-bounty-live-hunts-case-studies]]
- [[server-side-request-forgery]]