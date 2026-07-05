
- Also read the [angular sercurity reference](https://angular.dev/best-practices/security) itself 

## Phase 1: Source Mapping & Taint Tracking (Entry Points)
**Goal:** Identify all avenues where untrusted data enters the client-side context.

### URL & Router State Auditing (`ActivatedRoute`)
- [ ] **Methodology:** Trace data flows from `queryParams`, `params`, and `fragment` subscriptions.
- [ ] **Test:** Inject boundary characters and payload strings into the URL; observe if state dictates rendering logic, error pages, or dynamic imports.

### Cross-Origin Messaging (`postMessage`)
- [ ] **Methodology:** Grep bundles for `HostListener('window:message')` or `addEventListener('message')`.
- [ ] **Test 1:** Verify origin validation. If regex is used, attempt bypasses (e.g., `attacker-trusted.com` bypassing `/trusted\.com/`).
- [ ] **Test 2:** Send malformed objects to the handler to test type confusion or state hijacking.

### PWA Storage Subsystem Auditing
- [ ] **Methodology:** Identify all interactions with `localStorage`, `sessionStorage`, and `IndexedDB`.
- [ ] **Test 1:** Check for Shared Origin constraints (are other subdomains vulnerable to XSS, allowing storage poisoning?).
- [ ] **Test 2:** Manually mutate stored JSON states; reload the app to observe if hydrated data bypasses sanitizers.

### Service Worker DOM Communication
- [ ] **Methodology:** Audit `MessageChannel` listeners inside the Angular application.
- [ ] **Test:** Determine if the DOM blindly trusts payloads arriving from the SW without type/content validation.

---

## Phase 2: Sink Auditing & Framework Bypasses
**Goal:** Locate intentional circumventions of Angular's DOMSanitizer.

### Angular Security Bypasses (`DomSanitizer`)
- [ ] **Methodology:** Grep minified bundles for:
  - `bypassSecurityTrustHtml`
  - `bypassSecurityTrustUrl`
  - `bypassSecurityTrustResourceUrl`
  - `bypassSecurityTrustScript`
- [ ] **Test 1:** Backtrack these sinks to their sources.
- [ ] **Test 2:** Audit custom Pipes (e.g., `SafeHtmlPipe`) for dynamic trust decisions.

### Direct DOM Manipulation
- [ ] **Methodology:** Search for `ElementRef.nativeElement` and `Renderer2`.
- [ ] **Test 1:** Verify if `innerHTML` / `outerHTML` receives untrusted data.
- [ ] **Test 2:** Audit `Renderer2.setProperty(el, 'innerHTML', data)` usage.

### Dynamic Component Instantiation
- [ ] **Methodology:** Audit `ViewContainerRef.createComponent`.
- [ ] **Test:** Check if attacker controls component config, props, or templates.

### Server-Side Rendering (Angular Universal)
- [ ] **Methodology:** Analyze `TransferState` from server to client.
- [ ] **Test:** Inject payloads into SSR data and verify script context escaping.

---

## Phase 3: PWA & Service Worker Exploitation

> [!danger] **Goal:** Escalate transient execution into persistent compromise, exploit native-like PWA permissions, and abuse offline capabilities.

- [ ] **Service Worker Hijacking (The Persistence Layer)**
    
    - [ ] _Methodology:_ Assume a single transient XSS exists. Evaluate what an attacker can achieve via the `navigator.serviceWorker` API.
        - [ ] _Test 1:_ Attempt to register a rogue service worker scoped to `/` or the application's root using a compromised endpoint.
        - [ ] _Test 2:_ Audit the SW `fetch` event listener. Can you bypass cache restrictions or intercept JWTs appended to headers?
- [ ] **Cache API Poisoning**
    
    - [ ] _Methodology:_ Review offline-first caching mechanisms (`caches.open`).
        - [ ] _Test 1:_ Use console access to overwrite a cached API JSON response with malicious HTML/JS payloads.
        - [ ] _Test 2:_ Disconnect the network, reload the PWA, and verify if the application parses the poisoned cache as executable code.
- [ ] **Web Manifest & Installation Spoofing**
    
    - [ ] _Methodology:_ Inspect the `manifest.json` file.
        - [ ] _Test 1:_ Review the `start_url`. Does it append generic query parameters (e.g., `?pwa=true`) that could be swapped for payload injection parameters during installation?
        - [ ] _Test 2:_ Audit icons and theme colors for UI redressing. Verify if the application allows dynamic manifest generation that could be poisoned to spoof a different brand (PWA Phishing).
- [ ] **Cross-PWA Permission Leakage**
    
    - [ ] _Methodology:_ Evaluate if multiple PWAs are hosted under the same origin but different paths (e.g., `example.com/app1`, `example.com/app2`).
        - [ ] _Test:_ Identify if a malicious or compromised PWA on the same origin can silently inherit sensitive permissions (like Geolocation, Camera, or WebNFC) previously granted to a benign PWA without triggering a new user consent prompt.
- [ ] **Push Notification & Background Sync Abuse**
    
    - [ ] _Methodology:_ Audit the implementation of the Web Push API and Background Sync API within the Service Worker.
        - [ ] _Test 1 (Phishing/Spoofing):_ Trigger push notifications via the SW. Determine if the browser/OS obscures the originating domain, allowing a compromised SW to execute credential harvesting by spoofing system-level or high-trust brand notifications.
        - [ ] _Test 2 (Botnet/C2 Persistence):_ Register a `sync` event. Verify if the Service Worker can be kept alive in the background (even after the user closes the PWA) to act as a covert C2 beacon, silently exfiltrate local data, or perform computational abuse.
- [ ] **IndexedDB-to-SW Injection**
    
    - [ ] _Methodology:_ Trace how the Service Worker reads state from IndexedDB to dictate its logic (e.g., dynamic routing rules, push handlers, caching policies).
        - [ ] _Test:_ Inject a payload into IndexedDB via a lower-privileged DOM XSS. Reload the app to determine if the Service Worker dynamically evaluates or blindly trusts the poisoned IndexedDB data, leading to a complete Service Worker context compromise.
- [ ] **Offline Side-Channel Profiling**
    
    - [ ] _Methodology:_ Exploit the offline fallback mechanisms and Cache Storage timings to track users.
        - [ ] _Test:_ Load an attacker-controlled iframe within the PWA, simulate network disconnection, and attempt to load known sub-resources from other target domains. Time the responses to accurately fingerprint the user's cross-origin browsing history based on what is successfully returned from the local Cache API.
## Phase 4: Static Bundle Analysis (Blackbox Pentesting)
**Goal:** Deconstruct minified code to uncover hidden attack surface.

### Automated Bundle Parsing
- [ ] **Methodology:** Extract `.js` bundles from Network tab.
- [ ] **Test:** Run:
  - `jsluice`
  - `retire.js`

### AST-Based Grepping (Manual Triage)
- [ ] **Methodology:** Unminify via DevTools / Prettier.
- [ ] **Check 1:**  
  ```js
  \.setProperty\([a-zA-Z],["']innerHTML["']
  ```