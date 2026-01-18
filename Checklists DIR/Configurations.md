
- This checklist is based on the **Server Security Misconfiguration** category from[ Bugcrowd's Vulnerability Rating Taxonomy (as of December 2025)](https://bugcrowd.com/vulnerability-rating-taxonomy). 

#  Server Security Misconfiguration

## Exposed Services and Portals
- [ ] **Exposed Admin Portal**  
  Priority: P1  
  Test: Directory enumeration (e.g., ffuf, gobuster), common paths (/admin, /phpmyadmin, /server-status).  
  Note: High impact if accessible without auth.

- [ ] **Exposed Non-Admin Portal** (e.g., debug, monitoring)  
  Priority: P3  

- [ ] **Exposed Protected Portal** (behind weak auth)  
  Priority: P5  

- [ ] **Using Default Credentials** on any exposed service  
  Priority: P1  
  Test: Attempt known defaults (admin/admin, root/toor, etc.) on discovered panels/databases/devices.

- [ ] **Directory Listing Enabled**  
  Priority: P5 (Non-sensitive) / Varies (Sensitive exposure)  
  Test: Access directories and check for auto-indexing.

- [ ] **Fingerprinting/Banner Disclosure** (Server headers, error messages revealing versions)  
  Priority: P5  
  Test: curl -I, analyze error pages.

## HTTP Security Headers and Cookies
- [ ] **Lack of Security Headers**  
  - [ ] Cache-Control (Sensitive page: P4 / Non-sensitive: P5)
  - [ ] Content-Security-Policy (P5)
  - [ ] Strict-Transport-Security (HSTS) (P5)
  - [ ] X-Frame-Options (P5)
  - [ ] X-Content-Type-Options, X-XSS-Protection, etc. (P5)  
  Test: curl headers or browser dev tools; use tools like securityheaders.com.

- [ ] **Missing Secure or HTTPOnly Cookie Flag**  
  Priority: P4 (Session token) / P5 (Non-session)  
  Test: Inspect Set-Cookie headers.

- [ ] **Cookie Scoped to Parent Domain**  
  Priority: P5  

- [ ] **Clickjacking** (missing X-Frame-Options or weak CSP)  
  Priority: P4 (Sensitive actions) / P5 (Others)  
  Test: Create PoC iframe page.

- [ ] **Missing Subresource Integrity (SRI)** on external resources  
  Priority: P5  

## Rate Limiting and Abuse Protections
- [ ] **No Rate Limiting on Form**  
  Priority: P4–P5  
  Subtypes:
  - Registration, Email/SMS-triggering, Password reset (P4)
  - Change password (P5)  
  Test: Automated requests with Burp Intruder; monitor for blocks.

- [ ] **CAPTCHA Issues**  
  Priority: P4 (Implementation flaw) / P5 (Missing or brute-forceable)  
  Test: Automation attempts, logic bypasses.

- [ ] **Username/Email Enumeration**  
  Priority: P5  
  Test: Response/timing differences on invalid vs valid users.

## TLS/SSL Configuration
- [ ] **Insecure SSL**  
  Priority: P5  
  Subtypes:
  - Certificate errors
  - Insecure cipher suites
  - Lack of forward secrecy  
  Test: testssl.sh, SSL Labs scan.

- [ ] **SSL Attacks** (e.g., BREACH, POODLE)  
  Priority: Varies  

## DNS and Email Server Configuration
- [ ] **Misconfigured DNS**  
  Priority: P3–P5  
  - Subdomain Takeover (P3) → Test: Subdomain enum + dangling record PoC (subjack, dnsrecon)
  - Zone Transfer (P4) → dig AXFR
  - Missing CAA Record (P5)
  - Missing DNSSEC (P5)

- [ ] **Mail Server Misconfiguration** (SPF/DKIM/DMARC)  
  Priority: P3–P5  
  - No spoofing protection (P3)
  - Spoofing to inbox due to DMARC issues (P4)
  - Missing/misconfigured SPF/DKIM (P5)
  - Spoofing to spam or non-email domain (P5)  
  Test: Send spoofed emails, check mxtoolbox or manual delivery.

## Request and Protocol Handling
- [ ] **Server-Side Request Forgery (SSRF)**  
  Priority: P2 (Internal high impact) → P5 (External low/DNS only)  
  Test: Attempt internal/external resource access via user-supplied URLs.

- [ ] **Potentially Unsafe HTTP Method Enabled** (e.g., TRACE, non-standard)  
  Priority: P5  
  Test: netcat or curl with METHOD.

- [ ] **HTTP Request Smuggling**  
  Priority: Varies  
  Test: CL.TE / TE.CL variations.

- [ ] **Unsafe Cross-Origin Resource Sharing (CORS)**  
  Priority: Varies  

- [ ] **Web Application Firewall (WAF) Bypass** leading to direct server access  
  Priority: P4  

## File and Resource Handling
- [ ] **Unsafe File Upload**  
  Priority: P5  
  - Extension filter bypass
  - No antivirus scanning
  - No size limits  
  Test: Upload variants (double ext, null byte, etc.).

- [ ] **Path Traversal**  
  Priority: Varies  
  Test: ../../etc/passwd patterns.

- [ ] **Reflected File Download (RFD)**  
  Priority: P5  

## Authentication and OAuth
- [ ] **OAuth Misconfiguration**  
  Priority: P2–P4 / Varies  
  - Account takeover (P2)
  - Account squatting (P4)
  - Insecure redirect URI
  - Missing/broken state parameter  
  Test: Intercept OAuth flows in Burp.

- [ ] **Lack of Password Confirmation**  
  Priority: P4–P5  
  - Delete account (P4)
  - Change email/password/2FA (P5)

- [ ] **Email Verification Bypass**  
  Priority: P5  

## Database and Other
- [ ] **Database Management System (DBMS) Misconfiguration** (excessively privileged user)  
  Priority: P4  

- [ ] **Cache Poisoning / Deception**  
  Priority: Varies  

- [ ] **Race Condition**  
  Priority: Varies  

- [ ] **Bitsquatting / Same-Site Scripting**  
  Priority: P5  

- [ ] **Software Package Takeover**  
  Priority: Varies  

# Cloud Security Misconfiguration

## Identity and Access Management (IAM) Misconfigurations
- [ ] **Publicly Accessible IAM Credentials** (e.g., hardcoded keys in public repos, exposed in metadata)  
  Priority: P1–P2  
  Test: Search code/repos for keys (truffleHog, gitrob); check IMDSv1 exposure.  
  Note: Can lead to full account compromise.

- [ ] **Overly Permissive IAM Roles/Policies** (e.g., wildcard actions/resources, excessive privileges)  
  Priority: P2–P4  
  Test: Enumerate roles/policies (Pacu, CloudSploit, Prowler); check for AssumeRole trust issues.  
  Note: Enables privilege escalation or lateral movement.

## Storage Misconfigurations
- [ ] **Unencrypted Sensitive Data at Rest** (e.g., S3 buckets, EBS volumes without encryption)  
  Priority: P3–P4  
  Test: Check bucket/server-side encryption settings; scan for sensitive data in unencrypted storage.  
  Note: Higher impact if data is PII or secrets.

- [ ] **Publicly Accessible Cloud Storage** (e.g., public S3 buckets, Azure blobs, GCS buckets)  
  Priority: P1 (Sensitive data) / P3–P5 (Non-sensitive)  
  Test: Bucket enumeration (bucket-finder, S3Scanner); attempt anonymous access/listing/download.  
  Note: Often leads to data leakage.

## Network Configuration Issues
- [ ] **Lack of Network Segmentation** (e.g., no VPC isolation, overly broad security groups)  
  Priority: P3–P4  
  Test: Review security groups/NACLs; attempt cross-subnet access.  
  Note: Allows lateral movement if one resource is compromised.

- [ ] **Open Management Ports to the Internet** (e.g., RDP/SSH on 0.0.0.0/0, Kubernetes API exposed)  
  Priority: P2–P4  
  Test: Port scanning from external IP; check ingress rules.  
  Note: High risk for brute-force or exploitation.

## Misconfigured Services and APIs
- [ ] **Insecure API Endpoints** (e.g., unauthenticated Cloud Functions, exposed metadata endpoints)  
  Priority: P2–P4  
  Test: Enumerate APIs (enumerate-iam, ScoutSuite); test for auth bypass or open access.  
  Note: Can expose functions or metadata (e.g., IMDSv2 not enforced).

- [ ] **Exposed Debug or Admin Interfaces** (e.g., cloud console proxies, debug modes in serverless)  
  Priority: P3–P5  
  Test: Fingerprint cloud-specific paths; check for open dashboards.  

## Logging and Monitoring Issues
- [ ] **Disabled or Insufficient Logging** (e.g., no CloudTrail, GuardDuty disabled, incomplete audit logs)  
  Priority: P4–P5  
  Test: Review logging configs; attempt actions and check if logged.  
  Note: Hinders detection; lower direct impact but raises overall risk.

## Other Cloud-Specific Checks
- [ ] **Misconfigured Serverless Functions** (e.g., overly permissive triggers, public invocation)  
  Priority: Varies  
  Test: Enumerate functions/lambdas; test invocation without auth.

- [ ] **Insecure Container Registries** (e.g., public ECR/GAR repositories)  
  Priority: P3–P5  
  Test: Attempt anonymous pull of images.

- [ ] **Metadata Service Exposure/Abuse** (e.g., SSRF to IMDS for credentials)  
  Priority: P1–P2  
  Test: SSRF testing against http://169.254.169.254.

#  Mobile Security Misconfiguration


## General Mobile App Misconfigurations
- [ ] **Auto Backup Allowed by Default**  
  Priority: P5  
  Test: Check AndroidManifest.xml for `android:allowBackup="true"` (default in older apps); attempt ADB backup extraction.  
  Note: Can lead to sensitive data extraction via USB/ADB.

- [ ] **Clipboard Enabled/Sensitive Data in Clipboard**  
  Priority: P5  
  Test: Monitor clipboard access; check if app copies sensitive data (e.g., passwords) to clipboard without restrictions.  
  Note: Low impact as often OS-level; higher if app exposes sensitive info.

- [ ] **Absent or Defeatable SSL/TLS Certificate Pinning**  
  Priority: P4 (Defeatable) / P5 (Absent)  
  Test: Use Frida/Objection to bypass pinning; intercept traffic with Burp/MITMProxy.  
  Note: Allows MITM attacks if pinning is weak or missing.

- [ ] **Tapjacking / UI Redressing**  
  Priority: P5  
  Test: Overlay transparent activities; check for `filterTouchesWhenObscured` flag (Android) or iOS equivalents.  
  Note: Enables clickjacking on mobile UI elements.

- [ ] **Insecure Deep Links / Intent Handling**  
  Priority: Varies (P4–P5)  
  Test: Fuzz exported activities/components; send malicious intents via ADB/am start.  
  Note: Can lead to data leakage or unauthorized actions.

- [ ] **Improper Export of Components**  
  Priority: P4–P5  
  Test: Drozer or static analysis for exported activities/services/receivers without permission checks.

- [ ] **Insecure WebView Configurations**  
  Priority: P4–P5  
  Test: Check for JavaScript enabled without need, file access, unsafe loaders; attempt JS injection.

## General Tips
- Tools: MobSF (static), Frida/Objection (dynamic), ADB, Drozer (Android), idb (iOS), Burp Suite.
- Many mobile misconfigs are P5 due to requiring physical access or user interaction, but prove higher impact where possible (e.g., data exfil).
- Test both Android and iOS variants if applicable.
- Document OS version and app context for accurate severity.

This checklist covers the core items in Bugcrowd's Mobile Security Misconfiguration category.

# Network Security Misconfiguration
## Network Service Exposures
- [ ] **Telnet Enabled/Exposed**  
  Priority: P3–P4  
  Test: Nmap scan for port 23; attempt connection; check for weak/no auth.  
  Note: Insecure clear-text protocol; high risk if exposed externally.

- [ ] **Other Insecure Protocols Enabled** (e.g., FTP, SMBv1, outdated SNMP)  
  Priority: Varies (P4–P5)  
  Test: Service enumeration; version checking.

## General Tips
- This category is narrow; often overlaps with Server Security Misconfiguration.
- Tools: Nmap, Nessus, Masscan.
- Prioritize external exposure and sensitive services.

# Decentralized Application (DeApp) Misconfiguration

This checklist is based on the **Decentralized Application Misconfiguration** category from Bugcrowd's VRT. Focused on blockchain/DeFi/Web3 apps.

## Insecure Data Storage
- [ ] **Plaintext Private Key Exposure**  
  Priority: P1  
  Test: Review client-side code, localStorage, logs for keys.

- [ ] **Sensitive Information Exposure**  
  Priority: P3–P5  

## Marketplace & Protocol Issues
- [ ] **Orderbook Manipulation / Malicious Order**  
  Priority: Varies  
  Test: Front-run or manipulate transactions.

- [ ] **Signer Account Takeover / Unauthorized Asset Transfer**  
  Priority: P1–P2  

- [ ] **Price/Fee Manipulation / Oracle Manipulation**  
  Priority: P1–P3  

- [ ] **Denial of Service (Node/Protocol Level)**  
  Priority: Varies  

- [ ] **Improper Authorization / Signature Validation**  
  Priority: P2–P4  

- [ ] **Flash Loan Attacks / Governance Issues**  
  Priority: P1–P3  

## General Tips
- Tools: Mythril, Slither, Foundry, Etherscan review, transaction simulation.
- High impact in DeFi; prove fund loss for higher priority.

# Insecure OS/Firmware Misconfiguration

## Credential & Access Issues
- [ ] **Hardcoded Passwords** (Privileged/Non-Privileged)  
  Priority: P1–P3  
  Test: Firmware extraction, strings/binwalk.

- [ ] **Over-Permissioned/Shared Credentials in Storage**  
  Priority: P3–P4  

## Encryption & Update Issues
- [ ] **Data Not Encrypted at Rest** (Sensitive/Non-sensitive)  
  Priority: P3–P5  

- [ ] **Poorly Configured Disk/Full-Disk Encryption**  
  Priority: P4  

- [ ] **Weak/No Firmware Update Validation** (No integrity check, no encryption)  
  Priority: P2–P4  

- [ ] **Sensitive Artifacts Left on Disk**  
  Priority: P4–P5  

## Other
- [ ] **Kiosk Escape/Breakout**  
  Priority: P3–P5  
  Test: Input fuzzing, privilege escalation.

- [ ] **Poorly Configured OS Security Settings**  
  Priority: Varies  