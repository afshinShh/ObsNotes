1. **Null Origin Misconfiguration:** This occurs when a server accepts requests from the "null" origin. This can happen in scenarios where:
   - ==*Local Files and Development*==: When developers test web applications locally using `file:///` URLs (e.g., opening an HTML file directly in a browser without a server), the browser typically sets the origin to "null". In such cases, developers might temporarily allow the "null" origin in CORS policies to facilitate testing.
   - ==*Sandboxed Iframes*==: Web applications using sandboxed iframes (with the `sandbox` attribute) might encounter "null" origins if the iframe's content comes from a different domain. The "null" origin is a security measure in highly restricted environments.
   - ==*Specific Use Cases*==:
      -  non-web-browser environments 
      -  unconventional clients that don't send a standard origin.
   > senario:
     - An attacker could craft a phishing email with a link to a malicious HTML file. When the victim opens the file, it can send requests to the vulnerable server, which incorrectly accepts these as coming from a 'null' origin. 
	   - *XSS + CORS* ->  [[OLD/WEB/vulnerabilities/CORS/Examples#XSS + CORS|Example]]
1. **Bad Regex in Origin Checking:** Improperly configured regular expressions in origin checking can lead to accepting requests from unintended origins.
   > senario:
     - (e.g: a regex like `/example.com$/` would mistakenly allow `badexample.com`. An attacker could register a domain that matches the flawed regex and create a malicious site to send requests to the target server. Another example of lousy regex could be related to subdomains. For example, if domains starting with `example.com` is allowed, an attacker could use `example.com.attacker123.com`. The application should ensure that regex patterns used for validating origins are thoroughly tested and specific enough to exclude unintended matches.)
2. **Trusting Arbitrary Supplied Origin:** Some servers are configured to echo back the `Origin` header value in the `Access-Control-Allow-Origin` response header, effectively allowing any origin. 
   > senario
      - An attacker can craft a custom HTTP request with a controlled origin. Since the server echoes this origin, the attacker's site can bypass the SOP restrictions. Instead of echoing back origins, maintain an allowlist of allowed origins and validate against it.
   - ![[Pasted image 20251106203412.png]]
