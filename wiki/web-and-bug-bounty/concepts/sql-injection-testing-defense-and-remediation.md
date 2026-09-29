---
title: "SQL Injection Testing & Database Exploitation Frameworks: Defense, Hardening & Remediation"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[sql-injection-testing]]"
cluster: web-and-bug-bounty
tags:
  - sqli
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/sql-injection.md
confidence: high
contested: false
contradictions: []
---
# SQL Injection Testing & Database Exploitation Frameworks: Defense, Hardening & Remediation


<!-- TOC_START -->
## Table of Contents
- [Remediation Recommendations](#remediation-recommendations)
  - [Detection & Monitoring](#detection-monitoring)
    - [SIEM/Log Analysis Queries](#siemlog-analysis-queries)
  - [HTTP/2 & HTTP/3 Considerations](#http2-http3-considerations)
  - [Compliance & Regulatory Context](#compliance-regulatory-context)
  - [Threat Intelligence Integration](#threat-intelligence-integration)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Remediation Recommendations

- **Prepared Statements/Parameterized Queries**:

  ```java
  // Unsafe
  String query = "SELECT * FROM users WHERE username = '" + username + "'";

  // Safe (Java PreparedStatement)
  PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
  stmt.setString(1, username);
  ```

- **PHP PDO note:** When using PDO you must disable emulated prepares,Otherwise parameters are substituted client‑side and JSON operators can still be injectable.

  ```php
  $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
  ```

- **ORM Frameworks**: Use secure ORM frameworks with proper parameter binding
- **Input Validation**: Server-side validation with strong type checking
- **Stored Procedures**: Use properly coded stored procedures
- **Least Privilege**: Restrict database account permissions
- **WAF Implementation**: Deploy a web application firewall
- **Error Handling**: Prevent detailed error messages from being displayed to users
- **Database Activity Monitoring (DAM)**: Track and alert on suspicious database activity
  - Tools: Imperva DAM, IBM Guardium, Oracle Audit Vault
  - Cloud-native: AWS RDS Enhanced Monitoring, Azure SQL Auditing, GCP Cloud SQL Insights
- **Runtime Application Self-Protection (RASP)**: Detect and block SQLi at runtime
  - Tools: Contrast Security, Sqreen (Datadog), Hdiv Security
- **ML-based WAF**: Modern WAF with machine learning detection
  - Cloudflare WAF (ML rules)
  - AWS WAF Fraud Control Account Takeover Prevention
  - Signal Sciences (Fastly)
- **Row-Level Security (RLS)**: Enforce per-tenant/user data access in the database layer
- **Outbound controls**: Block DB servers from making outbound DNS/HTTP to limit OOB exfiltration
  - Implement egress filtering in security groups/firewalls
  - Use private subnets for database instances
- **Strong typed parameters**: For JSON/ARRAY params ensure explicit casts (e.g., `$1::jsonb`) to avoid operator confusion
- **API Gateway Schema Validation**: Enforce strict input validation at gateway level
  - AWS API Gateway Request Validators
  - Kong Request Validator plugin
  - Apigee JSON Threat Protection
- **Query Monitoring & Anomaly Detection**:
  ```python
  # Example: Monitor for suspicious patterns
  if re.search(r"(UNION|SELECT|INSERT|UPDATE|DELETE).*--", query, re.IGNORECASE):
      alert_security_team()
      block_request()
  ```
- **Container Security Context**: For containerized databases
  ```yaml
  # Kubernetes: Restrict service account access
  automountServiceAccountToken: false
  securityContext:
    readOnlyRootFilesystem: true
    runAsNonRoot: true
  ```

### Detection & Monitoring

#### SIEM/Log Analysis Queries

**Splunk:**

```spl
index=web sourcetype=access_combined
| regex _raw="(%27)|(\\')|(\\-\\-)|((%3D)|(=))[^\\n]*((%27)|(\\')|(\\-\\-)|(\\%3D))"
| eval suspected_sqli=if(match(_raw, "(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)"), "high", "low")
| where suspected_sqli="high"
| table _time, src_ip, uri, user_agent, status
```

**ELK/OpenSearch:**

```json
{
  "query": {
    "bool": {
      "should": [
        {
          "regexp": { "request.uri": ".*(union|select|insert|update|delete).*" }
        },
        { "match": { "request.body": "' OR 1=1" } }
      ]
    }
  }
}
```

**CloudWatch Insights (AWS RDS):**

```
fields @timestamp, @message
| filter @message like /(?i)(UNION|SELECT.*FROM|INSERT INTO|UPDATE.*SET|DELETE FROM)/
| filter @message like /(%27|'|--|\\/\\*)/
| stats count() by bin(5m)
```

### HTTP/2 & HTTP/3 Considerations

- **HPACK/QPACK Header Compression**: May alter detection patterns

  ```
  # HTTP/2 header compression can obfuscate payloads
  :path: /api/user?id=1%20UNION%20SELECT
  # Appears different after decompression
  ```

- **Request Smuggling to SQLi**:

  ```http
  POST /api/user HTTP/2
  Content-Length: 100
  Transfer-Encoding: chunked

  0

  POST /api/admin HTTP/1.1
  Content-Length: 50

  id=1' OR '1'='1
  ```

- **HTTP/3 QUIC Protocol**: Test SQLi over different protocols
  ```bash
  # Use curl with HTTP/3 support
  curl --http3 "https://target.com/api?id=1' UNION SELECT--"
  ```

### Compliance & Regulatory Context

- **PCI DSS 4.0**: Requirement 6.2.4 mandates protection against injection attacks
- **OWASP ASVS 4.0**: V5.3.4 requires parameterized queries or stored procedures
- **ISO 27001:2022**: A.8.22 web filtering control
- **NIST 800-53**: SI-10 Information Input Validation
- **SOC 2 Type II**: Common Criteria CC6.1 (Logical Access Controls)

### Threat Intelligence Integration

- **CISA KEV Catalog**: Monitor for actively exploited SQL injection CVEs
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **exploit-db.com**: Track recent SQLi PoC releases
- **GitHub Security Advisories**: Monitor ORM/framework CVEs
  ```bash
  # Automated monitoring
  gh api /advisories --jq '.[] | select(.summary | contains("SQL injection"))'
  ```


## Related Pages
- [[sql-injection-testing]]
- [[web-and-bug-bounty]]