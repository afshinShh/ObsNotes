# intro to logs 

based on intro to logs room from [tryhackme](https://tryhackme.com/room/introtologs)

-  Logs are a record of events within a system

- usually includes the following information:
  - A <mark style="background: #FF5582A6;">timestamp</mark> of when an event was logged
  - The name of the <mark style="background: #FF5582A6;">system</mark> or application that generated the log entry
  - The <mark style="background: #FF5582A6;">type of event</mark> that occurred 
  - Additional details about the event, such as the <mark style="background: #FF5582A6;">user who initiated the event</mark> or the device's <mark style="background: #FF5582A6;">IP address</mark> that generated the event
  - ![[Pasted image 20230830223148.png]]
#### Contextual Correlation
Logs can answer critical questions about an event, such as:

*   **What** happened?
*   **When** did it happen?
*   **Where** did it happen?
*   **Who** is responsible?
*   **Were** their actions **successful**?
*   **What** was the result of their action?
---
## log types

common ones :
*   **Application Logs:** Messages about specific applications, including status, errors, warnings, etc.
*   **Audit Logs:** Activities related to operational procedures crucial for regulatory compliance.
*   **Security Logs:** Security events such as logins, permissions changes, firewall activity, etc.
*   **Server Logs:** Various logs a server generates, including system, event, error, and access logs.
*   **System Logs:** Kernel activities, system errors, boot sequences, and hardware status.
*   **Network Logs:** Network traffic, connections, and other network\-related events.
*   **Database Logs:** Activities within a database system, such as queries and updates.
*   **Web Server Logs:** Requests processed by a web server, including URLs, response codes, etc.
---
## Log Formats

#todo each topic should have their own page
### Semi-structured Logs 
#### Syslog Message Format
A widely adopted logging protocol for system and network logs [[examples and templates#Semi-structured Logs| example]]
#### Windows Event Log (EVTX)
Proprietary Microsoft log for Windows systems [[examples and templates#Windows Event Log (EVTX)|example]]
### Structured Logs
#### Field Delimited Formats
Comma-Separated Values (<mark style="background: #ADCCFFA6;">CSV</mark>) and Tab-Separated Values (<mark style="background: #ADCCFFA6;">TSV</mark>) are formats often used for tabular data. [[examples and templates#Field Delimited Formats|example]]
#### JavaScript Object Notation (JSON)
Known for its readability and compatibility with modern programming languages.[[examples and templates#JavaScript Object Notation (JSON)|example]]
#### W3C Extended Log Format (ELF)
Defined by the World Wide Web Consortium (<mark style="background: #ADCCFFA6;">W3C</mark>), customizable for web server logging. It is typically used by Microsoft Internet Information Services (IIS) Web Server [[examples and templates#W3C Extended Log Format (ELF)|example]]

#### eXtensible Markup Language (XML)
Flexible and customizable for creating standardized logging formats.[[examples and templates#eXtensible Markup Language (XML)|example]]
### Unstructured Logs
#### NCSA Common Log Format (CLF)
A standardized web server log format for client requests. It is typically used by the <mark style="background: #ADCCFFA6;">Apache</mark> HTTP Server by default [[examples and templates#NCSA Common Log Format (CLF)|example]]
#### NCSA Combined Log Format (Combined)
An extension of CLF, adding fields like referrer and user agent. It is typically used by <mark style="background: #ADCCFFA6;">Nginx</mark> HTTP Server by default.[[examples and templates#NCSA Combined Log Format (Combined)|example]]

---
## Log Standards

- [**Common Event Expression (CEE):**](https://cee.mitre.org/) ->  MITRE -> a common structure for log data
- **[OWASP Logging Cheat Sheet:](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)** -> guideline for developers 
- **[Syslog Protocol:](https://datatracker.ietf.org/doc/html/rfc5424)** -> standard for message logging
- **[NIST Special Publication 800-92:](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf)** -> computer security log management guideline.
- **[Azure Monitor Logs:](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-platform-logs)** -> Microsoft Azure guideline.
- **[Google Cloud Logging:](https://cloud.google.com/logging/docs)** -> Google Cloud Platform (GCP) guideline.
- **[Oracle Cloud Infrastructure Logging:](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm)** -> Oracle Cloud Infrastructure (OCI) guideline.
- **[Virginia Tech - Standard for Information Technology Logging:](https://it.vt.edu/content/dam/it_vt_edu/policies/Standard_for_Information_Technology_Logging.pdf)** -> log review and compliance guideline.

---
