** Table of Contents **

- [intro to logs](#intro%20to%20logs)
			- [Contextual Correlation](#Contextual%20Correlation)
	- [log types](#log%20types)
	- [Log Formats](#Log%20Formats)
		- [Semi-structured Logs](#Semi-structured%20Logs)
			- [Syslog Message Format](#Syslog%20Message%20Format)
			- [Windows Event Log (EVTX)](#Windows%20Event%20Log%20(EVTX))
		- [Structured Logs](#Structured%20Logs)
			- [Field Delimited Formats](#Field%20Delimited%20Formats)
			- [JavaScript Object Notation (JSON)](#JavaScript%20Object%20Notation%20(JSON))
			- [W3C Extended Log Format (ELF)](#W3C%20Extended%20Log%20Format%20(ELF))
			- [eXtensible Markup Language (XML)](#eXtensible%20Markup%20Language%20(XML))
		- [Unstructured Logs](#Unstructured%20Logs)
			- [NCSA Common Log Format (CLF)](#NCSA%20Common%20Log%20Format%20(CLF))
			- [NCSA Combined Log Format (Combined)](#NCSA%20Combined%20Log%20Format%20(Combined))
	- [Log Standards](#Log%20Standards)
	- [Log Collection](#Log%20Collection)
					- [steps:](#steps:)
	- [Log Management](#Log%20Management)
					- [steps:](#steps:)
	- [Log Centralisation](#Log%20Centralisation)
					- [steps:](#steps:)
	- [Log Storage](#Log%20Storage)
					- [depends on:](#depends%20on:)
	- [Log Retention](#Log%20Retention)
	- [Log Analysis Process](#Log%20Analysis%20Process)
	- [Log Analysis Tools](#Log%20Analysis%20Tools)
	- [Log Analysis Techniques](#Log%20Analysis%20Techniques)

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
## Log Collection

-> the aggregation of logs from diverse sources
- Utilising the **Network Time Protocol (NTP)** -> maintain the system's time accuracy during logging -> **pool.ntp.org** to find an NTP server is best ->`ntpdate pool.ntp.org`
###### steps:
1) **Identify Sources**
2) **Choose a Log Collector**
3) **Configure Collection Parameters** 
4) **Test Collection**

---
## Log Management

Efficient Log -> stored <mark style="background: #ABF7F7A6;">securely</mark>, organised <mark style="background: #ABF7F7A6;">systematically</mark>, and is ready for <mark style="background: #ABF7F7A6;">swift retrieval</mark>
**a hybrid approach** can provide a balanced solution by hoarding all log files and selectively trimming.
###### steps:
- **Storage:** Decide on a secure storage solution, considering factors like retention period and accessibility.
- **Organisation:** Classify logs based on their source, type, or other criteria for easier access later.
- **Backup:** Regularly back up your logs to prevent data loss.
- **Review:** Periodically review logs to ensure they are correctly stored and categorised.

---
## Log Centralisation

Centralisation -> pivotal for swift log access, in-depth analysis, and rapid incident response
###### steps:
- **Choose a Centralised System:** such as the Elastic Stack or Splunk.
- **Integrate Sources:** Connect all your log sources to this centralised system.
- **Set Up Monitoring:** Utilise tools that provide<mark style="background: #FFB86CA6;"> real-time monitoring</mark> and <mark style="background: #FFB86CA6;">alerts</mark> for specified events.
- **Integration with Incident Management:** Ensure that your centralised system can <mark style="background: #FFB86CA6;">integrate</mark> seamlessly with any incident management tools or protocols you have in place.

---
## Log Storage

###### depends on:
 - **Security Requirements**
- **Accessibility Needs**
- **Storage Capacity** 
- **Cost Considerations**
- **Compliance Regulations**
- **Retention Policies** 
- **Disaster Recovery Plans**

---
## Log Retention

- **Hot Storage:** Logs from the past **3-6 months** that are <mark style="background: #BBFABBA6;">most accessible</mark>. Query speed should be near real-time, depending on the complexity of the query.
- **Warm Storage:** Logs from **six months to 2 years**, acting as a <mark style="background: #BBFABBA6;">data lake</mark>, easily accessible but not as immediate as Hot storage.
- **Cold Storage:** Archived or compressed logs from **2-5 years**. These logs are not easily accessible and are usually used for <mark style="background: #BBFABBA6;">retroactive analysis</mark> or <mark style="background: #BBFABBA6;">scoping purposes</mark>.

---

***Best Practices: Log Storage, Retention and Deletion***

- Determine the storage, retention, and deletion<mark style="background: #FFB8EBA6;"> policy</mark> based on both business needs and legal requirements.
- Regularly review and <mark style="background: #FFB8EBA6;">update the guidelines</mark> per changing conditions and regulations.
- <mark style="background: #FFB8EBA6;">Automate</mark> the storage, retention, and deletion processes to ensure consistency and avoid human errors.
- <mark style="background: #FFB8EBA6;">Encrypt</mark> sensitive logs to protect data.
- <mark style="background: #FFB8EBA6;">Regular backups</mark> should be made, especially before deletion.

---
## Log Analysis Process

- **Data Sources** -> systems or applications configured or user activities -> the<mark style="background: #FF5582A6;"> origin of logs</mark>
- **Parsing** -> <mark style="background: #FF5582A6;">breaking down</mark> log data to more manageable and understandable components -> to extract valuable information.
- **Normalisation** -> <mark style="background: #FF5582A6;">standardising</mark> parsed data ->  makes comparing and analysing data from different sources easier
- **Sorting** -> efficient data retrieval and identification of <mark style="background: #FF5582A6;">patterns</mark> -> dentifying trends and anomalies
- **Classification** -> <mark style="background: #FF5582A6;">assigning categories</mark> based on characteristics -> identify potential issues or threats that could be overlooked -> automated using machine learning
- **Enrichment** -> <mark style="background: #FF5582A6;">adds context</mark> to logs to make them more meaningful and easier to analyse -> make better decisions and more accurately respond to incidents ->  automated using machine learning
- **Correlation** -> <mark style="background: #FF5582A6;">linking related records</mark> and identifying connections between log entries -> critical in determining security threats or system performance issues
- **Visualisation** -> represents in <mark style="background: #FF5582A6;">graphical formats</mark> -> ecognising patterns, trends, and anomalies easier.
- **Reporting** -> <mark style="background: #FF5582A6;">summarises</mark> log data into structured formats -> provide insights, support decision-making, or meet compliance requirements
---
## Log Analysis Tools

complex analysis -> security Information and Event Management (SIEM) tools -> _Splunk_ or _Elastic Search_
immediate data analysis -> during incident respons :
- Linux-based ->`cat`, `grep`, `sed`, `sort`, `uniq`, and `awk`, along with `sha256sum`
- windows-based -> [EZ-Tools](https://ericzimmerman.github.io/#!index.md) and the default cmdlet `Get-FileHash`
  
---
## Log Analysis Techniques

- **Pattern Recognition** 
- **Anomaly Detection** 
- **Correlation Analysis**
- **Timeline Analysis**
- **Machine Learning and AI**
-  **Visualisation**
- **Statistical Analysis**
