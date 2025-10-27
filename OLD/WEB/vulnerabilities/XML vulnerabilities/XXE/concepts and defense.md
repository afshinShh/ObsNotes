-  XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to *interfere with an application's processing of XML data*
## How do XXE vulnerabilities arise?

-  because the XML specification contains various potentially **dangerous features**, and *standard parsers support these* features even if they are not normally used by the application.
- <mark style="background: #FFB86CA6;">XML external entities</mark> -> they allow an entity to be defined based on the contents of a* file path or URL* [[OLD/WEB/vulnerabilities/XML vulnerabilities/concepts#What are XML external entities?|definition]]
## What are the types of XXE attacks?

There are various types of XXE attacks:

- [Exploiting XXE to retrieve files](https://portswigger.net/web-security/xxe#exploiting-xxe-to-retrieve-files), where an external entity is defined containing the <mark style="background: #BBFABBA6;">contents of a file</mark>, and returned in the application's response.
- [Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe#exploiting-xxe-to-perform-ssrf-attacks), where an external entity is defined based on a <mark style="background: #BBFABBA6;">URL to a back-end system</mark>.
- [Exploiting blind XXE exfiltrate data out-of-band](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-exfiltrate-data-out-of-band), where sensitive <mark style="background: #BBFABBA6;">data is transmitted</mark> from the application server to a system that the attacker controls.
- [Exploiting blind XXE to retrieve data via error messages](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages), where the attacker can trigger a parsing <mark style="background: #BBFABBA6;">error message containing sensitive data</mark>.
## How to find and test for XXE vulnerabilities

- Testing for [file retrieval](https://portswigger.net/web-security/xxe#exploiting-xxe-to-retrieve-files) by <mark style="background: #FFF3A3A6;">defining an external entity based on a well-known operating system file </mark>and using that entity in data that is returned in the application's response.
- Testing for [blind XXE vulnerabilities](https://portswigger.net/web-security/xxe/blind) by <mark style="background: #FFF3A3A6;">defining an external entity based on a URL to a system that you control</mark>, and monitoring for interactions with that system. [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) is perfect for this purpose.
- Testing for <mark style="background: #FFF3A3A6;">vulnerable inclusion of user-supplied non-XML data within a server-side XML document</mark> by using an [XInclude attack](https://portswigger.net/web-security/xxe#xinclude-attacks) to try to retrieve a well-known operating system file.
# defense 

***cause*** -> XML parsing library supports potentially *dangerous XML features* that the application does not need or intend to use -> disable those features
- disable support for *`XInclude`* (verriding default behavior)
- *Consult the documentation* for your XML parsing library or API for details about how to disable unnecessary capabilities.

