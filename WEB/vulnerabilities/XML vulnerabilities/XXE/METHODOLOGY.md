# exploit
## to retrieve files

- a `DOCTYPE` element that defines an *external entity containing the path to the file*.
- a *data value* in the XML that is *returned in the application's response*. [[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#to retrieve files|example]]
=> <mark style="background: #D2B3FFA6;">sensitive data exposure</mark>
## to perform SSRF attacks

- define an *external XML entity using the target's URL*.
- again a *data value* in the XML that is *returned in the application's response*.[[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#to perform SSRF attacks|example]]
  -  no response? -> go *blind XXE*
=> <mark style="background: #D2B3FFA6;">two-way interaction with the back-end system</mark>.

# Blind XXE

- This means that the application *does not return the values* of any defined external entities *in its responses*.
## via out-of-band 

- **out-of-band [OAST](https://portswigger.net/burp/application-security-testing/oast)** -> same as performing SSRF but <mark style="background: #BBFABBA6;">URL= a domain which attacker controls</mark> 
  - reqular entities are blocked -> use **[[WEB/vulnerabilities/XML vulnerabilities/concepts#What are XML Parameter entities?|parameter entities]]** 
  - <mark style="background: #FF5582A6;">exploit</mark>  ->  host a malicious DTD  -> invoke the external DTD from within the in-band XXE payload  [[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#via out-of-band|example]]
## via error messages

