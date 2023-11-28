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

- if the application *returns the resulting error message* within its response
- use a <mark style="background: #BBFABBA6;">non existent path for url</mark> to raise error message [[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#via error messages|example]]
## repurposing a local DTD
#todo 

# hidden attack surfaces

## XInclude

- some applications *embed* client-submitted data *into an XML document* and  then parse it. 
  -> like SOAP requests 
- **`XInclude`** : allows an XML document to be *built from sub-documents* -> <mark style="background: #BBFABBA6;">you need only a single item of data</mark> -> reference the `XInclude` namespace + path to the file [[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#XInclude|example]] 
## via file upload

- *office document formats like **DOCX*** and *image formats like **SVG*** [[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#via file upload|example]]
- even if the application expect PNG or JPEG the *image processing library* that is being used might support SVG 

## via modified content type

- change the default content type of *POST request* from `application/x-www-form-urlencoded` to `text/xml`
  => ez hidden XXE attack surface [[WEB/vulnerabilities/XML vulnerabilities/XXE/payload#via modified content type|example]]
  