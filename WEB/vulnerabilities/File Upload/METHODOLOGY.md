no defense -> upload server-side scripts+execute as code =>  simple RCE via web shell upload [[WEB/vulnerabilities/File Upload/payload#basic|basic]]
# Exploiting flawed validation 

## Flawed file type validation
##### concepts
- when submitting HTML form content type of the `POST` request:
	- *simple text* -> `application/x-www-form-url-encoded`
	- *large amounts of binary data*, such as an entire *image file* or a *PDF* document -> `multipart/form-data`
		- each part contains a `Content-Disposition` (basic information about the input field)
			- may contain their own `Content-Type` header
##### exploit
=> **change the `Content-Type` header** [[WEB/vulnerabilities/File Upload/payload#Flawed file type validation|example]]
## Preventing file execution in user-accessible directories

- find a way to **upload in other directories**
  - `filename` field in `multipart/form-data` [[WEB/vulnerabilities/File Upload/payload#Preventing file execution in user-accessible directories|example]]
- server serves the contents of the file as plain text -> *source code leakage* (no RCE)
# Insufficient blacklisting

## Overriding the server configuration

- search for the *webserver config files* -> change the content of it to allow RCE [[WEB/vulnerabilities/File Upload/payload#Overriding the server configuration|example]] 
	- apache: `.htaccess` , `/etc/apache2/apache2.conf`
	- IIS: `web.config`
	- ...
## Obfuscating file extensions

/gitcomm