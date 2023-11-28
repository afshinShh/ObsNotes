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
## Insufficient blacklisting

### Overriding the server configuration

- search for the *webserver config files* -> change the content of it to allow RCE [[WEB/vulnerabilities/File Upload/payload#Overriding the server configuration|example]] 
	- apache: `.htaccess` , `/etc/apache2/apache2.conf`
	- IIS: `web.config`
	- ...
### Obfuscating file extensions

- **multiple extensions** 
	- `exploit.php.jpg` -> PHP file or JPG image
- **trailing character** 
	- `exploit.php.`
- use **URL encoding** (or double url encoding)
	- for dots, forward slashes, and backward slashes
	- `exploit%2Ephp`
- server validation in high level language (PHP, Java)but the server processes the file using low level languages(C/C++) -> **semicolons** or URL-encoded **null byte characters** before the file extension 
	- `exploit.asp;.jpg`
	- `exploit.asp%00.jpg` [[WEB/vulnerabilities/File Upload/payload#Obfuscating file extensions|example]]
- **multibyte unicode characters** -> may converted to null bytes after notmalization
	- filename passed as UTF-8 but then converted to ASCII
	- `xC0 x2E`, `xC4 xAE` or `xC0 xAE` -> `x2E` 
- if the extension gets replaced -> no recursion => smuggle it
	- `exploit.p.phphp`
## Flawed validation of the file's contents

- In the case of an <mark style="background: #FFB86CA6;">image upload</mark> the server might try to verify certain *intrinsic properties*
	- its dimensions
	- signature (magic number/magic bytes )
		- JPEG: `FF D8 FF`
		- ...
=> create a **polyglot JPEG** file containing malicious code within its metadata. [[WEB/vulnerabilities/File Upload/payload#Flawed validation of the file's contents|example]]

## Exploiting file upload race conditions
#todo
# Uploading files using PUT

- use `OPTIONS` request to test for support of `PUT` method
  - example:
    ```http
    PUT /images/exploit.php HTTP/1.1
    Host: vulnerable-website.com 
    Content-Type: application/x-httpd-php 
    Content-Length: 49 
    
    <?php echo file_get_contents('/path/to/file'); ?>
```

# Exploiting file upload vulnerabilities without remote code execution

## Uploading malicious client-side scripts

- if you can upload <mark style="background: #FFF3A3A6;">HTML files</mark> or <mark style="background: #FFF3A3A6;">SVG images</mark> -> you can potentially use `<script>` tags => **stored XSS**
- *same-origin policy* -> uploaded file should be served from the same origin which you uploaded it.

## parsing of uploaded files

- if server parses XML-based files:
  - Microsoft Office `.doc`
  - `.xls` files
=> **XXE injection**

/gitco