# path traversal (directory traversal)

- -> read arbitrary files on the server that is running an application:
	- Sensitive operating system files.
	- Credentials for back-end systems.
	- Application code and data.

- -> write to arbitrary files on the server -> modify application data or behavior -> take full control of the server.

## why this is happening?

Imagine a shopping application that displays images of items for sale using the following html tag

```html
<img src="/loadImage?filename=218.png">
```

- image files are stored on disk in the location `/var/www/images/`
- To return an image, the <mark style="background: #FFF3A3A6;">application appends the requested filename to this base directory</mark> and uses a filesystem API to read the contents of the file -> reads from `/var/www/images/218.png`
- if no defense is implemented attacker can use : `https://insecure-website.com/loadImage?filename=../../../etc/passwd` -> application reads and (after <mark style="background: #FFB86CA6;">normalization</mark>) returns  `/var/www/images/../../../etc/passwd` = `/etc/passwd`
- note : on windows `../` and `..\` are valid example: `https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`

