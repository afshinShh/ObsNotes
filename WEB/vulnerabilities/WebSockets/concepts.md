#  What are WebSockets?

[WebSockets](https://portswigger.net/web-security/websockets) are a <mark style="background: #FF5582A6;">bi-directional</mark>, <mark style="background: #FF5582A6;">full duplex</mark>(client and server can send message at the same time) communications protocol initiated <mark style="background: #FF5582A6;">over HTTP</mark>.

## HTTP vs WebSockets

<mark style="background: #FFF3A3A6;">HTTP</mark> -> client sends request and server responds | Even if the network connection stays open, this will be used for a separate transaction of a request and a response.

<mark style="background: #FFF3A3A6;">WebSockets</mark> -> initiated over HTTP | typically long-lived | Messages can be sent in either direction at any time and are not transactional in nature ->  low-latency or server-initiated messages: (like real-time feeds of financial data)
## How are WebSocket connections established?

```js
var ws = new WebSocket("wss://normal-website.com/chat");
```
request:
```http
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```
response:
```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

- ws -> websocket | wss -> ws over TLS
- `Connection` and `Upgrade` -> WebSocket handshake
- `Sec-WebSocket-Version` -> WebSocket protocol version
- `Sec-WebSocket-Key` ->  Base64-encoded random value ->generated in each handshake request
- `Sec-WebSocket-Accept` -> hash of the value submitted in the `Sec-WebSocket-Key` -> prevent misleading responses resulting from misconfigured servers or caching proxies
## What do WebSocket messages look like?

- simple ->  `ws.send("Peter Wiener");`
- a chat-bot application that uses json message: 
```json
{"user":"Hal Pline","content":"I wanted to be a Playstation growing up, not a device to answer your inane questions"}
```

# How to secure a WebSocket connection? 

![[Pasted image 20230905183625.png]]

- Use the `wss://` protocol (<mark style="background: #D2B3FFA6;">WebSockets over TLS</mark>).
- <mark style="background: #D2B3FFA6;">Hard code the URL</mark> of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
- Protect the WebSocket handshake message against <mark style="background: #D2B3FFA6;">CSRF</mark>, to avoid _cross-site WebSockets hijacking_ vulnerabilities.
- <mark style="background: #D2B3FFA6;">Treat data </mark>received via the WebSocket <mark style="background: #D2B3FFA6;">as untrusted</mark> in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as _SQL injection_ and _cross-site scripting_.
  /gitcomm