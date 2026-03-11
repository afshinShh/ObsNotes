** Table of Contents **

- [What are WebSockets?](#What%20are%20WebSockets?)
	- [HTTP vs WebSockets](#HTTP%20vs%20WebSockets)
	- [How are WebSocket connections established?](#How%20are%20WebSocket%20connections%20established?)
	- [What do WebSocket messages look like?](#What%20do%20WebSocket%20messages%20look%20like?)
- [Manipulating WebSocket traffic](#Manipulating%20WebSocket%20traffic)
	- [Intercepting and modifying WebSocket messages](#Intercepting%20and%20modifying%20WebSocket%20messages)
	- [Replaying and generating new WebSocket messages](#Replaying%20and%20generating%20new%20WebSocket%20messages)
	- [Manipulating WebSocket connections](#Manipulating%20WebSocket%20connections)
				- [how to (using Burp):](#how%20to%20(using%20Burp):)
- [How to secure a WebSocket connection?](#How%20to%20secure%20a%20WebSocket%20connection?)

#  What are WebSockets?

[WebSockets](https://portswigger.net/web-security/websockets) are a <mark style="background: #FF5582A6;">bi-directional</mark>, <mark style="background: #FF5582A6;">full duplex</mark>(client and server can send message at the same time) communications protocol initiated <mark style="background: #FF5582A6;">over HTTP</mark>.

## HTTP vs WebSockets

<mark style="background: #FFF3A3A6;">HTTP</mark> -> client sends request and server responds | Even if the network connection stays open, this will be used for a separate transaction of a request and a response.

<mark style="background: #FFF3A3A6;">WebSockets</mark> -> initiated over HTTP | typically long-lived | Messages can be sent in either direction at any time and are not transactional in nature ->  low-latency or server-initiated messages: (like real-time feeds of financial data)
![[Pasted image 20260311203055.png]]
- Text representation of a WebSocket frame [reference](https://aretekzs.com/posts/fuzzing-ws/#1)
-  Messages in WebSocket connection are transmitted as *frames*, which are low-level units that encapsulate the actual payload. Each frame includes metadata such as an _opcode_ (indicating message type), *masking information* (required for client-to-server messages to mitigate attacks such as cache poisoning), and fragmentation *flags* (to support message splitting across multiple frames). Each message can be composed of one or more frames, and *messages can be of two different types: text or binary*. Both types can be intermixed within the same session.
## How are WebSocket connections established?

- ![[Pasted image 20260311210740.png]]
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
## A Look at [Socket.IO](https://socket.io/) 
- source article -> [Mastering WebSockets Vulnerabilities](https://deepstrike.io/blog/mastering-websockets-vulnerabilities) 

[Socket.IO](https://socket.io/) is a popular JavaScript library that builds an additional protocol layer on top of WebSockets, providing extra features like automatic reconnection, heartbeats, and high-level events.

_How to Spot It:_
- Look for `?EIO=` in the handshake URL (e.g., `?EIO=4`)
- Watch for specific framing patterns in the messages

_Common [Socket.IO](https://socket.io/) Frames:_
- `40` - Connection opened successfully
- `2` and `3` - Ping/Pong heartbeats to keep the connection alive
- `42["eventName", payload]` - Event with data (e.g., `42["message","hello"]`)

_Why It Matters:_
==Each event== maps directly to server-side handlers, making them equivalent to HTTP endpoints that ==require proper validation and authorization== if not ? => may be vulnerable
### Basic [Socket.IO](http://Socket.IO) fuzzing
> [!example] Intruder example:
```python
import burp.api.montoya.http.message.params.HttpParameter as HttpParameter

def queue_websockets(upgrade_request, message):
    connection = websocket_connection.create(
        upgrade_request.withUpdatedParameters(HttpParameter.urlParameter("EIO", "4")))
    connection.queue('40')
    connection.queue('42["message","hello"]')

@Pong("3")
def handle_outgoing_message(websocket_message):
    results_table.add(websocket_message)

@PingPong("2", "3")
def handle_incoming_message(websocket_message):
    results_table.add(websocket_message)
```
**Use case:** More advanced attacks with better connection management.

> [!example] HTTP adapter variant:
```python
import burp.api.montoya.http.message.params.HttpParameter as HttpParameter

def create_connection(upgrade_request):
    connection = websocket_connection.create(
        upgrade_request.withUpdatedParameters(HttpParameter.urlParameter("EIO", "4")))
    connection.queue('40')
    connection.decIn()
    return connection

@Pong("3")
def handle_outgoing_message(websocket_message):
    results_table.add(websocket_message)

@PingPong("2", "3")
def handle_incoming_message(websocket_message):
    results_table.add(websocket_message)
```
---
# Manipulating WebSocket traffic

## Intercepting and modifying WebSocket messages

[WebSocket interception rules](https://portswigger.net/burp/documentation/desktop/settings/tools/proxy#websocket-interception-rules)
## Replaying and generating new WebSocket messages

select message in history -> repeater -> History Panel -> edit and resend 
## Manipulating WebSocket connections

situations for manipulating [[unprocessed-obsidians/OLD/WEB/vulnerabilities/WebSockets/concepts#How are WebSocket connections established?|the WebSocket handshake]] :

-  more attack surface.
-  connection drop -> establish a new one.
- Tokens or other data -> need updating.
##### how to (using Burp):
- Send a WebSocket message to Burp <mark style="background: #ADCCFFA6;">Repeater</mark> 
- <mark style="background: #ADCCFFA6;">pencil icon </mark>-> you can *attach* to an existing connected WebSocket/*clone* a connected WebSocket/*reconnect* to a disconnected WebSocket.
- you can edit the details via wizard
- click "Connect" -> see the results -> send new messages in Burp Repeater.

---
# How to secure a WebSocket connection? 

![[Pasted image 20230905183625.png]]

- Use the `wss://` protocol (<mark style="background: #D2B3FFA6;">WebSockets over TLS</mark>).
- <mark style="background: #D2B3FFA6;">Hard code the URL</mark> of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
- Protect the WebSocket handshake message against <mark style="background: #D2B3FFA6;">CSRF</mark>, to avoid _cross-site WebSockets hijacking_ vulnerabilities.
- <mark style="background: #D2B3FFA6;">Treat data </mark>received via the WebSocket <mark style="background: #D2B3FFA6;">as untrusted</mark> in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as _SQL injection_ and _cross-site scripting_.
  