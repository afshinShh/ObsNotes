# exploit and chain
## Manipulating WebSocket messages

[[unprocessed-obsidians/OLD/WEB/vulnerabilities/WebSockets/concepts#Manipulating WebSocket traffic|manipulate WebSocket]] 
-> test for xss by changing message [[unprocessed-obsidians/OLD/WEB/vulnerabilities/WebSockets/Examples#Manipulating WebSocket messages|payload]]
## Manipulating the WebSocket handshake
[[unprocessed-obsidians/OLD/WEB/vulnerabilities/WebSockets/concepts#Manipulating WebSocket connections|Manipulating WebSocket connections]]
## tools
-  [WebSocket Turbo Intruder](https://portswigger.net/bappstore/ba292c5982ea426c95c9d7325d9a1066) by portswigger
- [wsrepl](https://github.com/doyensec/wsrepl) (Websocket Read-Eval-Print Loop (REPL) for pentesters) from doyensec - see the paper here: ([Streamlining Websocket Pentesting with wsrepl](https://blog.doyensec.com/2023/07/18/streamlining-websocket-pentesting-with-wsrepl.html))
- Kettle, J. [_Backslash Powered Scanning: hunting unknown vulnerability classes_](https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes). PortSwigger. 2016
### automation methodology
[Full article](https://aretekzs.com/posts/fuzzing-ws) (Fuzzing WebSockets for Server-Side Vulnerabilities)

- [the Backslash Powered Scanner](https://github.com/PortSwigger/backslash-powered-scanner/) extension takes advantage of predefined metrics to compare responses. But ==metrics used for HTTP traffic cannot be directly applied to WebSockets== due to the fundamental differences between the protocols.
	- the following metrics would be good to take a look at:
		- [ ] the total number of messages received.
		- [ ] the sequence of received message types (text or binary)
		- [ ] the individual lengths of received messages
		- [ ] the number of spaces in each message
		- [ ] the number of HTML tags in each message
	- the common strategy:
	    - [ ] For simple cases (e.g., sending a message and expecting a single reply), you may only need to set the response capture time window.
	    - [ ] For more complex scenarios (e.g., applications using Socket.IO), you may need to send prerequisite messages such as a `40` to complete the protocol handshake, and add a short delay to avoid breaking the connection.
	- [ ] Select a WebSocket message and launch the extension.
	- [ ] If the message is in JSON or Socket.IO format, the extension will automatically fuzz all fields and JSON escape the payloads.
		- [ ] If it's not, you can wrap the desired insertion point with `FUZZ`, and the extension will target that area.
	- [ ] If no marker is provided, the extension will fuzz the entire message as a single unit.
	- In the settings, the response capture time window and, if needed, the delay, should be in milliseconds. If multiple prerequisite messages are needed, they can be separated using the `FUZZ` string.
		setting example: ![[Pasted image 20260311220638.png]]
