# Proxy WebSockets Filter
Documentation: [Filtering the WebSockets history with Bambdas](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history/bambdas)

> [! example] 
> 
This example script filters the WebSockets history to show only items that meet the following criteria: 
> - The message must be sent from the server.
> - The message payload length must be greater than `300` characters.
> `return message.payload().length() > 300 && message.direction() == Direction.SERVER_TO_CLIENT;`
## [ExtractPayloadToNotes.bambda](https://github.com/PortSwigger/bambdas/blob/main/Filter/Proxy/WS/ExtractPayloadToNotes.bambda)
### Extracts JSON elements from the WebSocket message and displays it in the "Notes" column of the WebSocket History tab
#### Author: Nick Coblentz (https://github.com/ncoblentz)
```java
//The bambda will search for json elements with the following keys. The keys below are just examples. Add the keys you want to include here:
List<String> terms = List.of("target","error");

if (!message.annotations().hasNotes()) {
  StringBuilder builder = new StringBuilder();
  String payload = utilities().byteUtils().convertToString(message.payload().getBytes());
  terms.forEach(term -> {
    Matcher m = Pattern.compile("\"" + term + "\":\"([^\"]+)\"", Pattern.CASE_INSENSITIVE).matcher(payload);
    while (m.find() && m.groupCount() > 0) {
      for (int i = 1; i <= m.groupCount(); i++) {
        if (m.group(i) != null)
          builder.append(term + ": " + m.group(i) + " ");
      }
    }
  });
  message.annotations().setNotes(builder.toString());
}
return true;

```
