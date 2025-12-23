# Open Redirect
## examples
### header based (= serverside redirect):
- Generally, server-side redirects always make use of the **Location** HTTP response header along with a <mark style="background: #BBFABBA6;">3XX HTTP status code</mark> (such as 301, 302 or 307)
```python
from flask import Flask, request, redirect
app = Flask(__name__)

@app.route("/")
def page():
    next = request.values.get('next')
    if next:
    	return redirect(next)
    else:
    	return 'Hi :)'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
```
###  JS based(= client side redirect):
- no **Location** header change 
- generally small delay 
```html
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Redirector</title>
	<script type="text/javascript">
		if(window.location.hash) {
			var hash = window.location.hash.substring(1); //Puts hash in variable, and removes the # character
			window.location = hash
			// hash found
		}
	</script>
</head>
<body>
<h1>Hello :-)</h1>
</body>
</html>
```
### checker function 
```php
<?php
function check_hmac($url, $hmac){
	return ($hmac == md5($url));
}

if (isset($_GET['url']) && isset($_GET['h'])) {
	if (check_hmac($_GET['url'], $_GET['h'])) header('Location: ' . $_GET['url']);
	else echo 'Invalid HMAC';
}

?>
<pre>
<a href="?url=https://google.com&h=99999ebcfdb78df077ad2727fd00969f">Google.com</a>
```
### Vulnerable code 
opening [the link](https://github.com/julz0815/mtech-training/blob/4a0d8fcec1d3883f140221cb8580a093ad277934/src/main/java/com/veracode/verademo/controller/UserController.java#L82) shows to the vulnerable code, the `/?target=` is vulnerable to Open Redirect ( RequestParam is an [annotation to extract query parameters](https://www.baeldung.com/spring-request-param)):
```java
@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String showLogin(
			@RequestParam(value = "target", required = false) String target,
			@RequestParam(value = "username", required = false) String username,
			Model model,
			HttpServletRequest httpRequest,
			HttpServletResponse httpResponse)
	{
		// Check if user is already logged in
		if (httpRequest.getSession().getAttribute("username") != null) {
			logger.info("User is already logged in - redirecting...");
			if (target != null && !target.isEmpty() && !target.equals("null")) {
				return "redirect:" + target;
			}
			else {
				// default to user's feed
				return "redirect:feed";
			}
		}

		User user = UserFactory.createFromRequest(httpRequest);
		if (user != null) {
			httpRequest.getSession().setAttribute("username", user.getUserName());
			logger.info("User is remembered - redirecting...");
			if (target != null && !target.isEmpty() && !target.equals("null")) {
				return "redirect:" + target;
			}
			else {
				// default to user's feed
				return "redirect:feed";
			}
		}
		else {
			logger.info("User is not remembered");
		}

		if (username == null) {
			username = "";
		}

		if (target == null) {
			target = "";
		}

		logger.info("Entering showLogin with username " + username + " and target " + target);

		model.addAttribute("username", username);
		model.addAttribute("target", target);
		return "login";
	}
```