most cases 
     - authentication -> session (checked every request)
     - Re-Authentication token is saved in the Cookie (checked only if the Session is not present)
       ![[Pasted image 20250921190655.png]]
- user can alter 
	- session token
	- cookie 
## authentication token 
- stateless
- In session based application behind load balancer, **sticky session** mechanism should be used ([more info](https://medium.com/@mrcyna/what-are-the-sticky-sessions-222c378d2ce1))
- Multiple platforms and domains (CORS: * )
- commonly saved in
	- **localStorage**
	- **sessionStorage**

# SSO 
- Allows a user to log in with a single ID to any of several related, yet independent, software systems
 - ***implementations***:
	  - Redirect 
	  - CORS
	  - JSONP
	  - oAuth
	  - SAML

## JSONP Call

- **loading a remote JavaScript object by `script` tag**. SOP *does not affect script tag* so there is no need to configure CORS
XmlHttpRequest -> cannot load page's content

```html
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Test</title>
</head>
<body>
<script type="text/javascript">

var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
	  alert(this.responseText);
	}
};
xhttp.open("GET", "https://www.w3schools.com/js/demo_jsonp.php", true);
xhttp.send();

</script>
</body>
</html>
```
- JSONP call -> loads  
```html
<!DOCTYPE html>
<html>
<body>

<h2>Request JSON using the script tag</h2>
<p>The PHP file returns a call to a function that will handle the JSON data.</p>
<p id="demo"></p>

<script>
function myFunc(myObj) {
  document.getElementById("demo").innerHTML = myObj.name;
}
</script>

<script src="https://www.w3schools.com/js/demo_jsonp.php"></script>

</body>
</html>
```

### Case number 1
![[Pasted image 20250924224615.png]]
### Case number2
![[Pasted image 20250924224555.png]]
# OAuth

- OAuth is an open standard for **access delegation** -> Authorization method 
	- using it as authentication method -> pseudo-authentication
-  [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/OAuth/concepts and defense|concepts and defense]]
- authorization code flow with PKCE
	- ![[Pasted image 20250924233858.png]]