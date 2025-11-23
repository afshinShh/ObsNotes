

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
### indicators

- when does the **misconfigration** accurs ? -> any of these conditions:
	- [ ] The request method is GET.
	- [ ] The authentication mechanism is through the cookie header.
	- [ ] The callback function or `jsonp` GET parameter is present in the request header.
	- [ ] Apart from the default headers, the request should not have additional headers.
	- [ ] The response Content-Type header is `application/x-javascript` or `text/javascript`.
	- [ ] The response content has a function and data like Anything-Here-as-a-Function({JSON data}).

_Tip:_ If the `callback` or `json` GET parameters are not present in the request, and the request and response match the above conditions, the JSONP-leveraged attack is still possible.]
## cases
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
#### Understanding Key OAuth Parameters

Now that we’ve walked through the basic OAuth Authorization Code flow, let’s take a look at some OAuth parameters to help understand the attack vectors:

- **`redirect_uri`**: The URI where the OAuth provider will redirect the user (in our case, John) after they have either granted or denied authorization. This URI must be pre-registered with the OAuth provider as part of the client application’s registration process.
- **`response_type`**: Specifies what kind of response the client application expects from the OAuth provider. The most common response_type values are:
    - **`code`**:
        - **Flow Name***: Authorization Code grant.
        - **Description:** The client expects the resource owner (user) to authorize the request, which prompts the authorization server to issue an authorization code. This code can then be exchanged by the client for an access token, allowing the client to access protected resources on behalf of the resource owner. This is the most common type used in web server flows.
    - **`token`**:
        - **Flow Name:** Implicit Grant.
        - **Description:** The client expects an access token **directly** from the resource owner. This is often used in client-side applications, like single-page apps (SPAs) such as Gmail or Facebook, where the client doesn’t have a backend server to handle the exchange of an authorization code.
    - **`client_id`**: A unique identifier that the OAuth provider (in our case, GitHub) issues to the client application (example.com).
    - **`scope`**: Allows the client to request specific permissions when it initiates the OAuth flow.
    - **`state`**: A security feature used to prevent [cross-site request forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) attacks.
    - **`prompt`**: A parameter that controls how the authorization server prompts the user during the authentication process. Common options include:
        - `none`: No user interaction; will fail if user consent or authentication is required.
        - `login`: Forces the user to log in again, regardless of their current session.
        - `consent`: Forces the user to consent to the requested permissions, even if consent was previously granted.
        - `select_account`: Prompts the user to select from multiple accounts if they are logged in with more than one.
    - **`response_mode`**: Specifies how the authorization response is returned to the client. Common options include:
        - `query`: The response is sent as query parameters (“?”) in the URI.
        - `fragment`: The response is sent as fragment (“#”) parameters in the URI.
        - `form_post`: The response is returned as a form submission (typically used for servers that can handle POST requests more securely)
# access control 

- Access control defines permission of users
- Defines each user is authorized to do a specific action or not
## types

- **Vertical**
- **Horizontal**
- **Context-dependent** -> upon the state of the application or the user's interaction with it
  - access to *functionality* (BFLA)
  - access to *object* (BOLA | IDOR)
### 403 & 401 Bypasses

Check the response headers, maybe some information can be given. For example, a **200 response** to **HEAD** with `Content-Length: 55` means that the **HEAD verb can access the info**.

### IDOR 
- direct access to an object in an internal database but does not check for access control
- example of *tricky situation*
  - ![[Pasted image 20250927061358.png]]
    the `user_id` is IDOR safe. However, in last example the `profile_pic` might be vulnerable to IDOR. Changing the `profile_pic` ID may result in viewing other users profile image.

exampe of *safe code*:
```php
public function destroyAddress($id, Request $request)
    {
        $address = Address::where('id',$id)->where('user_id',\auth()->user()->id)->first();
        if ($address){
            $address->delete();
            return helpers::preparedJsonResponseWithMessage(true, 'The address has been deleted successfully');
        }
    }
```

