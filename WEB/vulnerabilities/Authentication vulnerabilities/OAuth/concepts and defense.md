# *What* is OAuth?

- **authorization framework**-> <mark style="background: #FF5582A6;">enables websites and web applications to request limited access to a user's account on another application</mark>.
- the user fine-tunes the shared data. 

# *How* does OAuth 2.0 work?

- **Client application** - The website or web application that *wants to access* the user's data.
- **Resource owner** - *The user* whose data the client application wants to access.
- **OAuth service provider** - The website or application that *controls the user's data* and access to it. -> through API 

1. The <mark style="background: #BBFABBA6;">client requests access</mark> to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
2. The <mark style="background: #BBFABBA6;">user is prompted to log in</mark> to the OAuth service and explicitly give their consent for the requested access.
3. The <mark style="background: #BBFABBA6;">client application receives a unique access token</mark> that proves they have permission from the user to access the requested data. (depending on the grant type)
4. The client application uses this access token to make <mark style="background: #BBFABBA6;">API calls fetching the relevant data</mark> from the resource server.
# OAuth grant types

- also called **OAuth flows** -> <mark style="background: #FF5582A6;">determines the exact sequence of steps</mark> that are involved in the OAuth process
- The _OAuth service_ must be configured to _support_ a particular grant type
- The _client application_ _specifies_ which grant type it wants to use
### OAuth scopes

`scope` parameter of the authorization request = <mark style="background: #FF5582A6;">specification of the data</mark> which the client application wants to access -> *arbitraty text string* -> standardized:OpenID Connect 
- `scope=contacts
- `scope=contacts.read
- `scope=contact-list-r
- `scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly`
- ...
## Authorization code grant type

- <mark style="background: #FF5582A6;">in a glance</mark>:![[Pasted image 20231209120059.png]] [source](https://portswigger.net/web-security/images/oauth-authorization-code-flow.jpg)
- **the most secure** -> sensitive data (access token and user data) is not sent via the browser.
### 1. Authorization request
- request to the OAuth service's *`/authorization` endpoint* -> may vary between providers
```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

- **`client_id`** 
  -  Mandatory 
  -  unique *identifier of the client application*
  -  generated when the client application registers with the OAuth service
- **`redirect_uri`**
  - The URI to which the *user's browser should be redirected when sending the authorization code* to the client application.
  - _known as_:
    - `callback URI` 
    - `callback endpoint`
- **`response_type`**
  -  which *kind of response* the client application is expecting => *flow / grant type*
    authorization code grant type -> `code`
- **`scope`** 
  -  to specify which subset of the *user's data the client application wants to access*
  -  custom or defined by the OpenID connect specification.
- **`state`**
  - unique, unguessable value that is tied to the current session on the client application -> *CSRF token*
  - for the client app -> identifies the user 
### 2. User login and consent
- authorization server receives the request -> redirects user to the OAuth provider's login page
- list of data that the client application wants to access -> based on `scope`
- if the user revisit the client application later, it will often be able to log back in with a single click
### 3. Authorization code grant
- the user's browser will be redirected to the `/callback endpoint` = `redirect_uri` parameter
- contains the authorization code
```http
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```
### 4. Access token request
```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```
- *server-to-server* (all communication from this point also) in a secure back-channel
- *`client_secret`* -> authenticates the client appilication
- *`grant_type`* -> makes sure the new endpoint knows it -> in this case: `authorization_code`
### 5. Access token grant
- => everything is as expected
```json
{
    "access_token": "z0y9x8w7v6u5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile",
    …
}
```
### 6. API call
- the client application has the access code => it can finally fetch the user's data.
```http
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```
### 7. Resource grant
```json
{
    "username":"carlos",
    "email":"carlos@carlos-montoya.net",
    …
}
```
- data -> based on the `scope` of the token
- the client application grants the user an authenticated session => logging them in
## Implicit grant type

- <mark style="background: #FF5582A6;">in a glance</mark>: ![[Pasted image 20231209213934.png]] [source](https://portswigger.net/web-security/images/oauth-implicit-flow.jpg)
- *no authorization code* step... => no 
- all communication happens via *browser redirects* => no secure back-channel => far **less secure**
- more suited to <mark style="background: #FFF3A3A6;">single-page</mark> applications and <mark style="background: #FFF3A3A6;">native desktop</mark> applications
  - they cannot easily store the `client_secret`
### 1. Authorization request
```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
- **`response_type`** parameter must be set to *`token`*
### 2. User login and consent
(same process)
### 3. Access token grant
```http
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```
- instead of *authorization code -> access token and other token-specific data* as a __URL fragment__ => client application extracts the fragment and stores it.
### 4. API call
(same process but _via the browser_)
### 5. Resource grant
(same process but _via the browser_)
/gitcommiall