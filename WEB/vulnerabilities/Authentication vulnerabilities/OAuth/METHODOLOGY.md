# Identifying
## OAuth authentication

- proxy your traffic login option
- requests to *`/authorization` endpoint* containing *OAuth parameters*
## OpenID Connect
# Recon

- follow the OAuth flow:
  - identify the **specific provider** from the *hostname* => read the <mark style="background: #FF5582A6;">documentation</mark>
    - exact names of the endpoints
    - configuration options
  - <mark style="background: #FF5582A6;">`GET` request</mark> to the following => JSON configuration file containing key information
    - *`/.well-known/oauth-authorization-server`*
    - *`/.well-known/openid-configuration`*

# exploit
## Vulnerabilities in the OAuth client application

-  ***Improper implementation of the implicit grant type*** (access token sent via users's browser) 
  - recommended for SPA but gets used in simple *client-server web app* -> app need to store the current user data (user ID and access token) somewhere
    -  **`POST` request** and then assign the user a session cookie  -> you can impersonate other usres via changing the `POST` parameters
- ***Flawed CSRF protection***
  - no or guessable `state` parameter => csrf attack 
