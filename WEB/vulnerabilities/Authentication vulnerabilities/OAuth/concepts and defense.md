# *What* is OAuth?

- **authorization framework**-> <mark style="background: #FF5582A6;">enables websites and web applications to request limited access to a user's account on another application</mark>.
- the user fine-tunes the shared data. 

# *How* does OAuth 2.0 *work*?

- **Client application** - The website or web application that *wants to access* the user's data.
- **Resource owner** - *The user* whose data the client application wants to access.
- **OAuth service provider** - The website or application that *controls the user's data* and access to it. -> through API 

1. The <mark style="background: #BBFABBA6;">client requests access</mark> to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
2. The <mark style="background: #BBFABBA6;">user is prompted to log in</mark> to the OAuth service and explicitly give their consent for the requested access.
3. The <mark style="background: #BBFABBA6;">client application receives a unique access token</mark> that proves they have permission from the user to access the requested data. (depending on the grant type)
4. The client application uses this access token to make <mark style="background: #BBFABBA6;">API calls fetching the relevant data</mark> from the resource server.
## OAuth authentication
- the same basic OAuth flows -> <mark style="background: #FF5582A6;">difference: how the client application uses the data</mark> that it receives
  - resembles SAML-based **single sign-on (SSO)**

1. log in with your social media account option -> oauth service of the social media 
   - username 
   - email 
   - etc...
2. the client application requests the data from a dedicated `/userinfo` endpoint
3. *The access token* that it received from the authorization server is often used *instead of a traditional password*.
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
# OpenID Connect(OIDC)
## *What* is OpenID Connect?

- adds <mark style="background: #FF5582A6;">standardized, identity-related features</mark> to make **authentication** via OAuth work in a more reliable and uniform way 
  => solves many of basic OAuth implementation problems:
  - the client application had no way of knowing *when, where, or how the user was authenticated*
  - no *standard way of requesting user data for authentication* purpose.
## *How* does OpenID Connect work?

- From the client application's perspective: 
  - additional **standardized set of scopes** that are the same for all providers
  - extra **response type**: **`id_token`**
### OpenID Connect roles
same as for standard OAuth -> <mark style="background: #BBFABBA6;">different terminology</mark> 
- **Relying party** = OAuth client application
- **End user** = OAuth resource owner
- **OpenID provider** = OAuth service (that supports OpenID Connect) 
### OpenID Connect claims and scopes
- **claims -> `key:value`** pairs that represent <mark style="background: #FF5582A6;">information about the user</mark> on the resource server.
  - ex: `"family_name":"Montoya"`
- identical set of **scopes** for the client application:
  - _must_ specify the scope **`openid`** 
  - _can_ include one or more of these:
    - *`profile`*
    - *`email`*
    - *`address`*
    - *`phone`*
    - ...
  - ex: requesting the scope `openid profile` => read access to a series of claims related to the user's identity, such as `family_name`, `given_name`, `birth_date`, etc
##### OIDC Standard Claims and Scopes
[source](https://docs.vindicia.com/bundle/b_ConnectProductDescription/page/topics/OIDCStandardClaimsAndScopes_c.html)

- Below is the list of standard claims defined by OIDC:
  
| Claim                   | Type    | Description                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sub`                   | string  | **Subject** – A unique identifier for the user. This identifier may or may not be different for each relying party for a given user. This value is guaranteed not to change even if the user changes the properties of their account (for example, changes email address or phone number). Your application, if it wants to store user data, should use the **Subject** string as the unique identifier. |
| `name`                  | string  | Full name of the subject (that is, first name and last name)                                                                                                                                                                                                                                                                                                                                             |
| `family_name`           | string  | Last name of the subject                                                                                                                                                                                                                                                                                                                                                                                 |
| `given_name`            | string  | First name of the subject                                                                                                                                                                                                                                                                                                                                                                                |
| `picture`               | string  | URL to the subject's profile picture hosted on the issuer's server, if any                                                                                                                                                                                                                                                                                                                               |
| `locale`                | string  | Language setting of the subject                                                                                                                                                                                                                                                                                                                                                                          |
| `updated_at`            | integer | The last time the subject's profile was updated                                                                                                                                                                                                                                                                                                                                                          |
| `email`                 | string  | Email address of the subject                                                                                                                                                                                                                                                                                                                                                                             |
| `email_verified`        | boolean | Specifies whether the email address has been verified                                                                                                                                                                                                                                                                                                                                                    |
| `phone_number`          | string  | Phone number of the subject                                                                                                                                                                                                                                                                                                                                                                              |
| `phone_number_verified` | boolean | Specifies whether the phone number has been verified                                                                                                                                                                                                                                                                                                                                                     |

- The OIDC standard defines several scopes that map to standard claims as below:
  
| Scope            | Claims                                                                                                                                       |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `openid`         | Enables OIDC by requesting the ID Token (in addition to an access token). Without this scope, the request is not OIDC, but merely OAuth 2.0. |
| `profile`        | `name, family_name, given_name, picture, locale, updated_at`                                                                                 |
| `email`          | `email, email_verified`                                                                                                                      |
| `phone`          | `phone_number, phone_number_verified`                                                                                                        |
| `offline_access` | Requests that a refresh token be issued (in addition to an access token).                                                                    |
### ID token
- `id_token` response type -> <mark style="background: #FF5582A6;">returns a JSON web token (JWT)</mark> signed with a JSON web signature (JWS)
  - a *list of claims based on the scope* that was initially requested
  - information about *how and when the user was last authenticated* by the OAuth service
- **main benefit**: reduced number of requests => <mark style="background: #BBFABBA6;">better performance</mark>
  - access token then request data separately -> ID token  
  - simply relying on trusted channel ->  JWT cryptographic signature => less MITM attack chance (still possible -> keys are transmitted over the same network -> normally **`/.well-known/jwks.json`** )
  - *multiple options are supported* by OAuth ex:
    - `response_type=id_token token`
    - `response_type=id_token code`
# *How* do OAuth authentication *vulnerabilities arise*?

- authentication vulnerabilities -> <mark style="background: #FF5582A6;">because the OAuth specification is relatively vague and flexible by design</mark>.
  - configuration settings that are necessary for keeping users' data secure => bad practice
- <mark style="background: #FFB86CA6;">general lack of built-in security features</mark> => security relies on developers 
# *How to prevent* OAuth authentication vulnerabilities?

## For OAuth service providers

- Require client applications to register a whitelist of valid `redirect_uris`. Wherever possible, use strict byte-for-byte comparison to validate the URI in any incoming requests. Only allow complete and exact matches rather than using pattern matching. This prevents attackers from accessing other pages on the whitelisted domains.
- Enforce use of the `state` parameter. Its value should also be bound to the user's session by including some unguessable, session-specific data, such as a hash containing the session cookie. This helps protect users against CSRF-like attacks. It also makes it much more difficult for an attacker to use any stolen authorization codes.
- On the resource server, make sure you verify that the access token was issued to the same `client_id` that is making the request. You should also check the scope being requested to make sure that this matches the scope for which the token was originally granted.

## For OAuth client applications

- Make sure you fully understand the details of how OAuth works before implementing it. Many vulnerabilities are caused by a simple lack of understanding of what exactly is happening at each stage and how this can potentially be exploited.
- Use the `state` parameter even though it is not mandatory.
- Send a `redirect_uri` parameter not only to the `/authorization` endpoint, but also to the `/token` endpoint.
- When developing mobile or native desktop OAuth client applications, it is often not possible to keep the `client_secret` private. In these situations, the `PKCE` (`RFC 7636`) mechanism may be used to provide additional protection against access code interception or leakage.
- If you use the OpenID Connect `id_token`, make sure it is properly validated according to the JSON Web Signature, JSON Web Encryption, and OpenID specifications.
- Be careful with authorization codes - they may be leaked via `Referer` headers when external images, scripts, or CSS content is loaded. It is also important to not include them in the dynamically generated JavaScript files as they may be executed from external domains via `<script>` tags.
