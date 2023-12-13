## Vulnerabilities in the OAuth client application

##### Authentication bypass via OAuth implicit flow
> 1. click "My account" ->   complete the OAuth login process
> 2. study the requests and responses that make up the OAuth flow
> 3. **`POST` request** from client application to its own *`/authenticate` endpoint*
> 4. change the email address to target and send the request -> **"Request in browser"** -> "**In original session**"
>    => account takeover
##### Forced OAuth profile linking
>1. *`GET /auth?client_id[...]`*: `redirect_uri` send authorization code to **`/oauth-linking`** + *no `state parameter`*
> 2. try again -> "Copy URL" -> drop the request 
> 3. `<iframe src="https://site.net/oauth-linking?code=STOLEN-CODE"></iframe>`
>    => account takeover

