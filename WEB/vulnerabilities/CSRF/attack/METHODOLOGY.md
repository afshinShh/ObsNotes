
# test & exploit
 
no defense -> create a form ( [[WEB/vulnerabilities/CSRF/attack/payload#basic| basic payload]] )
## Bypassing CSRF-token validation

- change request method to get -> accepted -> delete method property of form 
- delete the entire csrf parameter 
- same request from 2 different user =>
  - swap csrf values
  - make request -> save csrf -> drop request -> use the saved csrf-token with another user 
  - change csrfKey cookie -> not related to session ->
    - use csrf-token+csrfKey on another user
    - find sink where you can inject cookie -> use a html element to deliver crafted link 
      [[WEB/vulnerabilities/CSRF/attack/payload#token tied to non-session cookie| token tied to non-session cookie]]
- same csrf is duplicated in cookie -> invent csrf token -> inject csrf cookie (same as injecting csrfKey)

## Bypassing SameSite cookie restrictions

### concepts

![[Pasted image 20230905141119.png]]
![[Pasted image 20230905141141.png]]

- top-level domain (TLD) -> `.com` or `.net`
- "effective top-level domain" (eTLD) -> `.co.uk`
- [[WEB/vulnerabilities/CSRF/attack/payload#What's the difference between a site and an origin?|examples]]
- SameSite restriction levels: -> `Set-Cookie:` `SameSite=?`
  - [`Strict`](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#strict) -> does not match the site currently shown in the browser's address bar, it will not include the cookie
  - [`Lax`](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#lax) -> default for Chrome -> OK if:  1)`GET` method 2)top-level navigation(such as clicking on a link).
  - [`None`](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#none) ->  disables SameSite -> cookie is intended to be used from a third-party context -> + `Secure`
/gitcomm
# chain 


**remember to check the [[checklist]]**
