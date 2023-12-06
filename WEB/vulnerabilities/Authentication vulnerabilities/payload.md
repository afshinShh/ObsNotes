# password-based login

## Brute-force attacks

### Brute-forcing usernames

#### Username enumeration

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
>   - `password`: same password but for each username repeated untill the rate limit gets reached -> null payload
>    => `username=§invalid-username§&password=example§§`
> - *`You have made too many incorrect login attempts`*
>   - => username achieved
> - *payload*: *sniper*:
>   - *Grep - Extract* -> the message
>   - `password`: wordlis
>     -> one has no error message 
>     => password achieved


