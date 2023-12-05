# password-based login

## Brute-force attacks

### Brute-forcing usernames

#### Username enumeration

- **via different responses**:
>1) *in the `POST /login` request*: `username=§invalid-username§`
>2) *Payload*: *Sniper* -> simple list
>3) **Length** *column* -> different response :  `Invalid username`/`Incorrect password` 
>   => username achieved
>4) `username=identified-user&password=§invalid-password§`
>5) `200` status code except for one, which got a **`302`** 
>   => password achieved

- **via subtly different responses**:
> **Settings** tab -> **Grep - Extract**, click Add -> `Invalid username or password`
> *one of the responses contains* **typo**: full stop/period -> trailing space 
> => username achieved
> ...

- **via response timing**
> 1) IP gets blocked after several request 
> **`X-Forwarded-For`** header is supported -> *IP spoof*
> 2) use a very *long password* for password field (*time consuming* to proccess)
> 3) *payload*: *Pitchfork* 
>    `X-Forwarded-For`: Numbers
>    `username`: simple list
>    Columns -> *Response received* and *Response completed* -> significant difference 
>    => username achieved
> 4)  *payload*: *Pitchfork* 
>    `X-Forwarded-For`: Numbers
>    `password`: simple list
>    -> `302` status
>    => password achieved

/gitcomm