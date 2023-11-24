# Obfuscating attacks using encodings

- *evade input filters* -> for a variety of attacks like <mark style="background: #FF5582A6;">XSS</mark> and <mark style="background: #FF5582A6;">SQL injection</mark>
## Context-specific decoding

- Both clients and servers use different decoding *to pass data between systems* -> when they want to use it, they have to decode it first.
- The exact sequence of decoding steps that are performed depends on <mark style="background: #FFF3A3A6;">the context in which the data appears</mark>. -> think about *where exactly your data is being injected*  
- Injection attacks -> injecting payloads that use recognizable patterns -> defenses block *suspicious patterns*. -> decoded data *should be same as* the decoding performed by the *back-end server or browser*
## URL encoding

ex: "Fish & Chips" -> `[...]/?search=Fish+%26+Chips`
- space -> `%20` or `+`
-  URL-based input -> URL decoded *server-side*
- `%22`, `%3C`, and `%3E` ->  `"`, `<`, and `>`
- if WAF fails in decoding correctly -> `SELECT` becomes `%53%45%4C%45%43%54` -> SQL injection
## double URL encoding

ex: `<img src=x onerror=alert(1)>` -> `[...]/?search=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` -> `[...]/?search=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E`
- encode key characters which WAF may filter -> `%` -> `%25`
## HTML encoding

ex: `<img src=x onerror=alert(1)>` -> `<img src=x onerror="&#x61;lert(1)">` 
- a *name* can be used for the reference -> `:`(colon) -> `&colon;`
- a *reference* may be provided using the character's decimal / hex code point -> `:`(colon) -> `&#58;` / `&#x3a;`
-  when using *decimal or hex-style* HTML encoding -> you can <mark style="background: #BBFABBA6;">optionally add leading zeros</mark> in the code points
   `:`(colon) -> `&#0000000000058` -> `<a href="javascript&#00000000000058;alert(1)">Click me</a>`
## XML encoding

ex:
```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```
- supports character encoding using the *same numeric escape sequences as HTML*
## unicode escaping

ex: DOM XSS -> `eval("\u0061lert(1)")`
- consist of the prefix `\u` followed by the *four-digit hex code* for the character -> `:`(colon) -> `\u003a`
-  *ES6* also supports a *new form* of unicode escape using *curly braces* -> `:`(colon) ->  `\u{3a}`
- gets decoded by JavaScript engine used by browsers (also most programming languages) -> *client-side* payloads
- it <mark style="background: #FFB86CA6;">must be inside a string context</mark> -> you *can't scape characters outside of string*(opening and closing parentheses, for example)
-  *ES6-style* unicode escapes <mark style="background: #BBFABBA6;">allow optional leading zeros</mark>. -> `<a href="javascript\u{0000000003a}alert(1)">Click me</a>`

## hex escaping

ex: `eval("\x61lert")`
- when injecting into a *string context*
- represent characters using their hexadecimal code point, prefixed with `\x` -> `a` -> `\x61`
- also *usefull for SQL injection* -> `SELECT` -> `0x53454c454354`
## octal escaping

ex: `eval("\141lert(1)")`
- same as hex scaping -> character references use a *base-8 numbering* system rather than base-16(hex)
- prefixed with a standalone backslash -> `a` -> `\141`

## using multiple encodings

ex: `<a href="javascript:&bsol;u0061lert(1)">Click me</a>` -> (`&bsol;` :`\` -> `u0061` becoms `\u0061` -> `a` character) 
-> `<a href="javascript:alert(1)">Click me</a>`
## SQL CHAR() function

ex: `CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)` -> `SELECT`
- `CHAR()`function : accepts a single *decimal or hex* code point and returns the *matching character*
- Hex codes must be prefixed with `0x` -> both `CHAR(83)` and `CHAR(0x53)` return the capital letter `S`
/git