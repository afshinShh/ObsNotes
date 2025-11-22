
- unicodes are decoded in js code
	- in nodejs apps : yashar === y\u0061shar
- HTML attributes are decoded automatically
- XSS is not related to content-type => always check for it (e.g  json:) 
	- doesnt url encode/decode
	- XSS in json sent data -> must be *DOM XSS* 
# XSS
## Contexts: 
- **Outside a tag**
	- script tag
	- tag + event handler
	-  </a> + js scheme 
	- non executable tag (eg </title>)
- **Inside a tag** 
	- break the attr & tag 
	- break the attr + event handler
	- attr (eg href / srcdoc)
- **JS context**
	- close </script>
	- break the context (expressions "-" )
- **DOM**
	- reflected but not in source code (ctrl + u ) => DOM
- **postMessage**
	- dangerous sink ? yes 
		- can we control input? yes
			- is it vulnerable? depends => can I Exploit my friend?
	- we cannot forge e.origin in message 
	- not only XSS but CSRF or ATO
## Post XSS
- [ ] ATO
	- [ ] change password
	- [ ] account bind (linking victim's account to that account = in other words: integrations)
- [ ] PII information leakage



# Narrow recon

- Dorking 
	- google + ===Bing=== 
	- omit the resources you wont need
- better to use old diffrernt snapshots in wayback machine [How?](https://archive.org/developers/wayback-cdx-server.html)
	- use `fl=timestamp` + `collapse=digest` for differet hashes
	- you can use [robofinder](https://github.com/Spix0r/robofinder) for robots.txt
- Katana is not good with DOM 
	- *Passive Crawling always / active crawling only in automation*
-  

# FUZZing
- sanding maformed|unexpected HTTP reqs
- to trigger unexpected behavior
- to discover hidden|unlinked  resources 
	- files
	- parameter
	- header
- you should balance the fuzzing condition
- ===***FOLLOW the LEAST CHANGE principle***=== (no kermanshaahi hack :)
### hidden resources
- unlinked directories|files
- development|testing environments
- API endpoints
- config files
### tools 
- FFUF
- ***[recollapse](https://github.com/0xacb/recollapse)***
- crunch
- hand
- GAP
	- use value replacement -> observe interesting behavior(reflection|change|malfunction) -> *reduce* and change values to exploit 
- fallparams 
	- discover parameters at first and filterout (leach:) 
- x8 | Arjun
- paramMiner
	- mess with the configs -> goes to target tree 
	- its wordlist is goated
- IIS shortname scanner
### checking phase
- ===**check the reliability of fuzzing**===
	- find a ***hook*** (static files are better)
	- verify the fuzzing by the hook (my pov: *dont use automatic filtering*)
- repeat  
-  testing your hook: 
```bash
wList_maker() {
    seq 1 100 > list.tmp
    echo $1 >> list.tmp
    seq 101 300 >> list.tmp
    echo $1 >> list.tmp
    seq 301 600 >> list.tmp
} #you MUST filter out all then find your hook when fuzzing -> -mc all -fs [something] => Now thats a good FUZZ
```
### inputs
- WAF, **checker function**, restriction, validation, etc bypass
- use *[recollapse](https://github.com/0xacb/recollapse)*
- Ranges 
	- 0x00, 0x2F
	- 0x3A, 0x40
	- 0x5B, 0x60
### files
1. recognize the *Web Server architecture*
2. recognize the *filename patterns*
	- login.php
	- loginUser.php
	- LoginUser.php
	- user_count.php => FUZZlowercase_ FUZZlowercase.php
3. FUZZ for JS files
4. FUZZ on status codes
### endpoints
- => function()
- Flask, Rails,Express,etc are route-based
- use Ffuf for normal fuzzing *partially* 
-  `/api/users/all`
	- `/api/users/FUZZ`
	- `/api/FUZZ/all`
	- `/api/FUZZ`  
- again ... you MUST use a hook
- **FOLLOW THE LEAST CHANGE PRINCIPLE**
### parameters
- query string parameters can be increased, as long as the server handles the request (in average 25 -> 40 params)
- the number of parameters included in each HTTP request is called a ***chunk***
	- smaller chunk => improves discovery
- fuzz on various *status codes* (including 404 -> web application)
- fuzzing *headers is similar to fuzzing parameters*, nothing special
- fuzz with both *GET and POST* HTTP methods
#### magic parameters
- every web app has hidden parameters
	- Findable in web app
	- *similar to other parameter names*
		- yahoo_home_url -> yahoo_home_redirect
		- use_local_engine -> reflects into engine json object
			- ? -> frontend json object
			- use_FUZZ_engine -> use_remote_engine
	- totally new
- ==**programmers use the same parameter names on different pages**==
	- (e.g all params -> unfurl (extract params) -> use elsewhere)
- **where**? 
	- all HTTP req parameters
	- HTML form names + ids + etc
	- JS variable names
	- JSON object in js files
- example ? 
	- (passive (waymore + paramSpider)(`inurl:? || inurl:&`) + active (manually like GAP + automated like x8 + fallparams))
	-  (e.g manual GAP -> replace values -> interesting behavior | e.g automated x8)
	- *MANUALL is ALWASY BETTER* (false positive)
```bash
param_maker() {
    filename="$1"
    value="$2"
    counter=0
    query_string=""

    while IFS= read -r keyword
    do
        if [ -n "$keyword" ]
        then
            counter=$((counter+1))
            query_string="${query_string}${keyword}=${value}${counter}&"
        fi

        if [ $counter -eq 25 ]
        then
            echo "${query_string%?}"
            query_string=""
            counter=0
        fi
    done < "$filename"

    if [ $counter -gt 0 ]
    then
        echo "${query_string%?}"
    fi
}
```
### wordlist
- generic -> **[wordlist_with_underscore.txt](https://wordlists-cdn.assetnote.io/data/manual/wordlist_with_underscores.txt)** 
- make you own 
	- 3(.-_ included) & 4 alphanumeric ->  crunch
	- ASCII characters are good to fuzz
	- **PATERNS** again
	- gather wordlists by Hand

### over CDN 
- lower your threads + delay
- capture by burp => add the corresponding headers
- proxy through burp + turn on HTTP2  


