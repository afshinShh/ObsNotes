---
title: Insecure Deserialization & Object Injection Attacks
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - deserialization
  - rce
  - bug-bounty
sources:
  - unprocessed-obsidians/insecure-deserialization.md
confidence: high
contested: false
contradictions: []
---

# Insecure Deserialization & Object Injection Attacks

## Overview
Serialization is the process of converting complex in-memory programming objects into binary or text streams for transmission or storage. Insecure Deserialization occurs when an application deserializes untrusted, user-supplied byte streams without strict allowlisting or cryptographic integrity checks. In object-oriented languages, object instantiation triggers magic methods or constructors before application logic executes, enabling attackers to instantiate arbitrary classes, construct **gadget chains**, and achieve arbitrary Remote Code Execution (RCE).

## Serialized Format Identification Signatures

| Language / Framework | Serialization Format | Common Magic Bytes / Encoding Signature | Dangerous Deserialization Function |
| :--- | :--- | :--- | :--- |
| **Java** | Native Object Serialization | Hex `ac ed 00 05` / Base64 `rO0AB...` | `ObjectInputStream.readObject()` |
| **PHP** | Native String Serialization | Text `O:4:"User":...` or `a:2:{...}` | `unserialize()` |
| **.NET** | BinaryFormatter / Soap | Base64 `AAEAAAD/////` | `BinaryFormatter.Deserialize()` |
| **Python** | Pickle / PyYAML | Binary opcodes / `!!python/object` | `pickle.loads()`, `yaml.load()` (without SafeLoader) |
| **Node.js** | node-serialize | JSON with `{"_$$ND_FUNC$$_": ...}` | `node-serialize.unserialize()` |
| **Ruby** | Marshal | Hex `` | `Marshal.load()` |

## Language-Specific Exploitation Mechanisms

### 1. Node.js `node-serialize` IIFE Exploitation
The `node-serialize` library supports serializing functions. When deserializing, functions wrapped with Immediately Invoked Function Expressions (IIFE) `()` execute instantly upon parsing:
```json
{
  "rce": "_$$ND_FUNC$$_function(){ require('child_process').execSync('whoami'); }()"
}
```

### 2. Python `pickle` Protocol Injection
Python's `pickle` module contains a virtual machine that executes opcodes. Using the `__reduce__` magic method returns a callable tuple that executes during deserialization:
```python
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('cat /etc/passwd',))

payload = pickle.dumps(Exploit())
```

### 3. Java Gadget Chains (ysoserial)
Java exploitation chains together classes already present on the application's classpath (gadgets):
- A root class (e.g. `BadAttributeValueExpException`) invokes methods like `toString()` or `hashCode()` upon deserialization.
- The invocation triggers getter methods in utility libraries (e.g. Apache Commons Collections, Spring, Jackson).
- The chain culminates in a dynamic class loader or template execution sink (`TemplatesImpl.newTransformer()`), executing arbitrary bytecode.

### 4. PHP Object Injection & PHAR Deserialization
PHP triggers magic methods (`__wakeup()`, `__destruct()`, `__toString()`) when objects are created or cleaned up:
- **PHAR Deserialization**: PHP archive files (`.phar`) store serialized metadata in their headers. Any filesystem function (`file_exists()`, `is_dir()`, `getimagesize()`) called with a `phar://` URL wrapper triggers deserialization of metadata even without calling `unserialize()` directly.

## Modern Vectors in Cloud Infrastructure
- **Message Queues & Event Streaming**: Asynchronous workers consuming serialized task payloads from RabbitMQ, Celery, or Kafka.
- **Microservices & Redis Caching**: Internal caching services storing serialized user sessions without cross-service signature checks.

## Defensive Hardening
1. **Avoid Native Deserialization**: Utilize safe, pure-data interchange formats (standard JSON, Protocol Buffers) that do not support code instantiation.
2. **Strict Class Allowlisting**: Where native deserialization is unavoidable, configure strict object filters (e.g. Java `ObjectInputFilter`, Python avoiding `pickle` for untrusted input).
3. **Cryptographic Signing**: Sign serialized blobs with HMAC-SHA256 before storage or transmission, rejecting any blob with an invalid signature.

## Related Pages
- [[insecure-deserialization]]
- [[server-side-template-injection]]
- [[xml-external-entity-injection]]
