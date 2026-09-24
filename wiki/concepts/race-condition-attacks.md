---
title: Race Condition Attacks & Concurrency Exploitation
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - race-condition
  - business-logic
  - bug-bounty
sources:
  - unprocessed-obsidians/race-condition.md
confidence: high
contested: false
contradictions: []
---

# Race Condition Attacks & Concurrency Exploitation

## Overview
A race condition occurs when a system's substantive behavior depends on the relative timing or interleaving of concurrent execution threads or processes. In web applications, race conditions emerge when multiple HTTP requests access and modify shared state (e.g. database rows, account balances, cached tokens, filesystem paths) without adequate atomic locking or strict transaction isolation.

## Concurrency Vulnerability Primitives

```
Thread 1: Check balance ($100 >= $100) -> OK
   Thread 2: Check balance ($100 >= $100) -> OK
Thread 1: Deduct $100 -> Balance becomes $0
   Thread 2: Deduct $100 -> Balance becomes -$100 (or double withdrawal)
```

### 1. Time-of-Check to Time-of-Use (TOCTOU)
A security check is performed (e.g. verifying coupon validity), but before the state change is finalized, a concurrent request executes the same check. Both requests pass the check before either decrements the balance.

### 2. Read-Modify-Write Desynchronization
Non-atomic operations in web handlers:
1. `val = db.query("SELECT balance FROM accounts WHERE id = 1")`
2. `val = val - withdraw_amount`
3. `db.execute("UPDATE accounts SET balance = ? WHERE id = 1", val)`
If two threads execute Step 1 concurrently, the second write overwrites the first, losing track of the true state change.

## High-Risk Business Logic Scenarios
- **Financial Balance Exfiltration**: Simultaneous withdrawal or transfer requests from the same account exceeding available balance.
- **Single-Use Coupon & Voucher Multiplication**: Submitting 20 simultaneous redemption requests for a single-use $50 promo code, yielding $1000 in credits.
- **File Upload Race Windows**: Uploading an executable webshell (`shell.php`) that is temporarily written to disk while an anti-virus or image verification routine runs; accessing the file URL during the 500ms window before deletion executes the payload.
- **Account Registration & Identifier Collision**: Creating duplicate accounts claiming the identical username or email address.

## Testing Methodologies: The HTTP/2 Single-Packet Attack
Traditional multi-threaded testing suffered from network jitter (TCP packet round-trip time differences). The modern **HTTP/2 single-packet attack** (pioneered by PortSwigger) completely eliminates network jitter:
1. Multiple HTTP/2 request streams are prepared on a single TCP connection.
2. The initial headers and body bytes (minus the final byte) of all requests are transmitted.
3. The server receives and buffers all requests.
4. The client sends a single TCP packet containing the final byte for all 20+ streams simultaneously.
5. The server backend processes all requests at the identical millisecond, triggering sub-millisecond race windows with near-100% reliability.

### Turbo Intruder Scripting Pattern
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    # Queue 20 requests without concluding the stream
    for i in range(20):
        engine.queue(target.req, gate='race1')
    # Release all requests in a single TCP packet
    engine.openGate('race1')
```

## Defensive Hardening
1. **Atomic Database Operations**: Use atomic update queries rather than Read-Modify-Write in application code:
   ```sql
   UPDATE accounts SET balance = balance - 100 WHERE id = 1 AND balance >= 100;
   ```
2. **Database Row-Level Locking**: Enforce `SELECT ... FOR UPDATE` within transactions.
3. **Distributed Locks**: Implement Redis-based distributed mutexes (`Redlock`) keyed by user or resource ID around critical sections.
4. **Idempotency Keys**: Require client-supplied unique tokens per transaction to deduplicate rapid replay submissions.

## Related Pages
- [[race-condition]]
- [[insecure-direct-object-reference]]
- [[graphql-security]]
