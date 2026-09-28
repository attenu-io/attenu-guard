# Streaming the ledger

*Every allow and deny, sent to your own endpoint as it is decided. Each block below ran on
`attenu-guard==0.18.0` from PyPI, Python 3.14.6, macOS, and its output is pasted from that run.*

## The model

Every `check()` appends one JSON line to a hash-chained ledger: the `node` that asked, the `scope`,
the decision as `event`, and on a `deny` the `reason`. Issuing and delegating add `root` and `spawn`
lines. Each line's `hash` covers the line and the previous `hash`, so the chain verifies from the file
alone.

## Tail the file

`audit_path` appends each entry to a file as it is decided. This is the README quickstart's scenario,
with a pause before each check:

```python
# agent.py
import time
from attenu_guard import Authority, Guard, RowLimit

parent = Guard.issue("orchestrator", Authority(
    scopes={"crm.*", "mail.send"}, ceilings=[RowLimit(100_000)], ttl=3600),
    audit_path="log.jsonl")
child = parent.delegate("summarizer", Authority(
    scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900), task="summarize Q3")

for scope in ("crm.read", "crm.export"):
    time.sleep(1)
    print(scope, child.check(scope, context={"rows": 4_200}).explain())
```

Start `tail -F`, which waits for the file, then `python agent.py` in a second terminal.

```console
$ tail -F log.jsonl
{"agent":"orchestrator","authority":{"constraints":[{"key":"max_rows","max":100000}],"scopes":["crm.*","mail.send"],"ttl":3600},"c14n":"JCS","chain_id":"chain","event":"root","hash":"c3cbf3569722ca34eafabc2dff88d961288fcc2779eaacbcfdfc879e5e672763","node":"chain:n0","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":0,"ts":1,"v":1}
{"agent":"summarizer","c14n":"JCS","chain_id":"chain","event":"spawn","granted":{"constraints":[{"key":"max_rows","max":5000}],"scopes":["crm.read"],"ttl":900},"hash":"c18f3b9802d0c7b65cabad7d3df5da53227918f7b47d061567c8e07f515e768b","node":"chain:n1","parent":"chain:n0","prev_hash":"c3cbf3569722ca34eafabc2dff88d961288fcc2779eaacbcfdfc879e5e672763","requested":{"constraints":[{"key":"max_rows","max":5000}],"scopes":["crm.read"],"ttl":900},"seq":1,"task":"summarize Q3","ts":2,"v":1}
{"c14n":"JCS","chain_id":"chain","context":{"rows":4200},"event":"allow","hash":"eee1629a4dfbb0d01076681be1a63857597d9be683a5ff802275633152bad28d","node":"chain:n1","prev_hash":"c18f3b9802d0c7b65cabad7d3df5da53227918f7b47d061567c8e07f515e768b","scope":"crm.read","seq":2,"tool":null,"ts":3,"v":1}
{"c14n":"JCS","chain_id":"chain","context":{"rows":4200},"disposition":"out_of_authority","event":"deny","hash":"8dec7b885b425b47611ea8559c84cbe1952ce1f6147d74a76b4c0eea188c8488","node":"chain:n1","prev_hash":"eee1629a4dfbb0d01076681be1a63857597d9be683a5ff802275633152bad28d","reason":"scope_not_granted","reasons":[{"code":"scope_not_granted","constraint":null,"limit":null,"message":"scope 'crm.export' not covered by held scopes ['crm.read']","requested":"crm.export"}],"scope":"crm.export","seq":3,"tool":null,"ts":4,"v":1}
```

## A custom sink

A sink is any object with a `write(entry)` method, passed as `Guard.issue(..., audit_sinks=[...])`. The
ledger calls it for every entry right after the file write, on the calling thread and under its lock. A
slow `write()` slows every `check()` on the chain, and one that raises makes `check()` raise
`CommittedAuditError` with the entry already chained. So this sink only queues; a thread does the POST:

```python
# post_sink.py
import json, queue, threading, urllib.request

class PostSink:
    def __init__(self, url):
        self.url, self.queue = url, queue.Queue()
        threading.Thread(target=self._send, daemon=True).start()

    def write(self, entry):              # inside check(): queue and return
        self.queue.put(json.dumps(entry).encode())

    def _send(self):
        while True:
            body = self.queue.get()
            try:
                request = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
                urllib.request.urlopen(request, timeout=5).close()
            except OSError as exc:
                print("not delivered:", exc)
            self.queue.task_done()
```

The endpoint, a stdlib HTTP server, re-checks the chain on every POST and keeps a copy:

```python
# receiver.py
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from attenu_guard import AuditLog, canonical

received, out = [], open("received.jsonl", "wb")

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        entry = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        received.append(entry)
        ok, problem = AuditLog.verify(received)
        out.write(canonical.dumps(entry) + b"\n")       # the agent's exact bytes
        out.flush()
        print(*(f"{k}={entry[k]}" for k in ("seq", "event", "node", "scope", "reason") if k in entry),
              "| chain OK" if ok else f"| {problem}", flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 8765), Receiver).serve_forever()
```

The agent is `agent.py` without the pause, with the sink passed in:

```python
# agent_post.py
from attenu_guard import Authority, Guard, RowLimit
from post_sink import PostSink

sink = PostSink("http://127.0.0.1:8765/ledger")
parent = Guard.issue("orchestrator", Authority(
    scopes={"crm.*", "mail.send"}, ceilings=[RowLimit(100_000)], ttl=3600),
    audit_path="log.jsonl", audit_sinks=[sink])
child = parent.delegate("summarizer", Authority(
    scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900), task="summarize Q3")

for scope in ("crm.read", "crm.export"):
    print(scope, child.check(scope, context={"rows": 4_200}).explain())
sink.queue.join()                        # send everything before exit
```

In a fresh directory, start the receiver, then the agent in a second terminal:

```console
$ python receiver.py
seq=0 event=root node=chain:n0 | chain OK
seq=1 event=spawn node=chain:n1 | chain OK
seq=2 event=allow node=chain:n1 scope=crm.read | chain OK
seq=3 event=deny node=chain:n1 scope=crm.export reason=scope_not_granted | chain OK
```

```console
$ python agent_post.py
crm.read allowed
crm.export denied: scope_not_granted requested=crm.export: scope 'crm.export' not covered by held scopes ['crm.read']
```

With the endpoint down, `check()` still returns. For delivery that survives a crash or an outage, pass
`attenu_guard.sinks.SpoolSink("spool.ndjson")` instead. It appends each entry, with the key
`(boot_id, chain_id, seq, hash)`, to a bounded local file; your uploader POSTs what `read_pending()`
returns and calls `ack(n)` once the endpoint confirms.

## Verify at the endpoint

The receiver re-runs `AuditLog.verify` over everything it holds: a missing or reordered entry shows as
a `seq` gap, an altered one as a hash mismatch. Its file holds the agent's bytes, so the CLI verifies it
too:

```console
$ cmp log.jsonl received.jsonl && attenu-guard verify received.jsonl
OK
$ sed -i.bak 's/"event":"deny"/"event":"allow"/' received.jsonl
$ attenu-guard verify received.jsonl
TAMPERED — hash mismatch at seq 3
```

A chain check cannot catch a log re-hashed from the edit onward, or a missing last entry. A signed
anchor over the head catches both: `evidence.export_bundle(guard.audit_log(), signer)` adds one, and
`attenu-guard verify bundle.json --pubkey HEX` checks the anchor, child ⊆ parent and containment.
Both ends need `pip install 'attenu-guard[crypto]'` for Ed25519.

## What the console does with it

Attenu's console, which is not public, takes these entries through a `SpoolSink` that a separate
uploader drains, stores each line once under its idempotency key and flags a line that contradicts the
stored chain. It draws the delegation graph and the denials, and runs `verify_bundle` with the
product's key once a signed anchor arrives.

## Limits

- An entry records authorization, not execution: an `allow` does not say the tool ran or what it
  returned. See [what the evidence does not prove](THREAT-MODEL.md#what-the-evidence-does-not-prove).
- A call that never reaches `check()` or an adapter's hook leaves no line.
- `PostSink` drops an entry whose POST fails, and a crash loses what is still queued. `log.jsonl`
  already has every entry the sink was given.
- The hash does not identify a stream: two processes running the same workload write identical hashes
  from the first line. Tag each process (`identity.boot_id()`) and give each chain its own `chain_id`.

Not yet, in 0.18.0:

- An uploader that drains `SpoolSink` to HTTP with retries. The loop around `read_pending()` and
  `ack()` is yours.
- Incremental verification. `AuditLog.verify` re-walks the chain from `seq` 0 on every call.
