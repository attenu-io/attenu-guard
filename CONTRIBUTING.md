# Contributing

Thanks for helping make agent delegation safe.

## Ground rules

- **DCO required.** Sign off every commit (`git commit -s`). By doing so you
  certify the [Developer Certificate of Origin](https://developercertificate.org/).
  We use DCO rather than a CLA so the project stays genuinely community-owned.
- **Apache-2.0.** All contributions are under the project license. Do not paste
  code under GPL/AGPL/BUSL or any copyleft/commercial-restriction license — it
  will be rejected (we keep the tree clean for downstream commercial use).
- **Tests are not optional.** Any change to `authority.py`, `chain.py`, or
  `guard.py` must keep `python tests/run_properties.py` green and add a case if
  it introduces a new behaviour. Invariant changes need a property, not an
  example.

## Scope of the open library

We happily take: new framework adapters, new ceiling types, audit-schema
consumers/exporters (SIEM connectors especially), performance, docs, and
hardening. We will politely redirect one thing: anything that *derives* authority
automatically from an application's structure or a task belongs in
[`attenu-derive`](https://github.com/attenu-io/attenu-derive), the open engine, not
here — the boundary keeps this library thin and dependency-free. Asking "can it
decide the policy for me?" is a feature request for the engine, and we'll point
you there kindly.

## Dev loop

```bash
python tests/run_properties.py     # zero-dep invariant check
pytest                             # full hypothesis suite (pip install -e '.[test]')
python examples/poisoned_summarizer.py
```
