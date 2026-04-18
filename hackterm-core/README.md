# hackterm-core

Shared MITM proxy infrastructure for `hack3270` and `hack5250`. Pure Python, no GUI dependency, stdlib only.

**Author:** Garland Glessner <gglessner@gmail.com>
**License:** GPL-3.0

## What's here

| Module | What |
|---|---|
| `protocol.py` | `Protocol` ABC — the contract both `TN3270` and `TN5250` implement. `parse()`, `mutate()`, `build_inbound()`, `negotiate_hook()`, `detect()`, `spoof_aid()`. Plus the dataclasses: `Screen`, `Field`, `MutateOpts`, `NegotiateOpts`, `FieldWrite`, `QueryLies`. |
| `proxy.py` | `ProxyDaemon` — headless `select()` loop. Owns the client+server socket pair. Drives `protocol.mutate()` on every host→client packet. Negotiation phase (until `detect()` returns True) routes through `negotiate_hook()` instead. Observer pattern + `set_client_intercept()` callback. |
| `ebcdic.py` | `EbcdicCodec` — codepage-aware (`cp037`, `cp500`, `cp1140`). Wraps Python's `codecs` with a `[0xNN]` fallback for non-ASCII bytes (preserves compatibility with hack3270's `TELNET_PATTERNS` regexes). |
| `storage.py` | `Storage` — SQLite. Schema is byte-identical to hack3270's so existing `.db` files open without migration. Parameterized queries (the legacy used string-format SQL). |
| `inject.py` | `MaskInjector` — the `****` template trick. Operator types asterisks in the target field, proxy intercepts and splits into preamble/mask/postamble. `TRUNC`/`SKIP`/`OVERFLOW` modes. |
| `api_server.py` | `ApiServer` — non-blocking line-based TCP listener with handler registry. Both tools register their own commands. |

## Install

```bash
pip install -e .
```

## The `Protocol` contract

Attack code is written against `Protocol` and never knows whether it's running on 3270 or 5250:

```python
from hackterm_core import Protocol, MutateOpts, Screen

class MyProtocol(Protocol):
    name = "myproto"
    aid_table = {"ENTER": 0x7D, ...}
    default_codepage = "cp037"

    def detect(self, first_bytes: bytes) -> bool: ...
    def negotiate_hook(self, data, direction, opts) -> bytes: ...
    def parse(self, data: bytes) -> Screen: ...
    def mutate(self, data: bytes, opts: MutateOpts) -> bytes: ...
    def build_inbound(self, aid, cursor, fields) -> bytes: ...
    def spoof_aid(self, original, new_aid) -> bytes: ...
```

`MutateOpts` field names are protocol-neutral:

| Field | 3270 | 5250 |
|---|---|---|
| `unprotect` | Clear SF attr bit 5 | Clear FFW bypass bit `0x2000` (only on hidden fields) |
| `reveal_hidden` | Clear attr bits 2&3 (`0x0C`) | Rewrite screen-attr `0x27` → `0x20` |
| `remove_numeric` | Clear SF attr bit 4 | Zero FFW shift bits `0x0700` |
| `high_visibility` | Inject SFE color pair | Use `0x22` (white) instead of `0x20` (green) |

## Tests

```bash
pytest  # 79 tests
```
