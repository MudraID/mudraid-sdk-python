# mudraid-sdk

Python SDK for [MudraID](https://mudraid.ai) — a trust layer for AI agents.

A **drop-in replacement for `requests`** that adds transparent agent
authentication via MudraID-issued short-lived JWTs. Every call your
agent makes is automatically signed, refreshed on expiry, and routed
to the right platform — with no decorators, no boilerplate, no
secrets in code.

```python
# Before
import requests
response = requests.get("https://api.skyscanner.com/flights")

# After
from mudraid import Agent
agent = Agent()  # auto-loads credentials from .env
response = agent.get("https://api.skyscanner.com/flights")
```

That's the entire integration diff.

### Which client to use

There are two authentication profiles, and the source recommends the newer one
for new integrations:

| | `Agent` (legacy) | `MachineAgent` (V2) |
|---|---|---|
| Authenticates with | an `api_key_id` + shared `secret` | a `private_key_jwt` client assertion (RFC 7523) — no shared secret on the wire |
| Scope of an issued token | the agent's **full** permitted set when none is named | exactly the scopes named; omitting them requests the **empty** set |
| Bound to a resource | no | yes, via an RFC 8707 resource indicator |
| Retry semantics | consequence-safe | consequence-safe (identical) |

`Agent` remains fully supported and is what the rest of this README shows,
because it is the shorter diff. **New integrations should prefer
`MachineAgent`** — a compromised platform cannot
replay a client assertion the way it can replay a shared secret, and an omitted
scope set cannot silently widen to everything.

The legacy profile will be deprecated with a runtime warning and a migration
window before any removal; `Agent.legacy()` names the choice explicitly at the
call site if you want it pinned.

---

## What the SDK actually does

For every outgoing request the SDK:

1. **Resolves** the URL's host to a MudraID `platform_id`
   (bootstrapped once at first use from `POST /auth/agents/me/platforms`).
2. **Mints** a short-lived JWT for that platform via `POST /auth/token`
   (cached in process memory until ~30 s before expiry).
3. **Attaches** `Authorization: Bearer <jwt>` to the request.
4. **Forwards** to `requests` and returns the response unmodified.

On 401 from the upstream platform, the SDK refreshes the JWT and retries
once **only when the retry is consequence-safe** — a GET, PUT, DELETE or
other idempotent method, or any request you have given an
`idempotency_key`. Token expiry in mid-flight is invisible to your code
for those. An unkeyed POST or PATCH is **not** replayed: the 401 is
returned to you, because a platform that performs the write and *then*
answers 401 would otherwise be charged, shipped or booked twice. See
[Retries never duplicate a consequential action](#retries-never-duplicate-a-consequential-action).

Two HTTP `Session` instances are held internally: one for MudraID,
one for outgoing platform calls. They never share connections — your
agent secret can never accidentally leak onto a platform-bound
request, by construction.

---

## Installation

```bash
pip install mudraid-sdk==1.1.0
```

Requires Python 3.10+.

---

## Quickstart

### 1. Register an agent on MudraID

Sign in to the MudraID portal (or call the API), create a new agent,
and grant it the platforms + scopes it needs. You'll receive **once**:

- `MUDRAID_API_KEY_ID` — public identifier (safe to log)
- `MUDRAID_SECRET` — private credential (never logged, never persisted)

### 2. Drop the credentials into your project's `.env`

```env
MUDRAID_API_KEY_ID=muid_kid_a3f8e9c1d2b4f5e6a7b8c9d0e1f2a3b4
MUDRAID_SECRET=muid_sk_...your-secret...
```

Add `.env` to your `.gitignore`. The SDK loads it automatically;
explicit OS-env values override `.env`; explicit kwargs override
both.

### 3. Replace `requests` with `Agent`

```python
from mudraid import Agent

agent = Agent()  # reads .env
response = agent.get("https://api.skyscanner.com/flights/search")
response.raise_for_status()
flights = response.json()
```

That's it. The SDK is now handling authentication for every call.

---

## Full request surface

`Agent` mirrors `requests.Session`:

```python
agent.get(url, **kwargs)        # GET
agent.head(url, **kwargs)       # HEAD
agent.options(url, **kwargs)    # OPTIONS

agent.post(url, idempotency_key=None, **kwargs)     # POST
agent.patch(url, idempotency_key=None, **kwargs)    # PATCH
agent.put(url, idempotency_key=None, **kwargs)      # PUT
agent.delete(url, idempotency_key=None, **kwargs)   # DELETE
```

All `requests` kwargs work: `params`, `json`, `data`, `headers`,
`timeout`, `stream`, `files`, etc. Anything you pass survives through
to the underlying `requests` call.

Returns a real `requests.Response` — the SDK is a thin auth shim, not
a client framework.

### Retries never duplicate a consequential action

The SDK retries in two places: after a platform `401` (refresh the token, replay)
and after a transport failure. Neither will replay a request whose replay could
duplicate a side effect.

| Method | Replayed on 401 / ambiguous failure? |
|---|---|
| `GET` `HEAD` `OPTIONS` `PUT` `DELETE` | Yes — replaying cannot duplicate an effect |
| `POST` `PATCH` **with** `idempotency_key` | Yes — the server collapses the duplicate |
| `POST` `PATCH` **without** a key | **No** |

Without a key, a `401` is returned to you unreplayed, and an ambiguous transport
failure raises `MudraIDExecutionUnknownError`. You are the only party that knows
whether the action is safe to repeat.

```python
# A payment that must not happen twice.
r = agent.post(f"{API}/payments", json={"amount": 5000},
               idempotency_key=f"pay-{order_id}")

# Without the key, a platform that mutates and THEN answers 401 hands you the
# 401 instead of silently charging the customer a second time.
r = agent.post(f"{API}/payments", json={"amount": 5000})
if r.status_code == 401:
    ...  # reconcile, then re-issue with a key
```

Use a key that is stable for the *action*, not for the attempt — a fresh UUID per
call deduplicates nothing. `MachineAgent` applies the identical rule with the
identical signature.

---

## Error handling

Every SDK-raised exception inherits from `MudraIDError`. Catch the
base class to handle anything SDK-originated:

```python
from mudraid import Agent, MudraIDError

agent = Agent()
try:
    response = agent.get("https://api.skyscanner.com/flights")
except MudraIDError as exc:
    log.warning("SDK rejected the call: %s", exc)
```

Or catch specific subclasses for precise behaviour:

| Exception | Raised when |
|---|---|
| `MudraIDConfigError` | `MUDRAID_API_KEY_ID` / `MUDRAID_SECRET` missing or empty |
| `MudraIDAuthError` | MudraID rejected the credentials (HTTP 401 from `/auth/token`) |
| `MudraIDRevokedError` | Authorisation denied (HTTP 403: agent inactive, no platform access, scope rejected) |
| `MudraIDNetworkError` | Could not reach MudraID, response was malformed, or an unmapped non-2xx (the message names the path and `base_url`) |
| `MudraIDRateLimitedError` | MudraID rate-limited the call (HTTP 429). Subclasses `MudraIDNetworkError`; carries `retry_after_seconds` |
| `MudraIDPlatformNotRegisteredError` | Caller URL's host isn't a platform this agent is registered with |

### Rate limiting

Control-plane calls pass through **layered** rate limiting. A 429 can come from
any of these, and they are not the same limit with the same remedy:

| Layer | Keyed by | What it means |
|---|---|---|
| Per-key budget | your `api_key_id` | Token minting, credential verification and the platform bootstrap draw on **one shared counter for that key** — spending it on any of the three spends it for all. Sized so a brute-force attempt against one key burns that key's budget. |
| Account fair use | your **account** | The plan's ceiling, or an abuse block. Belongs to the whole account, so throttling one agent may not clear it. |
| Gateway limit | caller **source** | The gateway meters the whole control-plane surface by where the request came from — so a busy neighbour behind the same egress address can spend it, and your key may be nowhere near its own budget. |

All three raise `MudraIDRateLimitedError`.

**How the SDK tells them apart.** identity-service labels its own refusals with
a machine-readable `error_code`, and the gateway stamps `RateLimit-*` headers on
what it meters. The body's label wins whenever it is present — the gateway adds
those headers to responses it merely *forwards*, so reading them first would
blame the gateway for every application-level refusal in the system.

**The SDK names a specific layer only when the response says which one refused.**
Otherwise the message says the layer is unknown and lists the candidates. That is
deliberate: a confident wrong attribution would send you to throttle one agent
over a limit that was never that agent's, which is worse than saying "slow down,
cause unclear". Slowing down is the correct first move whichever layer answered.

The SDK does **not** sleep and retry for you either: a wait of up to a minute
inside a library call is indistinguishable from a hang, and the bootstrap this
most often guards runs once at start-up. You get the server's own delay and
decide:

```python
from mudraid import Agent, MudraIDRateLimitedError
import time

try:
    response = agent.get("https://api.example.com/things")
except MudraIDRateLimitedError as exc:
    time.sleep(exc.retry_after_seconds or 60)
```

`retry_after_seconds` is `None` when the server sent no `Retry-After` header —
an absence, never a guessed number, so you can tell "wait this long" from
"wait, length unknown".

**A 429 is not a credential failure.** The credentials were never examined; the
call simply arrived too fast.

---

**Platform-side 4xx / 5xx responses are NOT raised** — they come back
as ordinary `Response` objects so your code can decide what to do.
The single exception is 401, and only when replaying is
consequence-safe: the SDK refreshes the token and retries once for
idempotent methods, or for any request carrying an `idempotency_key`.
An unkeyed POST or PATCH is surfaced to you unreplayed.

---

## Configuration reference

| Setting | Env var | Constructor kwarg | Default |
|---|---|---|---|
| Public API key id | `MUDRAID_API_KEY_ID` | `api_key_id=` | (required) |
| Secret | `MUDRAID_SECRET` | `secret=` | (required) |
| MudraID base URL | `MUDRAID_BASE_URL` | `base_url=` | `https://api.mudraid.ai` |

Precedence: **kwarg > OS env > `.env` file**.

Anything else (timeouts, cache TTLs) is internal and stable in v1.

### `MUDRAID_BASE_URL` must be `https://`

The token and bootstrap calls send `{"api_key_id", "secret"}` as a JSON **body** —
your agent's long-lived credential, in the clear, on every mint. Over `http://`
that is readable by every hop in between, and nothing later can recover from it:
the secret is spent the moment it is sent.

So a cleartext URL to a remote host raises `MudraIDConfigError` at construction,
before anything is transmitted. `http://` is permitted **only** for a loopback
host, which is the local-development case:

```python
Agent(base_url="http://localhost:8001")   # fine — never leaves the machine
Agent(base_url="http://api.mudraid.ai")   # MudraIDConfigError
```

### Control-plane calls do not follow redirects

`requests` follows redirects by default and **replays the body** on 307/308. It
strips a cross-host `Authorization` header; it has no equivalent for a body,
because in general it cannot know one is sensitive. This one is.

So the SDK sets `allow_redirects=False` on every call that carries a credential —
the two control-plane paths and the V2 token endpoint — and surfaces a 3xx as
`MudraIDNetworkError`. Neither path redirects on a MudraID deployment; in
practice a 3xx here means `MUDRAID_BASE_URL` resolves to a proxy, a login portal
or a vanity domain rather than the API. The `Location` value is deliberately not
echoed into the error message.

Calls to *your platforms* are unaffected — those go through a separate session
and follow redirects as `requests` normally would.

### `PyJWTSigner` signs asymmetrically or not at all

`private_key_jwt` exists so no shared secret crosses the wire. PyJWT will
nonetheless encode `alg=none` (unsigned) or `HS256` (symmetric — your "private
key" becomes a secret the server must also hold), either of which dissolves the
profile without changing anything visible at the call site. `PyJWTSigner`
therefore accepts only `RS*`, `PS*`, `ES*` and `EdDSA`, and raises `ValueError`
otherwise. Supply your own `AssertionSigner` if you genuinely need something
else — there the choice is yours and it is visible.

---

## Diagnostics

Turn on the SDK's structured logs to watch the trust loop in action:

```python
import logging
logging.getLogger("mudraid").setLevel(logging.DEBUG)
```

Module loggers:

- `mudraid.agent` — request lifecycle and 401 retries
- `mudraid.token_manager` — cache hits, mints, refreshes
- `mudraid.platform_resolver` — bootstrap, host→platform_id resolution
- `mudraid.http` — outbound MudraID requests
- `mudraid.env` — `.env` loading

**No log statement in the SDK ever emits a secret or a JWT** — locked
by anti-leak unit tests that sweep the entire DEBUG output for
sentinel credential strings.

---

## Try it locally

A runnable sample agent ships in [`examples/sample-agent/`](../../examples/sample-agent/).
It calls the sample platform (running the matching FastAPI middleware)
and walks through the trust loop step by step.

```bash
# From the repo root:
docker compose up -d                                       # backend
docker compose --profile samples up -d sample-platform     # platform

cd examples/sample-agent
cp .env.example .env                                       # add real creds
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e ../../sdks/mudraid-sdk-python

python main.py
```

Expected output is documented in [`examples/sample-agent/README.md`](../../examples/sample-agent/README.md)
— a four-section walk through the public route, scope-gated read,
scope-gated write (403 by design), and unregistered host
(`MudraIDPlatformNotRegisteredError` by design).

---

## How the SDK fits into the wider system

```
your agent code              your platform's server
─────────────────            ────────────────────────
agent.get(url) ────┐         ┌──── @app.get("/items")
                   ▼         ▲
              ┌─────────┐    │
              │  SDK    │    │   ┌────────────────┐
              │ bootstrap│   │   │ MudraIDMiddleware │
              │ token   │    │   │  in your app      │
              │ refresh │    │   └────────────────┘
              └─────────┘    │           ▲
                   │         │           │
                   ▼         │           │
              ┌─────────────────────────────┐
              │     MudraID backend          │
              │  identity / platforms / KMS  │
              └─────────────────────────────┘
```

The matching server-side package is
[`mudraid-middleware`](../mudraid-middleware-python/) for FastAPI /
Starlette platforms.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
