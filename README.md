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

# After — legacy direct-permission profile
from mudraid import Agent
agent = Agent()  # auto-loads credentials from .env
response = agent.get("https://api.skyscanner.com/flights")
```

That example uses legacy direct platform permissions. A linked OAuth Machine Client uses the V2 setup below.

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

### Linked OAuth Machine Client (V2)

Use `MachineAgent` when the portal grants authority to an OAuth Machine Client.
`Agent(prefix=...)` always selects legacy key/secret authentication; linking a
client in the portal does not switch that Python object to V2. A refresh of
legacy discovery cannot load a V2 grant. You do not need a legacy direct grant
for this flow.

Install `mudraid-sdk[v2]`. Use the runnable
[linked-client example](examples/linked_machine_client.py), configuring:

| Variable | Value |
|---|---|
| `MUDRAID_CLIENT_ID` | The linked OAuth client ID |
| `MUDRAID_PRIVATE_KEY_PATH` | Local path to the private key corresponding to its registered public key |
| `MUDRAID_KEY_ID` | That registered key's `kid` |
| `MUDRAID_TOKEN_ENDPOINT` | Your environment's `/oauth2/token` URL |
| `MUDRAID_ASSERTION_AUDIENCE` | The assertion audience required by that authorization server |
| `MUDRAID_RESOURCE` | The exact approved resource identifier |
| `MUDRAID_SCOPES` | Explicit space-separated scopes, for example `tasks:read` |
| `MUDRAID_TASKS_URL` | The task API URL served by that approved resource |

With these variables set, the supported SDK entry point is:

```python
from mudraid import MachineAgent

agent = MachineAgent.from_env()
try:
    response = agent.get("https://your-approved-platform.example/tasks", timeout=15)
    response.raise_for_status()
finally:
    agent.close()
```

Use the URL served by your approved resource. You can also run
`python examples/linked_machine_client.py` from the source distribution.
For multiple agents, call `MachineAgent.from_env("WEBSITE_API")` and configure
the corresponding `WEBSITE_API_*` variables. The loader reads only the process
environment: it does not discover a `.env` file or use unprefixed fallbacks.
Missing identity configuration fails locally rather than selecting another
identity or a legacy credential. An omitted or empty `SCOPES` requests no
scopes; it never means all permissions. Set the scopes needed for your call.
For a custom or KMS-backed signer, use
`MachineAgent.from_env("WEBSITE_API", signer=my_signer)`; then local key-file
variables are unnecessary. The built-in key-file path uses RS256; callers
requiring ES256 can supply an explicitly configured `PyJWTSigner` instead.

`from_env` is included in this source version and its release artifacts; an
older installed SDK may not contain it. Verify the published package version
before copying this example. Public repository mirroring and package release
are separate from merging changes into the backend repository.
The private key remains local; the SDK signs an assertion, obtains a
resource-bound token, then calls the platform.

The client must have an effective grant for the requested resource/scopes,
valid agent binding and usable credentials in the correct organization and
environment. Registration or linking alone grants no authority. Test V2 in
sandbox before production; production eligibility remains enforced by the
server. If token exchange refuses the request, inspect that refusal and the
client's grant/binding rather than adding legacy permissions.

---

## What the legacy Agent does

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

### What bootstrap writes

What the audit trail should show after an agent starts up:

- A successful `POST /auth/agents/me/platforms` (the bootstrap read)
  writes **nothing** — no audit event, no server-side state. Only a
  *failed* authentication attempt against it is audited
  (`agent_platforms_auth_failed`).
- `POST /auth/token` emits **one** `agent_token_issued` audit event,
  written in the background after the response is sent. No token is
  stored server-side — the JWT is stateless and platforms verify it
  against the JWKS.
- **Neither** call produces a verification event. Verification entries
  begin when the token is first *presented* to a verify/decide path, or
  when the sandbox "Test authentication" action is used.

So an agent that has bootstrapped and minted a token but not yet called
a platform shows exactly one `agent_token_issued` event and no
verification entries. That is correct, not missing data.

---

## Installation

```bash
pip install mudraid-sdk
```

> **Which version this installs.** The latest on PyPI is **1.1.0**. This
> source tree is **1.3.0**, which is not published yet — pinning `==1.3.0`
> would fail to resolve. Install unpinned to get the current release, or pin
> `==1.1.0` explicitly if you need a fixed version today.

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

## Multi-agent applications

A process that runs several agents can't give them all the same
`MUDRAID_API_KEY_ID` — later assignments would overwrite earlier ones.
`prefix=` gives each agent its own pair of variables. The prefix **replaces
the `MUDRAID` segment** of the default names; the suffixes stay exactly the
same:

| Constructor call | Key id variable | Secret variable |
|---|---|---|
| `Agent()` | `MUDRAID_API_KEY_ID` | `MUDRAID_SECRET` |
| `Agent(prefix="SUPERVISOR")` | `SUPERVISOR_API_KEY_ID` | `SUPERVISOR_SECRET` |
| `Agent(prefix="WEBSITE_API")` | `WEBSITE_API_API_KEY_ID` | `WEBSITE_API_SECRET` |

`.env` for a four-agent system:

```env
SUPERVISOR_API_KEY_ID=muid_kid_...
SUPERVISOR_SECRET=muid_sk_...
RESEARCH_API_KEY_ID=muid_kid_...
RESEARCH_SECRET=muid_sk_...
CODER_API_KEY_ID=muid_kid_...
CODER_SECRET=muid_sk_...
WEBSITE_API_API_KEY_ID=muid_kid_...
WEBSITE_API_SECRET=muid_sk_...

# Shared by every agent unless a per-agent {PREFIX}_BASE_URL overrides it.
MUDRAID_BASE_URL=https://api.staging.mudraid.ai
```

```python
from mudraid import Agent

supervisor_agent = Agent(prefix="SUPERVISOR")
research_agent = Agent(prefix="RESEARCH")
coder_agent = Agent(prefix="CODER")
website_api_agent = Agent(prefix="WEBSITE_API")
```

Rules worth knowing:

- **Credentials never fall back to the unprefixed names.** If
  `SUPERVISOR_SECRET` is missing, construction raises `MudraIDConfigError`
  naming `SUPERVISOR_SECRET` — it will not silently borrow `MUDRAID_SECRET`,
  because handing one agent another agent's identity is the exact bug the
  prefix exists to prevent.
- **The base URL does fall back.** It describes your deployment, not an
  identity: `{PREFIX}_BASE_URL` > `MUDRAID_BASE_URL` > the production
  default.
- **Explicit kwargs still win** over prefixed variables, same as always.
- The prefix must be usable as an env-var name fragment (letters, digits,
  single underscores; starts with a letter). `"supervisor"` and
  `"SUPERVISOR_"` are normalized to `"SUPERVISOR"`; anything else is refused
  with a `MudraIDConfigError` rather than guessed at.

The SDK does **not** load your `.env` at import time, and won't — a library
that mutates `os.environ` as an import side effect would let a stray `.env`
inside a container image fight the real environment your orchestrator
injects, and would make behaviour depend on import order. Construction of
the first `Agent` triggers the (idempotent, `override=False`) load, which is
early enough for every flow above. If you need the environment populated
before any `Agent` exists — e.g. for your own `os.getenv` calls — do it
explicitly at your program's entry point:

```python
from dotenv import load_dotenv

load_dotenv()  # python-dotenv is already an SDK dependency
```

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
| `MudraIDProductionMachineClientRequiredError` | The surface is **production** and a native `api_key_id` + `secret` is not a production credential (HTTP 403 `production_machine_client_required`). Subclasses `MudraIDRevokedError`; carries `recommended_authentication_method` (`private_key_jwt`) and `compatibility_authentication_available`. A retry with the same credential cannot succeed — use `MachineAgent` |
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
| Credential prefix | — | `prefix=` | (none — the `MUDRAID_*` names above) |

Precedence: **kwarg > OS env > `.env` file**.

With `prefix="SUPERVISOR"` the env vars consulted become
`SUPERVISOR_API_KEY_ID`, `SUPERVISOR_SECRET`, and `SUPERVISOR_BASE_URL`
(base URL falling back to `MUDRAID_BASE_URL`; credentials never falling
back) — see **Multi-agent applications** above.

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

### Production surfaces are reached by a machine client, not by an agent secret

A native agent credential (`api_key_id` + `secret`) mints tokens for
**sandbox** and **staging** surfaces. On a surface whose registered environment
is **production**, MudraID decides the mint by the surface's stored
environment — never by anything the request claims — and refuses the native
credential with a typed `403` whose `code` is
`production_machine_client_required`. The SDK raises
`MudraIDProductionMachineClientRequiredError` (a subclass of
`MudraIDRevokedError`, so existing handlers keep working) carrying the server's
`recommended_authentication_method` — `private_key_jwt` — and whether the
compatibility method is available. Nothing about a retry can clear it: the
remedy is a different credential, which is `MachineAgent`.

While the floor is being rolled out the server may run it in **shadow** mode,
recording the decision and still issuing the token; do not write code that
depends on the native mint continuing to succeed on a production surface.

What a production client looks like, and what it never does:

* **`private_key_jwt` is the recommended method.** The private key stays with
  you; MudraID holds only the public JWK and verifies a short-lived,
  single-use assertion signed with **`RS256`** or **`ES256`** (the exact list
  the server advertises). A key is activated by proof of possession — a
  challenge you sign with the private key — and rotated by registering the
  next key, activating it the same way, and retiring the old one; the SDK
  never sees, stores or transmits the private key.
* **`client_secret_basic` is the compatibility method.** It is permitted in
  production only while your organization holds a recorded, unexpired
  compatibility approval, and that approval is re-checked on **every** token
  request — the moment it lapses or is revoked the same secret is refused
  with a uniform `invalid_client`. The secret is disclosed **exactly once**,
  in the response that creates or rotates it, and is never readable again;
  rotation issues a new secret with a bounded overlap for the old one.
* **There is no downgrade.** A client registered with `private_key_jwt`
  cannot be switched to a shared secret; a secret-authenticated client cannot
  present a key. The method chosen at registration is the method the token
  endpoint enforces.

### `PyJWTSigner` signs asymmetrically or not at all

`private_key_jwt` exists so no shared secret crosses the wire. PyJWT will
nonetheless encode `alg=none` (unsigned) or `HS256` (symmetric — your "private
key" becomes a secret the server must also hold), either of which dissolves the
profile without changing anything visible at the call site. `PyJWTSigner`
therefore accepts exactly the two algorithms MudraID verifies — **`RS256`** and
**`ES256`** — and raises `ValueError` for anything else. That includes the
other asymmetric algorithms PyJWT can encode (`RS384`, `RS512`, `PS*`,
`ES384`, `ES512`, `ES256K`, `EdDSA`): they would sign a well-formed assertion
the token endpoint refuses with a uniform `invalid_client` that says nothing,
so the SDK refuses them early and says why. Supply your own `AssertionSigner`
if you genuinely need something else — there the choice is yours and it is
visible.

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
