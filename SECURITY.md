# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Report it privately to
**security@mudraid.ai**, and we will acknowledge within **2 business days**.

Please include, as far as you can establish it:

- what an attacker can do — the effect, not only the flaw;
- the version you tested, and how you installed it;
- a reproduction, or the smallest thing that shows the behaviour.

You will get a substantive reply, not only an acknowledgement: what we
reproduced, what we could not, and what we intend to do. If we disagree that
something is a vulnerability we will say so and explain why, rather than letting
the report go quiet.

We will not pursue legal action over good-faith research that stays within your
own accounts and data, does not degrade the service for others, and does not
access or retain anyone else's information.

## What is in scope

This repository — the library's own code and the wiring it documents.

The service it talks to is a separate system with the same contact address, and
a report about one is welcome under the other; we would rather route it
ourselves than have you guess which it belongs to.

**`mudraid-platform-middleware` is a different package with its own policy.**
It is the server-side enforcement library — deny-closed decisions, policy
bundles, freshness windows. None of that is in this package, and a report about
it belongs there. Both addresses are the same, so a misrouted report is not a
lost one.

## What this library does and does not do

Worth stating plainly, because a report is often about the difference. This is
a **client** SDK: it obtains and presents credentials for an agent's outbound
calls. It makes no authorization decision and enforces nothing.

- It holds credentials you supply and tokens it obtains. It never writes either
  to disk and never logs either; **a credential, secret or bearer token
  appearing in any log line is a vulnerability**, and one we will treat as such
  even when nothing else is exploitable. `tests/unit/test_logging_guards.py`
  asserts this at DEBUG level across the token lifecycle, including the
  credential-failure and network-failure paths.
- It retries a request once after a token expires mid-flight, and **only when
  the retry is consequence-safe** — an idempotent method, or a request you gave
  an `idempotency_key`. **A path that replays a consequential request without
  an idempotency key is a vulnerability**, and is the class of report we most
  want. `tests/unit/test_consequence_safe_retry.py` is where that boundary is
  pinned.
- `MachineAgent` signs an RFC 7523 `private_key_jwt` client assertion. The
  signer refuses `none` and every `HS*` algorithm: an unsigned assertion proves
  nothing, and a symmetric one would make the "private" key a secret the server
  holds too. **A route to a signed assertion under a symmetric or absent
  algorithm is a vulnerability.**
- It presents a token as `Authorization: Bearer` only when the server typed it
  as a bearer token. Other token types are protected by a binding this SDK does
  not implement, and sending one as a bearer would use the credential outside
  the thing that makes it safe.
- It **does not verify any signature on a server response**, and does not claim
  to. Responses are trusted to the extent TLS makes them trustworthy. Do not
  build a trust assumption on a signature that is not there.
- With `Agent` (the legacy profile) a request that names no scopes receives the
  agent's **full** permitted set. That is the documented behaviour of that
  profile, not a defect; `MachineAgent` inverts it, and new integrations should
  prefer it for exactly that reason. See the README's profile comparison.

## Supported versions

Maturity and support for every published version are declared in the MudraID
adapter support matrix, which is the authority here — not this section, and not
a marketing page. It is not shipped inside this distribution; ask
security@mudraid.ai for the entry covering the version you tested.

This package is **1.x**. Report against the latest published version where you
can, and say which version you tested where you cannot.
