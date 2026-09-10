# MudraID Python SDK

Authenticate AI agents through a linked OAuth machine client and call its approved resource.

## Configure a linked machine client

Register an OAuth machine client, bind it to the intended agent, register its
public JWK, complete proof of possession, and approve the exact resource/scopes
in the correct organization and environment. Linking alone grants no authority.
The same workflow works in sandbox and production, subject to server eligibility checks.

Install the SDK and signing dependencies:

```bash
pip install mudraid-sdk 'PyJWT>=2.13,<3' 'cryptography>=50'
```

Set these process environment variables, using your environment's actual values:

| Variable | Meaning |
|---|---|
| `MUDRAID_CLIENT_ID` | Linked OAuth client ID |
| `MUDRAID_TOKEN_ENDPOINT` | HTTPS OAuth token endpoint |
| `MUDRAID_ASSERTION_AUDIENCE` | Exact assertion audience accepted by that server |
| `MUDRAID_RESOURCE` | Exact approved resource identifier |
| `MUDRAID_SCOPES` | Space-separated scopes; omitted/empty requests no scopes |
| `MUDRAID_PRIVATE_KEY_PATH` | Private key file corresponding to the registered public key |
| `MUDRAID_KEY_ID` | Registered public key identifier (`kid`) |

```python
from mudraid import Agent

agent = Agent.from_env()  # reads explicit process environment variables
try:
    response = agent.get("https://your-platform.example/tasks", timeout=15)
    response.raise_for_status()
finally:
    agent.close()
```

`Agent.from_env("WEBSITE_API")` uses only `WEBSITE_API_*` values. Missing
configuration fails locally; it never switches to another client's variables.
For custom/KMS signing, pass `signer=my_signer`; no local key file is then read.
For explicit configuration use `Agent(MachineIdentity(...))`. `MachineAgent`
remains available as an alias for the same client implementation.

The token endpoint requires HTTPS; HTTP is accepted only for explicit loopback
hosts in local development. Userinfo, fragments, whitespace and invalid ports
are rejected before signing or network traffic. Assertions are not followed
through redirects. Private keys stay local.

## Client-secret authentication

Set `MUDRAID_AUTH_METHOD=client_secret_basic` and `MUDRAID_CLIENT_SECRET`, along
with the client ID, token endpoint, resource and requested scopes. Use the same
`Agent.from_env()` entry point. This method requires no signing key or assertion
audience. The server's policy/approval requirements still apply.

For explicit configuration, pass `ClientSecretIdentity(client_id=...,
token_endpoint=..., resource=..., client_secret=...)` to `Agent`. A credential
failure never switches methods or selects a different environment automatically.

## Requests, retries and failures

`get`, `head`, `options`, `post`, `put`, `patch` and `delete` return requests
responses. Tokens are cached per identity and refreshed near expiry. Give each
resource/scoped identity its own client. Set request timeouts explicitly.

A consequential POST/PATCH without an idempotency key is not blindly retried
after an ambiguous transport failure or a resource-server 401. Ambiguous
transport failures raise `MudraIDExecutionUnknownError`; an unreplayed 401 is
returned. An idempotent method or server-deduplicated `idempotency_key` permits
one consequence-safe recovery. Passing a key requires the server to actually
deduplicate it; the SDK cannot provide that guarantee by itself.

Catch `MudraIDError` for SDK errors. `MudraIDConfigError` identifies local setup
failures, `MudraIDAuthError` authentication refusals, `MudraIDRevokedError`
authority refusals, `MudraIDRateLimitedError` rate limits (with optional
`retry_after_seconds`), and `MudraIDBillingFrozenError` billing/plan refusals.
`close()` releases connections owned by the client; explicitly supplied token
managers/sessions remain caller-owned.

See [the runnable linked-client example](examples/linked_machine_client.py).
Publication does not itself establish a live platform integration or production
readiness; qualify the configured grant and protected resource end to end.
