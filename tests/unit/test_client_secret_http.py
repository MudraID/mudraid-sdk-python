"""Local HTTP integration, not full-backend proof: credential routing and refresh.

Unlike responses-based contract tests, this exercises requests serialization and
separate token/resource sessions over real loopback sockets. No AWS or live data.
"""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from mudraid import Agent, ClientSecretIdentity, RequestedScopes


def test_client_secret_http_journey_refreshes_without_forwarding_credentials():
    events = []
    issued = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            events.append((self.path, self.headers.get("Authorization"), parse_qs(body)))
            if self.path != "/oauth2/token":
                self.reply(404, {})
                return
            issued.append(f"access-{len(issued) + 1}")
            self.reply(200, {"access_token": issued[-1], "expires_in": 300, "token_type": "Bearer"})

        def do_GET(self):
            authorization = self.headers.get("Authorization")
            events.append((self.path, authorization, None))
            if self.path == "/tasks" and authorization == "Bearer access-2":
                self.reply(200, {"tasks": []})
            elif self.path == "/tasks":
                self.reply(401, {"error": "invalid_token"})
            else:
                self.reply(403, {"error": "insufficient_scope"})

    token_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    resource_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    servers = [token_server, resource_server]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    token_url = f"http://127.0.0.1:{token_server.server_port}/oauth2/token"
    resource = f"http://127.0.0.1:{resource_server.server_port}"
    agent = Agent(
        ClientSecretIdentity(
            client_id="test-client",
            client_secret="test-secret",
            token_endpoint=token_url,
            resource=resource,
            scopes=RequestedScopes.of(["tasks:read"]),
        )
    )
    try:
        assert agent.get(resource + "/tasks").json() == {"tasks": []}
        assert agent.get(resource + "/tasks").status_code == 200
        assert agent.get(resource + "/admin").status_code == 403
        assert len(issued) == 2  # one refresh on 401, none for cached reads or 403
        assert [e[0] for e in events] == [
            "/oauth2/token",
            "/tasks",
            "/oauth2/token",
            "/tasks",
            "/tasks",
            "/admin",
        ]
        basic = "Basic " + base64.b64encode(b"test-client:test-secret").decode()
        for path, authorization, body in events:
            if path == "/oauth2/token":
                assert authorization == basic
                assert body == {
                    "grant_type": ["client_credentials"],
                    "resource": [resource],
                    "scope": ["tasks:read"],
                }
            else:
                assert authorization in {"Bearer access-1", "Bearer access-2"}
    finally:
        agent.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
