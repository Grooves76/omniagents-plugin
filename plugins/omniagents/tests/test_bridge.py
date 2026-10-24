"""Offline contract tests. No live credentials, browser, app, or server is used."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import socket
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

SOURCE = Path(__file__).resolve().parents[1] / "bin/omniagents_bridge.py"
if SOURCE.exists():
    spec = importlib.util.spec_from_file_location("bridge_under_test", SOURCE)
    bridge = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = bridge
    spec.loader.exec_module(bridge)
else:
    bridge = None

ORIGIN = "https://0123456789abcdef0123456789abcdef.omniagents.link"
ENDPOINT = ORIGIN + "/mcp"


class MemorySecrets:
    def __init__(self):
        self.value = None
        self.saves = 0

    def load(self):
        return json.loads(json.dumps(self.value)) if self.value else None

    def save(self, value):
        self.value = json.loads(json.dumps(value))
        self.saves += 1


class OAuthProvider:
    """Network boundary with a real loopback browser redirect and PKCE validation."""
    def __init__(self, reject_registration=False, bad_state_first=False):
        self.requests = []
        self.browser_urls = []
        self.registration = None
        self.authorize = None
        self.reject_registration = reject_registration
        self.bad_state_first = bad_state_first
        self.thread = None
        self.callback_errors = []
        self.refreshes = 0

    def response(self, status, body):
        return bridge.Response(status, {"content-type": "application/json"}, json.dumps(body).encode())

    def request(self, method, url, headers=None, body=None):
        self.requests.append((method, url))
        if url.endswith("/.well-known/oauth-protected-resource"):
            return self.response(200, {"resource": ENDPOINT, "authorization_servers": [ORIGIN]})
        if url.endswith("/.well-known/oauth-authorization-server"):
            return self.response(200, {"issuer": ORIGIN, "authorization_endpoint": ORIGIN + "/authorize",
                "token_endpoint": ORIGIN + "/token", "registration_endpoint": ORIGIN + "/register",
                "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
                "authorization_response_iss_parameter_supported": True, "omniagents_native_clients_supported": ["chatgpt"]})
        if url.endswith("/register"):
            if self.reject_registration:
                return self.response(400, {"error": "invalid_client_metadata"})
            self.registration = json.loads(body)
            assert self.registration["omniagents_client"] == "chatgpt"
            assert self.registration["software_id"] == "it.omniagents.chatgpt.local"
            assert self.registration["application_type"] == "native"
            return self.response(201, {"client_id": "dedicated-native-client", "redirect_uris": self.registration["redirect_uris"]})
        if url.endswith("/token"):
            fields = parse_qs(body.decode(), strict_parsing=True)
            assert fields["resource"] == [ENDPOINT]
            assert fields["client_id"] == ["dedicated-native-client"]
            if fields["grant_type"] == ["authorization_code"]:
                digest = base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"][0].encode()).digest()).decode().rstrip("=")
                assert digest == self.authorize["code_challenge"][0]
                assert fields["redirect_uri"] == self.registration["redirect_uris"]
                assert fields["code"] == ["one-time-code"]
            else:
                assert fields["refresh_token"] == ["refresh-1"]
                self.refreshes += 1
            return self.response(200, {"access_token": "access-" + str(1 + self.refreshes),
                "refresh_token": "refresh-" + str(1 + self.refreshes), "token_type": "Bearer", "expires_in": 3600,
                "scope": "archive.read archive.operate"})
        raise AssertionError("Unexpected HTTP request")

    def browser(self, url):
        self.browser_urls.append(url)
        self.authorize = parse_qs(urlsplit(url).query)
        assert self.authorize["resource"] == [ENDPOINT]
        assert self.authorize["scope"] == ["archive.read archive.operate"]
        redirect = self.authorize["redirect_uri"][0]
        assert urlsplit(redirect).hostname == "127.0.0.1"
        assert urlsplit(redirect).path == "/omniagents/chatgpt/callback"

        def callback():
            if self.bad_state_first:
                try:
                    urlopen(redirect + "?" + urlencode({"state": "wrong", "code": "bad", "iss": ORIGIN}), timeout=4).read()
                except Exception:
                    pass
            try:
                urlopen(redirect + "?" + urlencode({"state": self.authorize["state"][0], "code": "one-time-code", "iss": ORIGIN}), timeout=4).read()
            except Exception as error:
                self.callback_errors.append(type(error).__name__)
        self.thread = threading.Thread(target=callback)
        self.thread.start()
        return True


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(bridge, "The portable bridge has not been implemented")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_discovery_uses_selected_installation_not_legacy_claude(self):
        for variant, origin in (("OmniAgents Personal", ORIGIN), ("OmniAgents Business", "https://fedcba9876543210fedcba9876543210.omniagents.link")):
            p = self.root / variant / "archive-home/config/chatgpt.json"
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps({"mcp_public_origin": origin, "mcp_http_enabled": True}))
        result = bridge.discover_installation(self.root)
        self.assertEqual(result.endpoint, ENDPOINT)
        self.assertIn("OmniAgents Personal", str(result.home))
        self.assertNotEqual(result.account, bridge.discover_installation(self.root, "business").account)

    def test_discovery_rejects_shared_alias_or_non_https(self):
        for value in ("http://0123456789abcdef0123456789abcdef.omniagents.link", "https://info.omniagents.link", ORIGIN + "@evil.example", ORIGIN + "/x", ORIGIN + "?token=x"):
            with self.subTest(value=value), self.assertRaises(bridge.BridgeError):
                bridge.validate_endpoint(value + "/mcp")

    def test_oauth_binds_dedicated_client_after_valid_state_and_pkce(self):
        provider, store = OAuthProvider(bad_state_first=True), MemorySecrets()
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser, auth_timeout=5)
        self.assertEqual(oauth.access_token(), "access-1")
        provider.thread.join()
        self.assertFalse(provider.callback_errors)
        self.assertEqual(store.saves, 1)
        self.assertEqual(store.value["resource"], ENDPOINT)
        self.assertEqual(store.value["kind"], "chatgpt")
        self.assertEqual(oauth.access_token(), "access-1")
        self.assertEqual(len(provider.browser_urls), 1)

    def test_rejected_native_registration_fails_before_browser_or_secret_save(self):
        provider, store = OAuthProvider(reject_registration=True), MemorySecrets()
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser, auth_timeout=1)
        with self.assertRaisesRegex(bridge.BridgeError, "NATIVE_OAUTH_NOT_SUPPORTED"):
            oauth.access_token()
        self.assertEqual(store.saves, 0)
        self.assertEqual(provider.browser_urls, [])

    def test_current_unsupported_server_performs_no_registration_or_authorization(self):
        class CurrentProvider(OAuthProvider):
            def request(self, method, url, headers=None, body=None):
                response = super().request(method, url, headers, body)
                if url.endswith("/.well-known/oauth-authorization-server"):
                    value = json.loads(response.body)
                    value.pop("omniagents_native_clients_supported")
                    return self.response(200, value)
                return response
        provider, store = CurrentProvider(), MemorySecrets()
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser)
        with self.assertRaisesRegex(bridge.BridgeError, "NATIVE_OAUTH_NOT_SUPPORTED"):
            oauth.access_token()
        self.assertEqual([method for method, _ in provider.requests], ["GET", "GET"])
        self.assertEqual(store.saves, 0)
        self.assertEqual(provider.browser_urls, [])

    def test_saved_grant_cannot_cross_installation_or_client_identity(self):
        for changed in ({"resource": "https://fedcba9876543210fedcba9876543210.omniagents.link/mcp"}, {"kind": "claude"}, {"token_endpoint": "https://evil.example/token"}):
            provider, store = OAuthProvider(), MemorySecrets()
            store.value = {"resource": ENDPOINT, "issuer": ORIGIN, "token_endpoint": ORIGIN + "/token", "kind": "chatgpt", "client_id": "dedicated-native-client", "access_token": "private", "refresh_token": "private", "expires_at": time.time()+3600, "scope": "archive.read archive.operate", **changed}
            oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser)
            with self.subTest(changed=changed), self.assertRaises(bridge.BridgeError):
                oauth.access_token()
            self.assertEqual(provider.requests, [])

    def test_expired_grant_refreshes_without_new_consent(self):
        provider, store = OAuthProvider(), MemorySecrets()
        store.value = {"resource": ENDPOINT, "issuer": ORIGIN, "token_endpoint": ORIGIN + "/token", "kind": "chatgpt", "client_id": "dedicated-native-client", "access_token": "access-1", "refresh_token": "refresh-1", "expires_at": time.time()-1, "scope": "archive.read archive.operate"}
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser)
        self.assertEqual(oauth.access_token(), "access-2")
        self.assertEqual(provider.refreshes, 1)
        self.assertEqual(provider.browser_urls, [])

    def test_refresh_cannot_promote_an_existing_read_only_grant(self):
        provider, store = OAuthProvider(), MemorySecrets()
        store.value = {"resource": ENDPOINT, "issuer": ORIGIN, "token_endpoint": ORIGIN + "/token", "kind": "chatgpt", "client_id": "dedicated-native-client", "access_token": "access-1", "refresh_token": "refresh-1", "expires_at": time.time()-1, "scope": "archive.read"}
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser)
        with self.assertRaisesRegex(bridge.BridgeError, "SCOPE_ESCALATION"):
            oauth.access_token()
        self.assertEqual(store.saves, 0)

    def test_invalid_grant_requires_fresh_consent_without_deleting_old_grants(self):
        class RevokedProvider(OAuthProvider):
            def request(self, method, url, headers=None, body=None):
                if url.endswith("/token") and parse_qs(body.decode()).get("grant_type") == ["refresh_token"]:
                    return self.response(400, {"error": "invalid_grant"})
                return super().request(method, url, headers, body)
        provider, store = RevokedProvider(), MemorySecrets()
        store.value = {"resource": ENDPOINT, "issuer": ORIGIN, "token_endpoint": ORIGIN + "/token", "kind": "chatgpt", "client_id": "dedicated-native-client", "access_token": "old-access", "refresh_token": "old-refresh", "expires_at": time.time()-1, "scope": "archive.read archive.operate"}
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser, auth_timeout=5)
        self.assertEqual(oauth.access_token(), "access-1")
        provider.thread.join()
        self.assertEqual(len(provider.browser_urls), 1)
        self.assertEqual(store.saves, 1)
        self.assertFalse(any(url.endswith("/revoke") for _, url in provider.requests))

    def test_non_grant_http_errors_do_not_replace_saved_credentials(self):
        class FailedProvider(OAuthProvider):
            def request(self, method, url, headers=None, body=None):
                if url.endswith("/token"):
                    return self.response(400, {"error": "invalid_client"})
                return super().request(method, url, headers, body)
        provider, store = FailedProvider(), MemorySecrets()
        store.value = {"resource": ENDPOINT, "issuer": ORIGIN, "token_endpoint": ORIGIN + "/token", "kind": "chatgpt", "client_id": "dedicated-native-client", "access_token": "old-access", "refresh_token": "old-refresh", "expires_at": time.time()-1, "scope": "archive.read archive.operate"}
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=provider.browser)
        with self.assertRaises(bridge.BridgeError):
            oauth.access_token()
        self.assertEqual(provider.browser_urls, [])
        self.assertEqual(store.saves, 0)
        self.assertEqual(store.value["refresh_token"], "old-refresh")

    def test_incomplete_local_connection_cannot_stall_oauth_callback(self):
        provider, store = OAuthProvider(), MemorySecrets()
        sockets = []
        def browser(url):
            redirect = urlsplit(parse_qs(urlsplit(url).query)["redirect_uri"][0])
            client = socket.create_connection(("127.0.0.1", redirect.port))
            sockets.append(client)
            client.sendall(b"GET /")
            timer = threading.Timer(3, client.close)
            timer.start()
            self.addCleanup(timer.cancel)
            return provider.browser(url)
        oauth = bridge.OAuthClient(ENDPOINT, store, self.root, http=provider, open_browser=browser, auth_timeout=2)
        started = time.monotonic()
        try:
            self.assertEqual(oauth.access_token(), "access-1")
            self.assertLess(time.monotonic() - started, 1.8)
        finally:
            for client in sockets: client.close()
            if provider.thread: provider.thread.join()

    def test_http_redirect_never_forwards_bearer_credentials(self):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                calls.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/unexpected-target")
                self.end_headers()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = bridge.HTTPClient(timeout=2).request("GET", "http://127.0.0.1:" + str(server.server_port) + "/original", {"Authorization": "Bearer test-only"})
            self.assertEqual(result.status, 302)
            self.assertEqual(calls, ["/original"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_http_identifies_native_client_to_public_transport(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                self.send_response(200 if self.headers.get("User-Agent", "").startswith("OmniAgents") else 403)
                self.end_headers()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = bridge.HTTPClient(timeout=2).request("GET", "http://127.0.0.1:" + str(server.server_port) + "/metadata")
            self.assertEqual(result.status, 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_wrong_callback_issuer_is_never_exchanged(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.parse_callback("/omniagents/chatgpt/callback?code=x&state=s&iss=https%3A%2F%2Fevil.example", "s", ORIGIN, True)

    def test_streaming_response_preserves_active_model_error(self):
        class Token:
            def access_token(self, force_used=None): return "private-token"
        class API:
            def request(self, method, url, headers=None, body=None):
                self.headers = headers
                return bridge.Response(200, {"content-type": "text/event-stream", "mcp-session-id": "session-1"}, b'event: message\ndata: {"jsonrpc":"2.0","id":2,"error":{"code":-32002,"message":"AI_NOT_ACTIVE"}}\n\n')
        api = API()
        local = bridge.Bridge(ENDPOINT, Token(), http=api)
        output = local.forward({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "omniagents_session", "arguments": {}}})
        self.assertEqual(output, [{"jsonrpc":"2.0","id":2,"error":{"code":-32002,"message":"AI_NOT_ACTIVE"}}])
        self.assertEqual(local.session_id, "session-1")

    def test_explicit_connect_verifies_catalog_without_calling_tools_or_activating_ai(self):
        class Token:
            def access_token(self, force_used=None): return "test-token"
        class API:
            def __init__(self): self.methods = []
            def request(self, method, url, headers=None, body=None):
                request = json.loads(body)
                self.methods.append(request["method"])
                if request["method"] == "notifications/initialized":
                    return bridge.Response(202, {}, b"")
                result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "omniagents_core", "version": "test"}} if request["method"] == "initialize" else {"tools": [{"name": "omniagents_session"}, {"name": "read_summary"}]}
                return bridge.Response(200, {"content-type": "application/json"}, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode())
        api = API()
        local = bridge.Bridge(ENDPOINT, Token(), http=api)
        self.assertEqual(local.verify_connection(), 2)
        self.assertEqual(api.methods, ["initialize", "notifications/initialized", "tools/list"])

    def test_explicit_connect_does_not_report_connected_for_rejected_catalog(self):
        class Token:
            def access_token(self, force_used=None): return "test-token"
        class API:
            def request(self, method, url, headers=None, body=None):
                return bridge.Response(200, {"content-type": "application/json"}, b'{"jsonrpc":"2.0","id":"connect-init","error":{"code":-32001,"message":"authorization required"}}')
        with self.assertRaisesRegex(bridge.BridgeError, "MCP_INITIALIZE_REJECTED"):
            bridge.Bridge(ENDPOINT, Token(), http=API()).verify_connection()

    def test_stdio_emits_only_json_rpc_and_does_not_authorize_empty_input(self):
        class Token:
            def access_token(self, force_used=None): raise AssertionError("No authorization for empty input")
        local = bridge.Bridge(ENDPOINT, Token())
        out = io.StringIO()
        local.serve(io.StringIO(""), out)
        self.assertEqual(out.getvalue(), "")
        local.serve(io.StringIO("not-json\n"), out)
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
