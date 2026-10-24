#!/usr/bin/env python3
"""OmniAgents local stdio → authenticated HTTP MCP bridge (macOS preview).

No Archive imports, local owner-session reuse, embedded endpoints, or model
activation. All tools pass through the installation's canonical OAuth boundary.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import ctypes
from ctypes import c_char_p, c_int32, c_uint32, c_void_p, POINTER, byref
from dataclasses import dataclass
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser

SCOPES = "archive.read archive.operate"
CALLBACK_PATH = "/omniagents/chatgpt/callback"
MAX_RESPONSE = 16 * 1024 * 1024


class BridgeError(Exception):
    """Only stable, nonsecret codes cross the stdio/log boundary."""


def validate_endpoint(value):
    if not isinstance(value, str) or not re.fullmatch(r"https://[0-9a-f]{32}\.omniagents\.link/mcp", value):
        raise BridgeError("INSTALLATION_ENDPOINT_INVALID")
    return value


@dataclass(frozen=True)
class Installation:
    home: Path
    endpoint: str
    account: str


def discover_installation(app_support=None, variant="personal"):
    if variant not in ("personal", "business"):
        raise BridgeError("INSTALLATION_VARIANT_INVALID")
    root = Path(app_support) if app_support is not None else Path.home() / "Library/Application Support"
    home = root / ("OmniAgents Personal" if variant == "personal" else "OmniAgents Business") / "archive-home"
    path = home / "config/chatgpt.json"
    try:
        # This file supplies only the public endpoint, never existing credentials.
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise BridgeError("INSTALLATION_CONFIG_UNTRUSTED")
        if info.st_size > 1024 * 1024:
            raise BridgeError("INSTALLATION_CONFIG_INVALID")
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        raise BridgeError("INSTALLATION_NOT_CONFIGURED") from None
    origin = config.get("mcp_public_origin")
    endpoint = validate_endpoint(origin.rstrip("/") + "/mcp" if isinstance(origin, str) else None)
    identity = str(home.resolve()) + "\n" + endpoint + "\nchatgpt"
    return Installation(home, endpoint, hashlib.sha256(identity.encode()).hexdigest())


def secure_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BridgeError("PRIVATE_STATE_DIRECTORY_UNSAFE")
    return path


@contextmanager
def exclusive_lock(directory, name):
    import fcntl
    directory = secure_directory(directory)
    fd = os.open(directory / (name + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BridgeError("PRIVATE_LOCK_UNSAFE")
        # Serializes rotating refresh tokens across independent MCP host processes.
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class MacKeychain:
    """Use Security.framework directly; secrets never become command arguments."""
    SERVICE = b"it.omniagents.chatgpt.plugin"

    def __init__(self, account):
        if sys.platform != "darwin":
            raise BridgeError("MACOS_KEYCHAIN_REQUIRED")
        self.account = account.encode("ascii")
        self.security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.cf.CFRelease.argtypes = [c_void_p]
        self.cf.CFRelease.restype = None
        self.security.SecKeychainFindGenericPassword.argtypes = [c_void_p, c_uint32, c_char_p, c_uint32, c_char_p, POINTER(c_uint32), POINTER(c_void_p), POINTER(c_void_p)]
        self.security.SecKeychainFindGenericPassword.restype = c_int32
        self.security.SecKeychainAddGenericPassword.argtypes = [c_void_p, c_uint32, c_char_p, c_uint32, c_char_p, c_uint32, c_void_p, POINTER(c_void_p)]
        self.security.SecKeychainAddGenericPassword.restype = c_int32
        self.security.SecKeychainItemModifyContent.argtypes = [c_void_p, c_void_p, c_uint32, c_void_p]
        self.security.SecKeychainItemModifyContent.restype = c_int32
        self.security.SecKeychainItemFreeContent.argtypes = [c_void_p, c_void_p]
        self.security.SecKeychainItemFreeContent.restype = c_int32

    def _find(self):
        length, data, item = c_uint32(), c_void_p(), c_void_p()
        status = self.security.SecKeychainFindGenericPassword(None, len(self.SERVICE), self.SERVICE, len(self.account), self.account, byref(length), byref(data), byref(item))
        if status == -25300:  # errSecItemNotFound
            return None, None
        if status:
            raise BridgeError("KEYCHAIN_ACCESS_DENIED")
        try:
            if length.value > 65536:
                raise BridgeError("KEYCHAIN_GRANT_INVALID")
            value = ctypes.string_at(data, length.value)
        finally:
            self.security.SecKeychainItemFreeContent(None, data)
        return value, item

    def load(self):
        data, item = self._find()
        if data is None:
            return None
        try:
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise BridgeError("KEYCHAIN_GRANT_INVALID") from None
        finally:
            self.cf.CFRelease(item)

    def save(self, value):
        data = json.dumps(value, separators=(",", ":")).encode()
        if len(data) > 65536:
            raise BridgeError("KEYCHAIN_GRANT_INVALID")
        _, item = self._find()
        if item:
            try:
                status = self.security.SecKeychainItemModifyContent(item, None, len(data), data)
            finally:
                self.cf.CFRelease(item)
        else:
            created = c_void_p()
            status = self.security.SecKeychainAddGenericPassword(None, len(self.SERVICE), self.SERVICE, len(self.account), self.account, len(data), data, byref(created))
            if created:
                self.cf.CFRelease(created)
        if status:
            raise BridgeError("KEYCHAIN_SAVE_FAILED")


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # In particular never forward a Bearer token or refresh token to a redirect.
        return None


class HTTPClient:
    def __init__(self, timeout=180):
        self.opener = build_opener(NoRedirect())
        self.timeout = timeout

    def request(self, method, url, headers=None, body=None):
        request = Request(url, data=body, headers={"User-Agent": "OmniAgentsChatGPTPlugin/0.1", **(headers or {})}, method=method)
        try:
            try:
                response = self.opener.open(request, timeout=self.timeout)
            except HTTPError as error:
                response = error
            with response:
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise BridgeError("HTTP_RESPONSE_TOO_LARGE")
                return Response(response.status, {k.lower(): v for k, v in response.headers.items()}, data)
        except (URLError, OSError, TimeoutError):
            raise BridgeError("OMNIAGENTS_UNREACHABLE") from None


def json_body(response, statuses=(200,)):
    if response.status not in statuses:
        raise BridgeError("OAUTH_HTTP_ERROR_" + str(response.status))
    try:
        result = json.loads(response.body)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError):
        raise BridgeError("OAUTH_RESPONSE_INVALID") from None


def parse_callback(path, expected_state, issuer, require_issuer):
    parsed = urlsplit(path)
    if parsed.path != CALLBACK_PATH or parsed.fragment:
        raise BridgeError("OAUTH_CALLBACK_INVALID")
    params = parse_qs(parsed.query, keep_blank_values=True)
    if any(len(values) != 1 for values in params.values()):
        raise BridgeError("OAUTH_CALLBACK_INVALID")
    state = params.get("state", [""])[0]
    if not secrets.compare_digest(state, expected_state):
        raise BridgeError("OAUTH_STATE_MISMATCH")
    actual_issuer = params.get("iss", [None])[0]
    if (require_issuer and actual_issuer is None) or (actual_issuer is not None and actual_issuer != issuer):
        raise BridgeError("OAUTH_ISSUER_MISMATCH")
    if "error" in params:
        raise BridgeError("OAUTH_CONSENT_DENIED")
    code = params.get("code", [""])[0]
    if not 1 <= len(code) <= 4096:
        raise BridgeError("OAUTH_CODE_INVALID")
    return code


class OAuthClient:
    def __init__(self, endpoint, store, state_dir, *, http=None, open_browser=None, clock=time.time, auth_timeout=180):
        self.endpoint = validate_endpoint(endpoint)
        self.origin = endpoint[:-4]
        self.store, self.state_dir = store, Path(state_dir)
        self.http = http or HTTPClient()
        self.open_browser = open_browser or webbrowser.open
        self.clock, self.auth_timeout = clock, auth_timeout
        self.lock_name = hashlib.sha256(endpoint.encode()).hexdigest()

    def discovery(self):
        resource = json_body(self.http.request("GET", self.origin + "/.well-known/oauth-protected-resource", {"Accept": "application/json"}))
        if resource.get("resource") != self.endpoint or resource.get("authorization_servers") != [self.origin]:
            raise BridgeError("OAUTH_RESOURCE_MISMATCH")
        meta = json_body(self.http.request("GET", self.origin + "/.well-known/oauth-authorization-server", {"Accept": "application/json"}))
        if meta.get("issuer") != self.origin or "S256" not in meta.get("code_challenge_methods_supported", []) or "none" not in meta.get("token_endpoint_auth_methods_supported", []):
            raise BridgeError("OAUTH_METADATA_INVALID")
        for field in ("token_endpoint", "registration_endpoint"):
            value = meta.get(field)
            if not isinstance(value, str) or value != self.origin + ("/token" if field == "token_endpoint" else "/register"):
                raise BridgeError("OAUTH_ENDPOINT_MISMATCH")
        # The existing server may advertise its branded authorization origin.
        authorize = meta.get("authorization_endpoint", "")
        if not isinstance(authorize, str) or not re.fullmatch(r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.omniagents\.link/authorize", authorize):
            raise BridgeError("OAUTH_AUTHORIZATION_ENDPOINT_INVALID")
        return meta

    def _validate_grant(self, value):
        if not isinstance(value, dict) or value.get("resource") != self.endpoint or value.get("issuer") != self.origin or value.get("kind") != "chatgpt" or value.get("token_endpoint") != self.origin + "/token":
            raise BridgeError("STORED_GRANT_IDENTITY_MISMATCH")
        if not all(isinstance(value.get(k), str) and 1 <= len(value[k]) <= 8192 for k in ("access_token", "refresh_token", "client_id", "scope")):
            raise BridgeError("STORED_GRANT_INVALID")
        if not isinstance(value.get("expires_at"), (int, float)) or not set(value["scope"].split()) <= set(SCOPES.split()) or "archive.read" not in value["scope"].split():
            raise BridgeError("STORED_GRANT_INVALID")
        return value

    def _token_result(self, result, client_id, prior=None):
        if str(result.get("token_type", "")).lower() != "bearer":
            raise BridgeError("OAUTH_TOKEN_INVALID")
        scope = result.get("scope", (prior or {}).get("scope", SCOPES))
        if prior and (not isinstance(scope, str) or not set(scope.split()) <= set(prior["scope"].split())):
            raise BridgeError("OAUTH_SCOPE_ESCALATION_REJECTED")
        try:
            duration = float(result["expires_in"])
            if not 0 < duration <= 86400 * 365:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise BridgeError("OAUTH_TOKEN_INVALID") from None
        grant = {"kind": "chatgpt", "resource": self.endpoint, "issuer": self.origin,
            "token_endpoint": self.origin + "/token", "client_id": client_id,
            "access_token": result.get("access_token"), "refresh_token": result.get("refresh_token"),
            "expires_at": self.clock() + duration, "scope": scope}
        return self._validate_grant(grant)

    def _token_request(self, fields):
        response = self.http.request("POST", self.origin + "/token", {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, urlencode(fields).encode())
        if response.status == 400 and fields.get("grant_type") == "refresh_token":
            try:
                failure = json.loads(response.body)
            except (ValueError, UnicodeError):
                failure = None
            if isinstance(failure, dict) and failure.get("error") == "invalid_grant":
                raise BridgeError("OAUTH_REFRESH_GRANT_INVALID")
        return json_body(response)

    def access_token(self, force_used=None):
        with exclusive_lock(self.state_dir, self.lock_name):
            saved = self.store.load()
            if saved:
                saved = self._validate_grant(saved)
                if saved["expires_at"] > self.clock() + 90 and (force_used is None or saved["access_token"] != force_used):
                    return saved["access_token"]
                try:
                    result = self._token_request({"grant_type": "refresh_token", "refresh_token": saved["refresh_token"], "client_id": saved["client_id"], "resource": self.endpoint})
                    grant = self._token_result(result, saved["client_id"], saved)
                except BridgeError as error:
                    if str(error) != "OAUTH_REFRESH_GRANT_INVALID":
                        raise
                    # A revoked/expired refresh grant needs explicit consent again.
                    # Preserve the saved entry until a replacement succeeds; never revoke.
                    grant = self._authorize()
            else:
                grant = self._authorize()
            self.store.save(grant)
            return grant["access_token"]

    def _authorize(self):
        meta = self.discovery()
        if "chatgpt" not in meta.get("omniagents_native_clients_supported", []):
            raise BridgeError("NATIVE_OAUTH_NOT_SUPPORTED_UPDATE_OMNIAGENTS")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        received = {}
        issuer, require_issuer = self.origin, meta.get("authorization_response_iss_parameter_supported") is True

        class CallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass  # Never log callback query parameters.

            def do_GET(self):
                try:
                    code = parse_callback(self.path, state, issuer, require_issuer)
                except BridgeError as error:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Authorization response rejected.")
                    if str(error) == "OAUTH_CONSENT_DENIED":
                        received["error"] = error
                    return
                received["code"] = code
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(b"Authorization received. Return to ChatGPT to finish connecting. The active AI was not changed.")

        class CallbackServer(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(1.0)
                return connection, address

        server = CallbackServer(("127.0.0.1", 0), CallbackHandler)
        server.timeout = 0.5
        redirect = "http://127.0.0.1:" + str(server.server_port) + CALLBACK_PATH
        try:
            registration = {"redirect_uris": [redirect], "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"], "client_name": "OmniAgents ChatGPT desktop plugin", "application_type": "native",
                "software_id": "it.omniagents.chatgpt.local", "omniagents_client": "chatgpt"}
            response = self.http.request("POST", meta["registration_endpoint"], {"Content-Type": "application/json", "Accept": "application/json"}, json.dumps(registration).encode())
            if response.status == 400:
                raise BridgeError("NATIVE_OAUTH_NOT_SUPPORTED_UPDATE_OMNIAGENTS")
            client = json_body(response, (201,))
            client_id = client.get("client_id")
            if not isinstance(client_id, str) or not 1 <= len(client_id) <= 8192 or client.get("redirect_uris") != [redirect]:
                raise BridgeError("OAUTH_REGISTRATION_INVALID")
            authorize_url = meta["authorization_endpoint"] + "?" + urlencode({"client_id": client_id, "redirect_uri": redirect,
                "response_type": "code", "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
                "resource": self.endpoint, "scope": SCOPES})
            if not self.open_browser(authorize_url):
                raise BridgeError("OAUTH_BROWSER_UNAVAILABLE")
            print("OmniAgents: approve the connection in your browser. The active AI stays unchanged.", file=sys.stderr)
            deadline = time.monotonic() + self.auth_timeout
            while not received and time.monotonic() < deadline:
                server.handle_request()
            if "error" in received:
                raise received["error"]
            if not received.get("code"):
                raise BridgeError("OAUTH_CONSENT_TIMEOUT")
            result = self._token_request({"grant_type": "authorization_code", "code": received["code"], "client_id": client_id,
                "redirect_uri": redirect, "code_verifier": verifier, "resource": self.endpoint})
            return self._token_result(result, client_id)
        finally:
            server.server_close()


def response_messages(response):
    if response.status == 202 or not response.body:
        return []
    try:
        if response.headers.get("content-type", "").lower().startswith("text/event-stream"):
            messages, data = [], []
            for line in response.body.decode("utf-8").replace("\r\n", "\n").split("\n") + [""]:
                if not line:
                    if data:
                        messages.append(json.loads("\n".join(data)))
                    data = []
                elif line.startswith("data:"):
                    data.append(line[5:].lstrip(" "))
        else:
            parsed = json.loads(response.body)
            messages = parsed if isinstance(parsed, list) else [parsed]
        if any(not isinstance(value, dict) for value in messages):
            raise ValueError()
        return [value for value in messages if value]
    except (ValueError, UnicodeError):
        raise BridgeError("MCP_RESPONSE_INVALID") from None


class Bridge:
    def __init__(self, endpoint, oauth, *, http=None):
        self.endpoint, self.oauth = validate_endpoint(endpoint), oauth
        self.http = http or HTTPClient()
        self.session_id = self.protocol = None

    def verify_connection(self):
        """Authenticate and read the catalog, without invoking or activating an AI."""
        initialized = self.forward({"jsonrpc": "2.0", "id": "connect-init", "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "OmniAgents ChatGPT desktop plugin", "version": "0.1"}}})
        result = next((item.get("result") for item in initialized if item.get("id") == "connect-init"), None)
        if not isinstance(result, dict) or result.get("serverInfo", {}).get("name") != "omniagents_core" or not self.protocol:
            raise BridgeError("MCP_INITIALIZE_REJECTED")
        self.forward({"jsonrpc": "2.0", "method": "notifications/initialized"})
        names, cursor = set(), None
        for page in range(32):
            ident = "connect-tools-" + str(page + 1)
            messages = self.forward({"jsonrpc": "2.0", "id": ident, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
            catalog = next((item.get("result") for item in messages if item.get("id") == ident), None)
            if not isinstance(catalog, dict) or not isinstance(catalog.get("tools"), list):
                raise BridgeError("MCP_CATALOG_UNAVAILABLE")
            for tool in catalog["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
                    raise BridgeError("MCP_CATALOG_INVALID")
                names.add(tool["name"])
            cursor = catalog.get("nextCursor")
            if not cursor:
                return len(names)
            if not isinstance(cursor, str) or len(cursor) > 2048:
                raise BridgeError("MCP_CATALOG_INVALID")
        raise BridgeError("MCP_CATALOG_PAGINATION_LIMIT")

    def forward(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            raise BridgeError("MCP_REQUEST_INVALID")
        token = self.oauth.access_token()
        for attempt in range(2):
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": "Bearer " + token}
            if self.session_id:
                headers["Mcp-Session-Id"] = self.session_id
            if self.protocol:
                headers["MCP-Protocol-Version"] = self.protocol
            response = self.http.request("POST", self.endpoint, headers, json.dumps(message, separators=(",", ":")).encode())
            if response.status == 401 and attempt == 0:
                token = self.oauth.access_token(force_used=token)
                continue
            if not 200 <= response.status < 300:
                raise BridgeError("MCP_HTTP_ERROR_" + str(response.status))
            sid = response.headers.get("mcp-session-id")
            if sid:
                if not re.fullmatch(r"[\x21-\x7e]{1,256}", sid):
                    raise BridgeError("MCP_SESSION_INVALID")
                self.session_id = sid
            messages = response_messages(response)
            if message["method"] == "initialize":
                for value in messages:
                    version = value.get("result", {}).get("protocolVersion")
                    if isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.-]{1,32}", version):
                        self.protocol = version
            return messages
        raise BridgeError("MCP_AUTHORIZATION_REQUIRED")

    def serve(self, source, destination):
        for line in source:
            message = None
            try:
                if len(line) > MAX_RESPONSE:
                    raise ValueError()
                message = json.loads(line)
                responses = self.forward(message)
            except (ValueError, UnicodeError):
                responses = [{"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "PARSE_ERROR"}}]
            except BridgeError as error:
                ident = message.get("id") if isinstance(message, dict) else None
                responses = [{"jsonrpc": "2.0", "id": ident, "error": {"code": -32001, "message": str(error)}}] if not isinstance(message, dict) or "id" in message else []
            for response in responses:
                destination.write(json.dumps(response, separators=(",", ":")) + "\n")
                destination.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", choices=("personal", "business"), default="personal")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--check", action="store_true", help="Read public configuration/discovery only; no OAuth, Keychain, or browser actions")
    operation.add_argument("--connect", action="store_true", help="Authorize this plugin and verify MCP initialize/tools/list, without any tool call or AI activation")
    options = parser.parse_args()
    try:
        installation = discover_installation(variant=options.instance)
        state_dir = Path.home() / "Library/Application Support/OmniAgents Plugin"
        if options.check:
            meta = OAuthClient(installation.endpoint, None, state_dir).discovery()
            supported = "chatgpt" in meta.get("omniagents_native_clients_supported", [])
            print(json.dumps({"instance": options.instance, "endpoint_configured": True, "oauth_metadata_valid": True, "native_oauth_supported": supported}))
            return 0 if supported else 2
        if sys.platform != "darwin":
            raise BridgeError("MACOS_KEYCHAIN_REQUIRED")
        store = MacKeychain(installation.account)
        oauth = OAuthClient(installation.endpoint, store, state_dir)
        local = Bridge(installation.endpoint, oauth)
        if options.connect:
            count = local.verify_connection()
            print(json.dumps({"status": "connected", "instance": options.instance, "tool_count": count, "active_model_changed": False}))
        else:
            local.serve(sys.stdin, sys.stdout)
        return 0
    except BridgeError as error:
        print("OmniAgents: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        # Exception messages may contain request URLs or headers: never serialize them.
        print("OmniAgents: BRIDGE_UNEXPECTED_ERROR", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
