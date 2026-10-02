"""Smoke-test trusted local DBX binaries using only disposable synthetic state.

Requires Python 3.10+ and the test-only dependencies in remote-mcp-requirements.txt.
No downloads, database connections, real profiles, or OS keyring entries are used.
"""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class SmokeFailure(RuntimeError):
    """A failed check whose message does not contain child output or credentials."""


def require(condition, message):
    # Unlike assert, these checks also run when Python is invoked with -O.
    if not condition:
        raise SmokeFailure(message)


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def integer(value):
    return encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class SigningFixture:
    issuer = "https://issuer.example.test"
    resource = "https://dbx.example.test/mcp"

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.tokens = []

    def jwks(self):
        public = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig",
                          "kid": "ephemeral-test", "n": integer(public.n),
                          "e": integer(public.e)}]}

    def token(self, **overrides):
        claims = dict(iss=self.issuer, aud=self.resource, sub="owner", scope="dbx:mcp",
                      exp=int(time.time()) + 120, nbf=int(time.time()) - 1)
        claims.update(overrides)
        body = ".".join(encode(json.dumps(value, separators=(",", ":")).encode())
                        for value in [dict(alg="RS256", typ="at+jwt", kid="ephemeral-test"), claims])
        token = body + "." + encode(self.key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256()))
        self.tokens.append(token)
        return token


def isolated_environment(root, inherited=None):
    inherited = os.environ if inherited is None else inherited
    # Windows environment variables are case-insensitive. Never inherit a remote
    # web backend, OAuth source, profile override, or data-encryption key.
    replaced = {"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
                "XDG_DATA_HOME", "RUST_LOG"}
    env = {key: value for key, value in inherited.items()
           if not key.upper().startswith("DBX_") and key.upper() not in replaced}
    for name in ("home", "config", "data"):
        (root / name).mkdir(mode=0o700)
    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
               APPDATA=str(root / "config"), LOCALAPPDATA=str(root / "config"),
               XDG_CONFIG_HOME=str(root / "config"), XDG_DATA_HOME=str(root / "data"),
               DBX_DATA_DIR=str(root / "data"), RUST_LOG="warn")
    key_file = root / "fixture-data-key"
    key_file.write_text(os.urandom(32).hex(), encoding="ascii")
    key_file.chmod(0o600)
    env["DBX_SECRET_KEY_FILE"] = str(key_file)
    return env


def binary_manifest(binary, windows_amd64=False):
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        header = stream.read(64)
        if windows_amd64:
            require(len(header) == 64 and header[:2] == b"MZ", "expected a Windows PE binary")
            stream.seek(struct.unpack_from("<I", header, 0x3C)[0])
            pe = stream.read(6)
            require(len(pe) == 6 and pe[:4] == b"PE\0\0", "invalid PE signature")
            require(struct.unpack_from("<H", pe, 4)[0] == 0x8664, "expected an AMD64 PE binary")
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "bytes": binary.stat().st_size,
            "architecture": "AMD64" if windows_amd64 else "not checked"}


@contextmanager
def managed_process(command, env, cwd, *, stdio=False):
    # Files avoid deadlocks when a failing child writes more than a pipe buffer.
    # They live inside the temporary fixture and are never printed or uploaded.
    with tempfile.TemporaryFile() as stderr, tempfile.TemporaryFile() as stdout:
        process = subprocess.Popen(command, env=env, cwd=cwd,
                                   stdin=subprocess.PIPE if stdio else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE if stdio else stdout,
                                   stderr=stderr, text=stdio, encoding="utf-8" if stdio else None)
        try:
            yield process, stdout, stderr
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()


def require_redacted(stream, tokens):
    stream.seek(0)
    # Read bounded overlapping chunks, including tokens crossing a boundary.
    forbidden = [token.encode() for token in tokens] + [b"BEGIN PRIVATE KEY", b"BEGIN RSA PRIVATE KEY"]
    overlap = max(map(len, forbidden))
    tail = b""
    for chunk in iter(lambda: stream.read(65536), b""):
        data = tail + chunk
        require(not any(value in data for value in forbidden), "child log disclosed synthetic signing material")
        tail = data[-overlap:]


def decode_rpc(data, request_id):
    try:
        if data.lstrip().startswith(b"{"):
            values = [json.loads(data)]
        else:
            values = [json.loads(line[5:].strip()) for line in data.splitlines()
                      if line.startswith(b"data:") and line[5:].strip()]
        result = next(value for value in values if isinstance(value, dict) and value.get("id") == request_id)
    except (ValueError, StopIteration) as error:
        raise SmokeFailure("missing or malformed matching JSON-RPC response") from error
    require("result" in result and "error" not in result, "JSON-RPC request failed")
    return result


class HttpClient:
    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, method="POST", body=None, auth=None, session=None, path="/mcp", extra=None):
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + auth
        if session:
            headers["Mcp-Session-Id"] = session
        headers.update(extra or {})
        data = body if body is None or isinstance(body, bytes) else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, dict(error.headers), error.read()

    def rpc(self, body, auth, session=None):
        status, headers, data = self.request(body=body, auth=auth, session=session)
        require(200 <= status < 300, f"JSON-RPC HTTP status {status}")
        return headers, decode_rpc(data, body["id"])


def initialize(request_id):
    return dict(jsonrpc="2.0", id=request_id, method="initialize",
                params=dict(protocolVersion="2025-06-18", capabilities={},
                            clientInfo=dict(name="synthetic-binary-smoke", version="1")))


def check_http(binary, root, env, signing):
    (root / "jwks.json").write_text(json.dumps(signing.jwks()), encoding="utf-8")
    config = dict(issuer=signing.issuer, resource=signing.resource, jwks_file="jwks.json",
                  allowed_subjects=["owner", "second-owner"], required_scope="dbx:mcp")
    (root / "oauth.json").write_text(json.dumps(config), encoding="utf-8")
    env = dict(env, DBX_MCP_OAUTH_CONFIG_FILE=str(root / "oauth.json"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    client = HttpClient(port)
    report = {}
    with managed_process([str(binary), "--http", "--http-port", str(port)], env, root) as (process, stdout, stderr):
        deadline = time.monotonic() + 30
        while True:
            require(process.poll() is None, "synthetic HTTP server exited before health check")
            try:
                if client.request("GET", path="/healthz")[0] == 200:
                    break
            except (urllib.error.URLError, TimeoutError):
                pass
            require(time.monotonic() < deadline, "synthetic HTTP server start timed out")
            time.sleep(0.1)
        status, _, data = client.request("GET", path="/.well-known/oauth-protected-resource/mcp")
        require(status == 200 and json.loads(data)["resource"] == signing.resource, "resource metadata mismatch")
        report["resource_metadata"] = True
        cases = [("missing", None, 401), ("malformed", "synthetic-invalid", 401),
                 ("expired", signing.token(exp=int(time.time()) - 1), 401),
                 ("audience", signing.token(aud="https://other.example.test/mcp"), 401),
                 ("issuer", signing.token(iss="https://other.example.test"), 401),
                 ("subject", signing.token(sub="uninvited"), 403),
                 ("scope", signing.token(scope="openid"), 403)]
        for name, token, expected in cases:
            status = client.request(body={}, auth=token)[0]
            require(status == expected, f"{name}: expected HTTP {expected}, got {status}")
            report["reject_" + name] = True
        auth = signing.token()
        headers, _ = client.rpc(initialize(1), auth)
        session = next((value for key, value in headers.items() if key.lower() == "mcp-session-id"), None)
        require(bool(session), "initialize did not return a session")
        require(client.request(body=dict(jsonrpc="2.0", method="notifications/initialized"),
                               auth=auth, session=session)[0] == 202, "initialized notification failed")
        _, listed = client.rpc(dict(jsonrpc="2.0", id=2, method="tools/list", params={}), auth, session)
        tools = {tool["name"] for tool in listed["result"]["tools"]}
        require("dbx_list_connections" in tools, "missing saved-connection listing tool")
        _, called = client.rpc(dict(jsonrpc="2.0", id=3, method="tools/call",
                                    params=dict(name="dbx_list_connections", arguments={})), auth, session)
        require(not called["result"].get("isError", False), "empty-profile tool call failed")
        report.update(authenticated_initialize_list_call=True, tool_count=len(tools))
        require(client.request(body={}, auth=signing.token(sub="second-owner"), session=session)[0] == 403,
                "session accepted a different allowed owner")
        require(client.request(body={}, auth=auth, session=session,
                               extra={"Origin": "https://evil.example.test"})[0] == 403, "foreign Origin accepted")
        require(client.request(body=b"x" * (1024 * 1024 + 1), auth=auth)[0] == 413, "oversized body accepted")
        report["session_origin_body_boundaries"] = True
        require(client.request("DELETE", auth=auth, session=session)[0] == 202, "session deletion failed")
        require(client.request(body={}, auth=auth, session=session)[0] == 404, "deleted session remains usable")
        report["delete_invalidates_session"] = True
        if os.name == "nt":
            process.terminate()
        else:
            process.send_signal(signal.SIGINT)
        process.wait(timeout=15)
        require(os.name == "nt" or process.returncode == 0, "unclean HTTP shutdown")
        for stream in (stdout, stderr):
            require_redacted(stream, signing.tokens + ["synthetic-invalid"])
        report["http_shutdown"] = "terminated isolated process" if os.name == "nt" else "graceful SIGINT"
    return report


def check_stdio(binary, root, env):
    with managed_process([str(binary)], env, root, stdio=True) as (process, _, stderr):
        replies = queue.Queue()

        def read_replies():
            for line in process.stdout:
                replies.put(line)
            replies.put(None)

        reader = threading.Thread(target=read_replies, daemon=True)
        reader.start()

        def exchange(value):
            process.stdin.write(json.dumps(value) + "\n")
            process.stdin.flush()
            if "id" not in value:
                return
            deadline = time.monotonic() + 15
            while True:
                try:
                    line = replies.get(timeout=max(0.001, deadline - time.monotonic()))
                except queue.Empty as error:
                    raise SmokeFailure("stdio reply timed out") from error
                require(line is not None, "stdio closed before reply")
                try:
                    response = json.loads(line)
                except ValueError as error:
                    raise SmokeFailure("invalid JSON on protocol stdout") from error
                require(isinstance(response, dict), "invalid JSON-RPC object")
                if "id" in response:
                    return decode_rpc(line.encode(), value["id"])
                require(time.monotonic() < deadline, "stdio reply timed out")

        exchange(initialize(10))
        exchange(dict(jsonrpc="2.0", method="notifications/initialized"))
        listed = exchange(dict(jsonrpc="2.0", id=11, method="tools/list", params={}))
        require("dbx_list_connections" in {tool["name"] for tool in listed["result"]["tools"]},
                "stdio missing saved-connection listing tool")
        process.stdin.close()
        process.wait(timeout=15)
        reader.join(timeout=5)
        require(not reader.is_alive() and process.returncode == 0, "unclean stdio shutdown")
        require_redacted(stderr, [])
    return {"stdio_compatible": True}


def run(binary, cli, windows_amd64=False):
    report = {"binary_manifest": {"mcp": binary_manifest(binary, windows_amd64),
                                   "cli": binary_manifest(cli, windows_amd64)}}
    with tempfile.TemporaryDirectory(prefix="dbx-synthetic-smoke-") as temporary:
        root = Path(temporary)
        env = isolated_environment(root)
        report.update(check_http(binary, root, env, SigningFixture()))
        output = subprocess.run([str(cli), "connections", "list", "--json"], env=env, cwd=root,
                                capture_output=True, timeout=15)
        require(output.returncode == 0, "CLI listing failed")
        require(json.loads(output.stdout) == {"connections": []}, "CLI profile is not empty")
        report["cli_empty_profile"] = True
        report.update(check_stdio(binary, root, env))
    report.update(platform=sys.platform, fixture_key="ephemeral explicit key file; OS keyring unused")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mcp_binary", type=Path)
    parser.add_argument("cli_binary", type=Path)
    parser.add_argument("--require-windows-amd64", action="store_true")
    args = parser.parse_args()
    try:
        report = run(args.mcp_binary.resolve(strict=True), args.cli_binary.resolve(strict=True),
                     args.require_windows_amd64)
    except Exception as error:
        # Child output, tokens, profile paths, and signing data are never included.
        reason = str(error) if isinstance(error, SmokeFailure) else type(error).__name__
        print(json.dumps({"status": "failed", "reason": reason}), file=sys.stderr)
        return 1
    print(json.dumps(dict(status="passed", **report), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
