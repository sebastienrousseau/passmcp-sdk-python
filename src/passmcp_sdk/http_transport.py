# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Streamable HTTP server handler and client transport for MCP 2025-06-18 .. 2026-07-28."""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from typing import Any

from passmcp_sdk.oauth import build_bearer_challenge
from passmcp_sdk.server import McpServer, OriginGuard
from passmcp_sdk.types import (
    HEADER_MISMATCH,
    INVALID_REQUEST,
    META_PROTOCOL_VERSION,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REVISION_2026_07_28,
    JsonRpcError,
)

BearerValidator = Callable[[str], bool]
HttpOpener = Callable[["HttpRequest"], "HttpResponse"]


@dataclass(frozen=True)
class HttpRequest:
    """Pure in-memory Streamable HTTP request representation."""

    method: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    path: str = "/mcp"

    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, val in self.headers.items():
            if key.lower() == target:
                return val
        return None


@dataclass(frozen=True)
class HttpResponse:
    """Pure in-memory Streamable HTTP response representation."""

    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, val in self.headers.items():
            if key.lower() == target:
                return val
        return None

    def json(self) -> dict[str, Any]:
        decoded = json.loads(self.body.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("HTTP response JSON is not an object")
        return decoded


def _json_response(
    status: int, payload: Mapping[str, Any], extra_headers: Mapping[str, str] | None = None
) -> HttpResponse:
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return HttpResponse(
        status=status,
        headers=headers,
        body=json.dumps(payload).encode("utf-8"),
    )


def _rpc_err_body(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _extract_bearer_token(auth_header: str | None) -> str | None:
    if auth_header is None:
        return None
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


def _check_stateless_headers(req: HttpRequest, decoded: Any) -> HttpResponse | None:
    proto_hdr = req.header("MCP-Protocol-Version")
    method_hdr = req.header("MCP-Method")
    if proto_hdr != REVISION_2026_07_28 and method_hdr is None:
        return None
    req_id = decoded.get("id") if isinstance(decoded, Mapping) else None
    body_method = decoded.get("method") if isinstance(decoded, Mapping) else None
    if method_hdr is not None and method_hdr != body_method:
        return _json_response(
            400,
            _rpc_err_body(req_id, HEADER_MISMATCH, "MCP-Method header disagrees with body method"),
        )
    if proto_hdr is not None and isinstance(decoded, Mapping):
        params = decoded.get("params")
        meta = params.get("_meta") if isinstance(params, Mapping) else None
        body_ver = meta.get(META_PROTOCOL_VERSION) if isinstance(meta, Mapping) else None
        if isinstance(body_ver, str) and body_ver != proto_hdr:
            return _json_response(
                400,
                _rpc_err_body(
                    req_id, HEADER_MISMATCH, "MCP-Protocol-Version disagrees with _meta"
                ),
            )
    return None


class StreamableHttpHandler:
    """Conforming Streamable HTTP processor with OriginGuard, Bearer auth, and sessions."""

    def __init__(
        self,
        server: McpServer,
        *,
        origin_guard: OriginGuard | None = None,
        bearer_validator: BearerValidator | None = None,
        resource_metadata_url: str = "",
        required_scope: str = "",
        enable_sessions: bool | None = None,
    ) -> None:
        self.server = server
        self.origin_guard = origin_guard if origin_guard is not None else server.origin_guard
        self.bearer_validator = bearer_validator
        self.resource_metadata_url = resource_metadata_url
        self.required_scope = required_scope
        self.enable_sessions = (
            enable_sessions
            if enable_sessions is not None
            else (server.revision != REVISION_2026_07_28)
        )
        self._sessions: set[str] = set()

    def _authenticate(self, req: HttpRequest) -> HttpResponse | None:
        if self.bearer_validator is None:
            return None
        token = _extract_bearer_token(req.header("Authorization"))
        if token is not None and self.bearer_validator(token):
            return None
        challenge = build_bearer_challenge(
            resource_metadata=self.resource_metadata_url,
            scope=self.required_scope,
            error="invalid_token" if token is not None else "",
        )
        return _json_response(
            401,
            _rpc_err_body(None, INVALID_REQUEST, "Unauthorized"),
            {"WWW-Authenticate": challenge},
        )

    def _check_session(
        self, req: HttpRequest, decoded: Any
    ) -> tuple[HttpResponse | None, dict[str, str]]:
        if not self.enable_sessions:
            return None, {}
        method = decoded.get("method") if isinstance(decoded, Mapping) else None
        req_id = decoded.get("id") if isinstance(decoded, Mapping) else None
        sid = req.header("Mcp-Session-Id")
        if method == "initialize":
            new_sid = secrets.token_urlsafe(24)
            self._sessions.add(new_sid)
            return None, {"Mcp-Session-Id": new_sid}
        if sid is not None and sid not in self._sessions:
            err_resp = _json_response(
                404, _rpc_err_body(req_id, INVALID_REQUEST, "Unknown session")
            )
            return err_resp, {}
        return None, ({"Mcp-Session-Id": sid} if sid else {})

    def handle(self, req: HttpRequest) -> HttpResponse:
        """Process an HttpRequest in-memory and return an HttpResponse."""
        if self.origin_guard is not None and not self.origin_guard.is_allowed(req.header("Origin")):
            return _json_response(403, _rpc_err_body(None, INVALID_REQUEST, "Forbidden Origin"))
        auth_err = self._authenticate(req)
        if auth_err is not None:
            return auth_err
        if req.method.upper() != "POST":
            return _json_response(
                405,
                _rpc_err_body(None, INVALID_REQUEST, "Method Not Allowed"),
                {"Allow": "POST"},
            )
        try:
            decoded = json.loads(req.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _json_response(400, _rpc_err_body(None, PARSE_ERROR, "Parse error"))
        mismatch = _check_stateless_headers(req, decoded)
        if mismatch is not None:
            return mismatch
        sess_err, resp_headers = self._check_session(req, decoded)
        if sess_err is not None:
            return sess_err
        rpc_resp = self.server.handle_request(decoded)
        if rpc_resp is None:
            return HttpResponse(status=202, headers=resp_headers, body=b"")
        err = rpc_resp.get("error")
        status = (
            404
            if self.server.revision == REVISION_2026_07_28
            and isinstance(err, Mapping)
            and err.get("code") == METHOD_NOT_FOUND
            else 200
        )
        return _json_response(status, rpc_resp, resp_headers)

    def to_wsgi(self) -> Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]:
        """Adapt this StreamableHttpHandler to a PEP 3333 WSGI application callable."""

        def _app(
            environ: dict[str, Any], start_response: Callable[[str, list[tuple[str, str]]], Any]
        ) -> Iterable[bytes]:
            headers: dict[str, str] = {}
            for key, val in environ.items():
                if key.startswith("HTTP_"):
                    headers[key[5:].replace("_", "-")] = str(val)
            if "CONTENT_TYPE" in environ:
                headers["Content-Type"] = str(environ["CONTENT_TYPE"])
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = environ["wsgi.input"].read(length) if length > 0 else b""
            resp = self.handle(
                HttpRequest(
                    method=str(environ.get("REQUEST_METHOD", "GET")),
                    headers=headers,
                    body=body,
                    path=str(environ.get("PATH_INFO", "/mcp")),
                )
            )
            start_response(f"{resp.status} MCP", list(resp.headers.items()))
            return [resp.body]

        return _app

    def make_request_handler(self) -> type[BaseHTTPRequestHandler]:
        """Return a stdlib BaseHTTPRequestHandler subclass bound to this handler."""
        parent = self

        class _BoundHandler(BaseHTTPRequestHandler):
            def _dispatch_http(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b""
                hdrs = {k: v for k, v in self.headers.items()}
                resp = parent.handle(
                    HttpRequest(method=self.command, headers=hdrs, body=raw, path=self.path)
                )
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if resp.body:
                    self.wfile.write(resp.body)

            do_POST = _dispatch_http  # noqa: N815
            do_GET = _dispatch_http  # noqa: N815
            do_DELETE = _dispatch_http  # noqa: N815

            def log_message(self, _format: str, *_args: object) -> None:
                return

        return _BoundHandler


def _urllib_opener(timeout: float = 10.0) -> HttpOpener:
    def _open(req: HttpRequest) -> HttpResponse:
        ureq = urllib.request.Request(
            req.path, data=req.body, headers=dict(req.headers), method=req.method
        )
        try:
            with urllib.request.urlopen(ureq, timeout=timeout) as resp:  # noqa: S310
                return HttpResponse(
                    status=resp.status, headers=dict(resp.headers.items()), body=resp.read()
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status=exc.code,
                headers=dict(exc.headers.items()) if exc.headers else {},
                body=exc.read(),
            )

    return _open


class HttpClientTransport:
    """Streamable HTTP client transport supporting Bearer tokens, sessions, and mirrored headers."""

    def __init__(
        self,
        endpoint: str,
        *,
        bearer_token: str | None = None,
        protocol_version: str | None = REVISION_2026_07_28,
        headers: Mapping[str, str] | None = None,
        opener: HttpOpener | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.endpoint = endpoint
        self.bearer_token = bearer_token
        self.protocol_version = protocol_version
        self._extra_headers = dict(headers) if headers else {}
        self._opener = opener if opener is not None else _urllib_opener(timeout=timeout)
        self.session_id: str | None = None

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        hdrs: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._extra_headers,
        }
        if self.bearer_token:
            hdrs["Authorization"] = f"Bearer {self.bearer_token}"
        if self.session_id:
            hdrs["Mcp-Session-Id"] = self.session_id
        method = payload.get("method")
        if self.protocol_version == REVISION_2026_07_28 and isinstance(method, str):
            hdrs["MCP-Protocol-Version"] = REVISION_2026_07_28
            hdrs["MCP-Method"] = method
        resp = self._opener(
            HttpRequest(
                method="POST",
                headers=hdrs,
                body=json.dumps(payload).encode("utf-8"),
                path=self.endpoint,
            )
        )
        sid = resp.header("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        if resp.status in {202, 204} or not resp.body:
            if resp.status >= 400:
                raise JsonRpcError(
                    INVALID_REQUEST,
                    f"HTTP {resp.status}",
                    {"status": resp.status, "wwwAuthenticate": resp.header("WWW-Authenticate")},
                )
            return None
        decoded = json.loads(resp.body.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise JsonRpcError(INVALID_REQUEST, "Invalid JSON-RPC response envelope")
        return decoded
