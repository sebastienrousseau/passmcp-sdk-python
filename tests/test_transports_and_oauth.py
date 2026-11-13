# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Tests for stdio transport, Streamable HTTP handler/client, OAuth 2.1 PKCE, and schema checks."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from passmcp_sdk import (
    HEADER_MISMATCH,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REVISION_2025_11_25,
    REVISION_2026_07_28,
    CacheHints,
    CallToolResult,
    HttpRequest,
    McpClient,
    McpServer,
    OAuthError,
    OriginGuard,
    Prompt,
    PromptArgument,
    Resource,
    StdioTransport,
    StreamableHttpHandler,
    Tool,
    ToolAnnotations,
    authorization_server_metadata_url,
    build_bearer_challenge,
    compute_s256_challenge,
    generate_pkce_verifier,
    parse_bearer_challenge,
    protected_resource_metadata_url,
    protected_resource_metadata_urls,
    serve_stdio,
    validate_authorization_server_metadata,
    validate_protected_resource_metadata,
    verify_s256,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

ECHO_TOOL = Tool(
    name="echo_target",
    title="Echo Target",
    description="Echo target endpoint cleanly for testing",
    read_only_hint=True,
    input_schema={
        "type": "object",
        "additionalProperties": False,
        "required": ["endpoint"],
        "properties": {
            "endpoint": {"type": "string"},
            "retries": {"type": "integer"},
        },
    },
    output_schema={
        "type": "object",
        "required": ["endpoint"],
        "properties": {"endpoint": {"type": "string"}},
    },
    annotations=ToolAnnotations(
        title="Echo Target",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)


def _build_test_server(revision: str = REVISION_2026_07_28) -> McpServer:
    srv = McpServer(
        name="demo",
        version="0.0.10",
        revision=revision,
        cache_hints=CacheHints(cacheable=True, ttl=300, scope="public"),
        instructions="Reference test server",
    )
    srv.register_tool(
        ECHO_TOOL,
        lambda args: CallToolResult(
            content=({"type": "text", "text": args["endpoint"]},),
            structured_content={"endpoint": args["endpoint"]},
        ),
    )
    srv.register_resource(
        Resource(uri="demo://doc", name="doc", title="Doc"),
        lambda _uri: "body",
    )
    srv.register_prompt(
        Prompt(
            name="greet",
            title="Greet",
            arguments=(PromptArgument(name="who", required=True),),
        ),
        lambda args: f"Hello {args['who']}",
    )
    return srv


def test_stdio_framing_notifications_and_malformed_lines() -> None:
    srv = _build_test_server()
    lines = "\n".join(
        [
            "",
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            "{truncated-json",
            '{"jsonrpc":"2.0","id":1,"method":"ping"}',
            '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}',
            '{"jsonrpc":"2.0","id":2,"method":"server/discover"}',
        ]
    )
    out_buf = io.StringIO()
    serve_stdio(srv, stdin=io.StringIO(lines + "\n"), stdout=out_buf)
    frames = [json.loads(line) for line in out_buf.getvalue().splitlines()]
    assert len(frames) == 3
    assert frames[0]["error"]["code"] == PARSE_ERROR
    assert frames[1] == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert frames[2]["result"]["resultType"] == "discover"
    assert frames[2]["result"]["_meta"]["io.modelcontextprotocol/serverInfo"] == {
        "name": "demo",
        "version": "0.0.10",
    }
    assert frames[2]["result"]["supportedVersions"] == [
        "2026-07-28",
        "2025-11-25",
        "2025-06-18",
    ]


def test_stdio_in_memory_and_spawned_child_process() -> None:
    srv = _build_test_server()
    with StdioTransport.from_in_memory_server(srv) as mem_tr:
        mem_client = McpClient(mem_tr)
        assert mem_client.discover()["resultType"] == "discover"
        res = mem_client.call_tool("echo_target", {"endpoint": "https://mcp.example.com/mcp"})
        assert res["structuredContent"] == {"endpoint": "https://mcp.example.com/mcp"}

    env = {
        **os.environ,
        "PYTHONPATH": str(REPO_ROOT / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    client, tr = McpClient.from_stdio(
        [sys.executable, str(REPO_ROOT / "examples" / "stdio_server.py")], env=env
    )
    with tr:
        assert client.discover()["serverInfo"]["name"] == "passmcp-sdk-python-demo"
        out = client.call_tool("inspect_target", {"endpoint": "https://mcp.example.com/mcp"})
        assert out["structuredContent"] == {
            "endpoint": "https://mcp.example.com/mcp",
            "transport": "http",
        }
        assert "passmcp-sdk-python" in client.read_resource("passmcp://sdk/overview")[
            "contents"
        ][0]["text"]
        prompt = client.get_prompt("audit_summary", {"server_name": "billing"})
        assert "billing" in prompt["messages"][0]["content"]["text"]


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("tools/call", {"name": "echo_target", "arguments": {}}),
        ("tools/call", {"name": "echo_target", "arguments": {"endpoint": 123}}),
        ("tools/call", {"name": "echo_target", "arguments": {"endpoint": "ok", "retries": True}}),
        ("tools/call", {"name": "echo_target", "arguments": {"endpoint": "ok", "extra": "x"}}),
        ("prompts/get", {"name": "greet", "arguments": {}}),
        ("prompts/get", {"name": "greet", "arguments": {"who": "  "}}),
    ],
)
def test_schema_and_negative_parameter_validation(
    method: str, params: dict[str, Any]
) -> None:
    srv = _build_test_server()
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    assert resp is not None and resp["error"]["code"] == INVALID_PARAMS


def test_streamable_http_auth_origin_and_method_guards() -> None:
    srv = _build_test_server()
    handler = StreamableHttpHandler(
        srv,
        origin_guard=OriginGuard(["https://console.example.com"]),
        bearer_validator=lambda tok: tok == "valid-secret",
        resource_metadata_url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        required_scope="mcp:read",
    )
    r_origin = handler.handle(
        HttpRequest(
            method="POST",
            headers={"Origin": "https://evil.example.com"},
            body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        )
    )
    assert r_origin.status == 403

    r_unauth = handler.handle(
        HttpRequest(method="POST", body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}')
    )
    assert r_unauth.status == 401
    chal = parse_bearer_challenge(r_unauth.header("WWW-Authenticate") or "")
    assert (
        chal.resource_metadata
        == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    )
    assert chal.scope == "mcp:read"

    auth_hdr = {"Authorization": "Bearer valid-secret"}
    r_get = handler.handle(HttpRequest(method="GET", headers=auth_hdr))
    assert r_get.status == 405 and r_get.header("Allow") == "POST"

    r_bad = handler.handle(HttpRequest(method="POST", headers=auth_hdr, body=b"{broken"))
    assert r_bad.status == 400 and r_bad.json()["error"]["code"] == PARSE_ERROR


def test_streamable_http_stateless_headers_and_client() -> None:
    srv = _build_test_server()
    handler = StreamableHttpHandler(
        srv, bearer_validator=lambda tok: tok == "valid-secret"
    )
    auth_hdr = {"Authorization": "Bearer valid-secret"}

    r_notif = handler.handle(
        HttpRequest(
            method="POST",
            headers=auth_hdr,
            body=b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
        )
    )
    assert r_notif.status == 202 and r_notif.body == b""

    r_mismatch = handler.handle(
        HttpRequest(
            method="POST",
            headers={**auth_hdr, "MCP-Protocol-Version": "2026-07-28", "MCP-Method": "tools/list"},
            body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        )
    )
    assert r_mismatch.status == 400 and r_mismatch.json()["error"]["code"] == HEADER_MISMATCH

    r_404 = handler.handle(
        HttpRequest(
            method="POST",
            headers=auth_hdr,
            body=b'{"jsonrpc":"2.0","id":1,"method":"no/such/method"}',
        )
    )
    assert r_404.status == 404 and r_404.json()["error"]["code"] == METHOD_NOT_FOUND

    http_client = McpClient.from_http(
        "https://mcp.example.com/mcp", bearer_token="valid-secret", opener=handler.handle
    )
    assert http_client.ping() == {}
    call_res = http_client.call_tool("echo_target", {"endpoint": "https://a.example/mcp"})
    assert call_res["structuredContent"] == {"endpoint": "https://a.example/mcp"}


def test_http_session_mode_on_handshake_revision() -> None:
    srv = _build_test_server(revision=REVISION_2025_11_25)
    handler = StreamableHttpHandler(srv)
    init_resp = handler.handle(
        HttpRequest(
            method="POST",
            body=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}',
        )
    )
    assert init_resp.status == 200
    sid = init_resp.header("Mcp-Session-Id")
    assert sid is not None and len(sid) >= 16

    ok_resp = handler.handle(
        HttpRequest(
            method="POST",
            headers={"Mcp-Session-Id": sid},
            body=b'{"jsonrpc":"2.0","id":2,"method":"ping"}',
        )
    )
    assert ok_resp.status == 200

    bogus_resp = handler.handle(
        HttpRequest(
            method="POST",
            headers={"Mcp-Session-Id": "bogus-session-id"},
            body=b'{"jsonrpc":"2.0","id":3,"method":"ping"}',
        )
    )
    assert bogus_resp.status == 404


def test_oauth_pkce_and_bearer_challenge() -> None:
    verifier = generate_pkce_verifier(64)
    assert len(verifier) == 64
    challenge = compute_s256_challenge(verifier)
    assert verify_s256(verifier, challenge) is True
    assert verify_s256(verifier, "wrong-challenge") is False
    assert (
        compute_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )
    with pytest.raises(OAuthError):
        generate_pkce_verifier(42)
    with pytest.raises(OAuthError):
        compute_s256_challenge("too-short")

    hdr = build_bearer_challenge(
        resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        scope="mcp:tools",
        error="invalid_token",
        error_description="Token expired",
    )
    parsed = parse_bearer_challenge(hdr)
    assert parsed.scope == "mcp:tools"
    assert parsed.error == "invalid_token"
    assert parsed.error_description == "Token expired"


def test_rfc9728_and_rfc8414_metadata_validation() -> None:
    assert protected_resource_metadata_urls("https://mcp.example.com/mcp") == (
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        "https://mcp.example.com/.well-known/oauth-protected-resource",
    )
    assert (
        protected_resource_metadata_url("https://mcp.example.com")
        == "https://mcp.example.com/.well-known/oauth-protected-resource"
    )
    prm = validate_protected_resource_metadata(
        {
            "resource": "https://mcp.example.com/mcp",
            "authorization_servers": ["https://auth.example.com"],
            "scopes_supported": ["mcp:tools"],
        },
        expected_resource="https://mcp.example.com/mcp",
    )
    assert prm.authorization_servers == ("https://auth.example.com",)

    with pytest.raises(OAuthError, match="resource mismatch"):
        validate_protected_resource_metadata(
            {
                "resource": "https://attacker.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
            expected_resource="https://mcp.example.com/mcp",
        )

    assert (
        authorization_server_metadata_url("https://auth.example.com/tenant")
        == "https://auth.example.com/.well-known/oauth-authorization-server/tenant"
    )
    asm = validate_authorization_server_metadata(
        {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "code_challenge_methods_supported": ["S256"],
        },
        expected_issuer="https://auth.example.com",
    )
    assert asm.code_challenge_methods_supported == ("S256",)

    with pytest.raises(OAuthError, match="S256"):
        validate_authorization_server_metadata(
            {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "code_challenge_methods_supported": ["plain"],
            }
        )
