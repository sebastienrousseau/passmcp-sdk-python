# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Tests for MCP server capability gating, SEP-2164, SEP-2549, OriginGuard, and client Policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from passmcp_sdk import (
    INVALID_PARAMS,
    LEGACY_RESOURCE_NOT_FOUND,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REVISION_2025_06_18,
    REVISION_2025_11_25,
    REVISION_2026_07_28,
    CacheHints,
    JsonRpcError,
    McpClient,
    McpServer,
    OriginGuard,
    Policy,
    PolicyViolationError,
    Prompt,
    PromptArgument,
    Resource,
    ResourceTemplate,
    Tool,
    parse_statement,
)

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "testdata" / "statement.json"


def test_undeclared_capabilities_omitted_and_rejected() -> None:
    srv = McpServer(name="minimal", version="0.0.10")
    init = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init is not None
    assert init["result"]["capabilities"] == {}

    disc = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})
    assert disc is not None
    assert disc["result"]["capabilities"] == {}
    assert "tools" not in disc["result"]
    assert "resources" not in disc["result"]
    assert "prompts" not in disc["result"]

    for idx, method in enumerate(
        (
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/templates/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "unknown/method",
        ),
        start=10,
    ):
        resp = srv.handle_request({"jsonrpc": "2.0", "id": idx, "method": method})
        assert resp is not None
        assert resp["error"]["code"] == METHOD_NOT_FOUND


def test_notifications_and_json_parse_errors() -> None:
    srv = McpServer(name="minimal", version="0.0.10")
    assert srv.handle_json('{"jsonrpc":"2.0","method":"notifications/initialized"}') is None

    bad_raw = srv.handle_json("{broken")
    assert bad_raw is not None
    parsed = json.loads(bad_raw)
    assert parsed["error"]["code"] == PARSE_ERROR

    ping_raw = srv.handle_json('{"jsonrpc":"2.0","id":"p1","method":"ping"}')
    assert ping_raw is not None
    assert json.loads(ping_raw) == {"jsonrpc": "2.0", "id": "p1", "result": {}}


def test_sep_2164_missing_resource_errors_across_revisions() -> None:
    srv_current = McpServer(name="docs", version="0.0.10", revision=REVISION_2026_07_28)
    srv_current.register_resource(
        Resource(uri="docs://readme", name="readme"), lambda _uri: "hello"
    )

    ok_resp = srv_current.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "docs://readme"},
        }
    )
    assert ok_resp is not None
    assert ok_resp["result"]["contents"][0]["text"] == "hello"

    missing_current = srv_current.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {"uri": "docs://missing"},
        }
    )
    assert missing_current is not None
    assert missing_current["error"]["code"] == INVALID_PARAMS
    assert missing_current["error"]["data"] == {"uri": "docs://missing"}

    for legacy_rev in (REVISION_2025_11_25, REVISION_2025_06_18):
        srv_legacy = McpServer(name="docs", version="0.0.10", revision=legacy_rev)
        srv_legacy.register_resource(
            Resource(uri="docs://readme", name="readme"), lambda _uri: "hello"
        )
        missing_legacy = srv_legacy.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {"uri": "docs://missing"},
            }
        )
        assert missing_legacy is not None
        assert missing_legacy["error"]["code"] == LEGACY_RESOURCE_NOT_FOUND
        assert missing_legacy["error"]["data"] == {"uri": "docs://missing"}

        # Stateless server/discover is rejected on handshake-era revisions.
        disc_legacy = srv_legacy.handle_request(
            {"jsonrpc": "2.0", "id": 4, "method": "server/discover"}
        )
        assert disc_legacy is not None
        assert disc_legacy["error"]["code"] == METHOD_NOT_FOUND


def test_sep_2549_cache_hints_validation_and_list_emission() -> None:
    with pytest.raises(ValueError, match="ttl_ms"):
        CacheHints(ttl_ms=-1, cache_scope="public")
    with pytest.raises(ValueError, match="ttl_ms"):
        CacheHints(ttl_ms=True, cache_scope="public")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cache_scope"):
        CacheHints(ttl_ms=0, cache_scope="shared")

    hints = CacheHints(ttl_ms=0, cache_scope="public")
    srv = McpServer(name="catalog", version="0.0.10", cache_hints=hints)
    srv.register_tool(Tool(name="ping_tool", read_only_hint=True), lambda _a: "pong")
    srv.register_resource(Resource(uri="cat://one", name="one"), lambda _u: "1")
    srv.register_resource_template(
        ResourceTemplate(uri_template="cat://items/{id}", name="item")
    )
    srv.register_prompt(
        Prompt(
            name="summarize",
            description="Summarize topic",
            arguments=(PromptArgument(name="topic", required=True),),
        ),
        lambda args: f"Summarize {args['topic']}",
    )

    for method in (
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    ):
        resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": method})
        assert resp is not None
        assert resp["result"]["_meta"] == {"ttlMs": 0, "cacheScope": "public"}

    disc = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})
    assert disc is not None
    assert set(disc["result"]["capabilities"].keys()) == {"tools", "resources", "prompts"}
    assert len(disc["result"]["tools"]) == 1
    assert len(disc["result"]["resources"]) == 1
    assert len(disc["result"]["resourceTemplates"]) == 1
    assert len(disc["result"]["prompts"]) == 1

    prompt_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "prompts/get",
            "params": {"name": "summarize", "arguments": {"topic": "SEP-2549"}},
        }
    )
    assert prompt_resp is not None
    assert prompt_resp["result"]["messages"][0]["content"]["text"] == "Summarize SEP-2549"


def test_origin_guard_and_http_dispatch() -> None:
    guard = OriginGuard(["https://App.Example.com:8443"])
    assert guard.is_allowed(None) is True
    assert guard.is_allowed("https://app.example.com:8443") is True
    assert guard.is_allowed("https://passmcp-origin-probe.invalid") is False
    assert guard.is_allowed("null") is False
    assert guard.is_allowed("") is False

    strict_guard = OriginGuard(["https://app.example.com"], allow_missing_origin=False)
    assert strict_guard.is_allowed(None) is False
    with pytest.raises(PermissionError):
        strict_guard.check("https://evil.example.com")

    srv = McpServer(name="guarded", version="0.0.10", origin_guard=guard)
    status_bad, _ = srv.handle_http(
        '{"jsonrpc":"2.0","id":1,"method":"ping"}',
        origin="https://passmcp-origin-probe.invalid",
    )
    assert status_bad == 403

    status_ok, body_ok = srv.handle_http(
        '{"jsonrpc":"2.0","id":1,"method":"ping"}',
        origin="https://app.example.com:8443",
    )
    assert status_ok == 200
    assert body_ok is not None
    assert json.loads(body_ok)["result"] == {}


def test_client_policy_read_only_default_and_attestation_gating() -> None:
    srv = McpServer(name="ops", version="0.0.10")
    srv.register_tool(Tool(name="status", read_only_hint=True), lambda _a: "green")
    srv.register_tool(Tool(name="drop_table", read_only_hint=False), lambda _a: "dropped")

    client = McpClient.from_server(srv)
    assert client.call_tool("status")["content"][0]["text"] == "green"
    with pytest.raises(PolicyViolationError, match="readOnlyHint"):
        client.call_tool("drop_table")

    # Opting into mutations permits mutating tools.
    mut_client = McpClient.from_server(srv, policy=Policy(allow_mutations=True))
    assert mut_client.call_tool("drop_table")["content"][0]["text"] == "dropped"

    # Gating on a verified Statement: fixture has 1 failure (protocol.origin),
    # so default require_zero_failures=True blocks calls!
    st = parse_statement(FIXTURE_PATH.read_bytes())
    strict_client = McpClient.from_server(
        srv,
        endpoint="https://mcp.example.com/mcp",
        transport_kind="http",
        policy=Policy(statement=st),
    )
    with pytest.raises(PolicyViolationError, match="failure"):
        strict_client.call_tool("status")

    # Wrong target endpoint fails covers() check.
    wrong_target_client = McpClient.from_server(
        srv,
        endpoint="https://untrusted.example.com/mcp",
        transport_kind="http",
        policy=Policy(statement=st, require_zero_failures=False),
    )
    with pytest.raises(PolicyViolationError, match="does not cover"):
        wrong_target_client.call_tool("status")

    # Matching endpoint + passing required check succeeds.
    gated_client = McpClient.from_server(
        srv,
        endpoint="https://mcp.example.com/mcp",
        transport_kind="http",
        policy=Policy(
            statement=st,
            require_zero_failures=False,
            min_score=85.0,
            required_checks=("auth.unauthenticated_tools",),
        ),
    )
    assert gated_client.call_tool("status")["content"][0]["text"] == "green"

    with pytest.raises(JsonRpcError):
        gated_client.call_tool("nonexistent")
