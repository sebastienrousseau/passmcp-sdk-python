# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Runnable end-to-end quickstart for passmcp-sdk."""

from __future__ import annotations

from pathlib import Path

from passmcp_sdk import (
    CacheHints,
    McpClient,
    McpServer,
    OriginGuard,
    Policy,
    Resource,
    Tool,
    parse_statement,
)


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    srv = McpServer(
        name="billing",
        version="0.0.10",
        cache_hints=CacheHints(ttl_ms=60_000, cache_scope="private"),
        origin_guard=OriginGuard(["https://console.example.com"]),
    )
    srv.register_tool(
        Tool(name="health", description="Read-only health probe", read_only_hint=True),
        lambda _args: "ok",
    )
    srv.register_resource(
        Resource(uri="billing://status", name="status", description="Service status"),
        lambda _uri: "healthy",
    )

    st = parse_statement((repo_root / "testdata" / "statement.json").read_bytes())
    assert st.covers("http", "https://mcp.example.com/mcp")

    client = McpClient.from_server(
        srv,
        endpoint="https://mcp.example.com/mcp",
        transport_kind="http",
        policy=Policy(
            allow_mutations=False,
            statement=st,
            require_zero_failures=False,
            min_score=80.0,
            required_checks=("auth.unauthenticated_tools",),
        ),
    )
    discovered = client.discover()
    tool_result = client.call_tool("health")
    print(
        f"{srv.name} v{srv.version} revision={discovered['protocolVersion']} "
        f"tool={tool_result['content'][0]['text']} grade={st.score_grade}"
    )


if __name__ == "__main__":
    main()
