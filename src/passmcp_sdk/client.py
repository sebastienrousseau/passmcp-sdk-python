# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Policy-enforcing MCP client with read-only defaults and attestation gating."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from passmcp_sdk.attestation import NoSuchCheckError, Statement
from passmcp_sdk.http_transport import HttpClientTransport, HttpOpener
from passmcp_sdk.server import McpServer
from passmcp_sdk.stdio import StdioTransport
from passmcp_sdk.types import METHOD_NOT_FOUND, REVISION_2026_07_28, JsonRpcError, Tool

TransportCallable = Callable[[dict[str, Any]], dict[str, Any] | None]


class PolicyViolationError(PermissionError):
    """Raised when a client call violates tool safety or attestation policy."""


@dataclass(frozen=True)
class Policy:
    """Client execution policy enforcing read-only defaults and verified attestations."""

    allow_mutations: bool = False
    statement: Statement | None = None
    require_zero_failures: bool = True
    min_score: float | None = None
    required_checks: tuple[str, ...] = ()

    def check_target(self, transport: str, endpoint: str) -> None:
        """Verify that any configured attestation statement covers and clears the target."""
        stmt = self.statement
        if stmt is None:
            return
        if not stmt.covers(transport, endpoint):
            raise PolicyViolationError(
                f"Attestation statement does not cover target {transport}:{endpoint}"
            )
        if self.require_zero_failures and stmt.predicate.counts.fail > 0:
            raise PolicyViolationError(
                f"Attestation statement records {stmt.predicate.counts.fail} failure(s)"
            )
        if self.min_score is not None:
            total = stmt.score_total
            if total is None or total < self.min_score:
                raise PolicyViolationError(
                    f"Attestation score {total} is below minimum {self.min_score}"
                )
        for check_id in self.required_checks:
            try:
                verdict = stmt.verdict_for(check_id)
            except NoSuchCheckError as exc:
                raise PolicyViolationError(str(exc)) from exc
            if verdict.status != "pass":
                raise PolicyViolationError(
                    f"Required check {check_id!r} has status {verdict.status!r}, want 'pass'"
                )

    def check_tool(self, tool: Tool) -> None:
        """Enforce readOnlyHint=True unless mutations are explicitly allowed."""
        if not self.allow_mutations and not tool.is_read_only:
            raise PolicyViolationError(
                f"Refusing to execute tool {tool.name!r}: readOnlyHint is not true "
                "and Policy.allow_mutations is False"
            )


def http_transport(
    endpoint: str,
    *,
    bearer_token: str | None = None,
    protocol_version: str | None = REVISION_2026_07_28,
    headers: Mapping[str, str] | None = None,
    opener: HttpOpener | None = None,
    timeout: float = 10.0,
) -> HttpClientTransport:
    """Create a zero-dependency Streamable HTTP JSON-RPC transport callable."""
    return HttpClientTransport(
        endpoint,
        bearer_token=bearer_token,
        protocol_version=protocol_version,
        headers=headers,
        opener=opener,
        timeout=timeout,
    )


class McpClient:
    """MCP JSON-RPC 2.0 client enforcing read-only tool defaults and attestation checks."""

    def __init__(
        self,
        transport: TransportCallable,
        *,
        endpoint: str = "stdio://local",
        transport_kind: str = "stdio",
        policy: Policy | None = None,
    ) -> None:
        self._send = transport
        self.endpoint = endpoint
        self.transport_kind = transport_kind
        self.policy = policy if policy is not None else Policy()
        self._next_id = 0
        self._tools_cache: dict[str, Tool] | None = None

    @classmethod
    def from_server(
        cls,
        server: McpServer,
        *,
        endpoint: str = "https://mcp.example.com/mcp",
        transport_kind: str = "http",
        policy: Policy | None = None,
    ) -> McpClient:
        """Bind a client directly to an in-process McpServer instance."""
        return cls(
            server.handle_request,
            endpoint=endpoint,
            transport_kind=transport_kind,
            policy=policy,
        )

    @classmethod
    def from_http(
        cls,
        endpoint: str,
        *,
        policy: Policy | None = None,
        bearer_token: str | None = None,
        protocol_version: str | None = REVISION_2026_07_28,
        headers: Mapping[str, str] | None = None,
        opener: HttpOpener | None = None,
        timeout: float = 10.0,
    ) -> McpClient:
        """Create a Streamable HTTP MCP client using Python's standard library."""
        return cls(
            http_transport(
                endpoint,
                bearer_token=bearer_token,
                protocol_version=protocol_version,
                headers=headers,
                opener=opener,
                timeout=timeout,
            ),
            endpoint=endpoint,
            transport_kind="http",
            policy=policy,
        )

    @classmethod
    def from_stdio(
        cls,
        command: Sequence[str],
        *,
        policy: Policy | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> tuple[McpClient, StdioTransport]:
        """Spawn a stdio MCP server process and return (client, transport)."""
        tr = StdioTransport.spawn(command, env=env, cwd=cwd)
        endpoint = " ".join(command)
        return cls(tr, endpoint=endpoint, transport_kind="stdio", policy=policy), tr

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.policy.check_target(self.transport_kind, self.endpoint)
        self._next_id += 1
        envelope: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            envelope["params"] = params
        response = self._send(envelope)
        if not isinstance(response, Mapping):
            raise JsonRpcError(-32603, f"Missing JSON-RPC response for {method}")
        err = response.get("error")
        if isinstance(err, Mapping):
            code = err.get("code", -32603)
            msg = err.get("message", "RPC error")
            raise JsonRpcError(int(code), str(msg), err.get("data"))
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise JsonRpcError(-32603, f"Malformed JSON-RPC result for {method}")
        return dict(result)

    def discover(self) -> dict[str, Any]:
        """Discover server capabilities via stateless server/discover or initialize."""
        try:
            res = self._call("server/discover", {})
            raw_tools = res.get("tools")
            if isinstance(raw_tools, list):
                parsed = [Tool.from_wire(item) for item in raw_tools if isinstance(item, Mapping)]
                self._tools_cache = {t.name: t for t in parsed}
            return res
        except JsonRpcError as exc:
            if exc.code != METHOD_NOT_FOUND:
                raise
        init_res = self._call(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "passmcp-sdk-python", "version": "0.0.10"},
            },
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init_res

    def ping(self) -> dict[str, Any]:
        """Send a JSON-RPC ping check."""
        return self._call("ping")

    def list_tools(self) -> list[Tool]:
        """Fetch and cache advertised server tools."""
        result = self._call("tools/list", {})
        raw_tools = result.get("tools", [])
        if not isinstance(raw_tools, list):
            raise JsonRpcError(-32603, "Invalid tools/list response")
        tools = [Tool.from_wire(item) for item in raw_tools if isinstance(item, Mapping)]
        self._tools_cache = {t.name: t for t in tools}
        return tools

    def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Validate tool policy (readOnlyHint by default) and execute tools/call."""
        self.policy.check_target(self.transport_kind, self.endpoint)
        if self._tools_cache is None:
            self.list_tools()
        assert self._tools_cache is not None
        tool = self._tools_cache.get(name)
        if tool is None:
            raise JsonRpcError(-32602, f"Unknown tool: {name}", {"name": name})
        self.policy.check_tool(tool)
        return self._call(
            "tools/call",
            {"name": name, "arguments": dict(arguments) if arguments is not None else {}},
        )

    def read_resource(self, uri: str) -> dict[str, Any]:
        """Read a resource URI via resources/read."""
        return self._call("resources/read", {"uri": uri})

    def get_prompt(
        self, name: str, arguments: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        """Resolve a prompt via prompts/get."""
        payload: dict[str, Any] = {"name": name}
        if arguments is not None:
            payload["arguments"] = dict(arguments)
        return self._call("prompts/get", payload)
