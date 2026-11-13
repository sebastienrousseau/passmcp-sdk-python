# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Reference stdio MCP server for passmcp conformance verification."""

from __future__ import annotations

import json
from typing import Any

from passmcp_sdk import (
    INVALID_PARAMS,
    CacheHints,
    CallToolResult,
    JsonRpcError,
    McpServer,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    Tool,
    ToolAnnotations,
    serve_stdio,
)

INSPECT_TARGET_TOOL = Tool(
    name="inspect_target",
    title="Inspect MCP Target",
    description=(
        "Inspect an HTTPS or stdio MCP target identifier and classify its transport "
        "without making any network connections."
    ),
    read_only_hint=True,
    input_schema={
        "type": "object",
        "additionalProperties": False,
        "required": ["endpoint"],
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "HTTPS or stdio target endpoint identifier to inspect",
            }
        },
    },
    output_schema={
        "type": "object",
        "required": ["endpoint", "transport"],
        "properties": {
            "endpoint": {"type": "string"},
            "transport": {"type": "string"},
        },
    },
    annotations=ToolAnnotations(
        title="Inspect MCP Target",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)


def _inspect_target(args: dict[str, Any]) -> CallToolResult:
    endpoint = args.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise JsonRpcError(INVALID_PARAMS, "endpoint must be a non-empty string")
    trimmed = endpoint.strip()
    transport = "http" if trimmed.startswith(("https://", "http://")) else "stdio"
    structured = {"endpoint": trimmed, "transport": transport}
    return CallToolResult(
        content=({"type": "text", "text": json.dumps(structured, sort_keys=True)},),
        structured_content=structured,
    )


def build_demo_server() -> McpServer:
    """Build the reference stdio MCP server used by passmcp check --stdio."""
    srv = McpServer(
        name="passmcp-sdk-python-demo",
        version="0.0.9",
        cache_hints=CacheHints(cacheable=True, ttl=300, scope="public"),
        instructions=(
            "Reference MCP server built with passmcp-sdk demonstrating read-only tools, "
            "SEP-2164 resources, prompts, and SEP-2549 cache hints."
        ),
    )
    srv.register_tool(INSPECT_TARGET_TOOL, _inspect_target)
    srv.register_resource(
        Resource(
            uri="passmcp://sdk/overview",
            name="sdk-overview",
            title="SDK Overview",
            description="Overview of the passmcp SDK capabilities and supported MCP revisions.",
            mime_type="text/plain",
        ),
        lambda _uri: (
            "passmcp-sdk-python supports MCP revisions 2025-06-18, 2025-11-25, and 2026-07-28 "
            "with capability-derived dispatch, SEP-2164, SEP-2549, and offline attestations."
        ),
    )
    srv.register_prompt(
        Prompt(
            name="audit_summary",
            title="Audit Summary Prompt",
            description="Generate a concise audit summary prompt for a named MCP server.",
            arguments=(
                PromptArgument(
                    name="server_name",
                    description="Name of the MCP server being audited",
                    required=True,
                ),
            ),
        ),
        lambda args: [
            PromptMessage(
                role="user",
                text=f"Summarize the MCP conformance posture for server {args['server_name']}.",
            )
        ],
    )
    return srv


if __name__ == "__main__":
    serve_stdio(build_demo_server())
