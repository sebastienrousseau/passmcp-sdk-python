# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Capability-gated MCP JSON-RPC 2.0 server with SEP-2164 and SEP-2549 conformance."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from passmcp_sdk.schema import CacheHints, validate_object_schema
from passmcp_sdk.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    LEGACY_RESOURCE_NOT_FOUND,
    META_SERVER_INFO,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REVISION_2026_07_28,
    SUPPORTED_REVISIONS,
    CallToolResult,
    JsonRpcError,
    Prompt,
    PromptMessage,
    Resource,
    ResourceContent,
    ResourceTemplate,
    Tool,
)

ToolHandler = Callable[[dict[str, Any]], Any]
ResourceHandler = Callable[[str], Any]
PromptHandler = Callable[[dict[str, str]], Any]


def _normalize_origin(origin: str) -> str:
    trimmed = origin.strip()
    if not trimmed or trimmed.lower() == "null":
        raise ValueError("Origin must be an explicit http(s) origin, not empty or 'null'")
    parts = urlsplit(trimmed)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"Invalid HTTP Origin: {origin!r}")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError(f"Origin must not carry path, query, or fragment: {origin!r}")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


class OriginGuard:
    """Strict HTTP Origin allowlist validator for Streamable HTTP MCP endpoints."""

    def __init__(
        self,
        allowed_origins: Iterable[str] = (),
        *,
        allow_missing_origin: bool = True,
    ) -> None:
        self._allowed = frozenset(_normalize_origin(item) for item in allowed_origins)
        self._allow_missing = allow_missing_origin

    @property
    def allowed_origins(self) -> frozenset[str]:
        return self._allowed

    def is_allowed(self, origin: str | None) -> bool:
        """Return True iff the HTTP Origin header value is permitted."""
        if origin is None:
            return self._allow_missing
        try:
            normalized = _normalize_origin(origin)
        except ValueError:
            return False
        return normalized in self._allowed

    def check(self, origin: str | None) -> None:
        """Raise PermissionError when the HTTP Origin header is disallowed."""
        if not self.is_allowed(origin):
            raise PermissionError(f"Forbidden HTTP Origin: {origin!r}")


def _rpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _format_tool_output(tool: Tool, output: Any) -> dict[str, Any]:
    if isinstance(output, CallToolResult):
        return output.to_wire()
    if isinstance(output, str):
        return {"content": [{"type": "text", "text": output}]}
    if isinstance(output, Mapping):
        result = dict(output)
        if "content" not in result and tool.output_schema is not None:
            return {
                "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                "structuredContent": result,
            }
        return result
    raise TypeError("Tool handler must return str, CallToolResult, or Mapping")


def _format_resource_output(uri: str, mime_type: str, output: Any) -> dict[str, Any]:
    if isinstance(output, str):
        return {"contents": [{"uri": uri, "mimeType": mime_type, "text": output}]}
    if isinstance(output, ResourceContent):
        return {"contents": [output.to_wire()]}
    if isinstance(output, list) and all(isinstance(x, ResourceContent) for x in output):
        return {"contents": [x.to_wire() for x in output]}
    if isinstance(output, Mapping):
        return dict(output)
    raise TypeError("Resource handler must return str, ResourceContent, list, or Mapping")


def _format_prompt_output(description: str, output: Any) -> dict[str, Any]:
    if isinstance(output, str):
        msg = PromptMessage(role="user", text=output).to_wire()
        res: dict[str, Any] = {"messages": [msg]}
        if description:
            res["description"] = description
        return res
    if isinstance(output, list) and all(isinstance(x, PromptMessage) for x in output):
        res = {"messages": [x.to_wire() for x in output]}
        if description:
            res["description"] = description
        return res
    if isinstance(output, Mapping):
        return dict(output)
    raise TypeError("Prompt handler must return str, list[PromptMessage], or Mapping")


class McpServer:
    """Capability-derived JSON-RPC 2.0 MCP server across 2025-06-18 .. 2026-07-28."""

    def __init__(
        self,
        name: str,
        version: str,
        *,
        revision: str = REVISION_2026_07_28,
        cache_hints: CacheHints | None = None,
        origin_guard: OriginGuard | None = None,
        instructions: str | None = None,
        supported_versions: Sequence[str] | None = None,
    ) -> None:
        if not name.strip() or not version.strip():
            raise ValueError("McpServer name and version must be non-empty")
        if revision not in SUPPORTED_REVISIONS:
            raise ValueError(f"Unsupported MCP revision: {revision!r}")
        self.name = name
        self.version = version
        self.revision = revision
        self.cache_hints = cache_hints
        self.origin_guard = origin_guard
        self.instructions = instructions
        self.supported_versions: tuple[str, ...] = (
            tuple(supported_versions)
            if supported_versions is not None
            else SUPPORTED_REVISIONS
            if revision == REVISION_2026_07_28
            else (revision,)
        )
        self._tools: dict[str, tuple[Tool, ToolHandler]] = {}
        self._resources: dict[str, tuple[Resource, ResourceHandler]] = {}
        self._templates: dict[str, ResourceTemplate] = {}
        self._prompts: dict[str, tuple[Prompt, PromptHandler]] = {}

    def register_tool(self, tool: Tool, handler: ToolHandler) -> None:
        """Register a tool and enable the tools capability."""
        self._tools[tool.name] = (tool, handler)

    def register_resource(self, resource: Resource, handler: ResourceHandler) -> None:
        """Register a readable resource and enable the resources capability."""
        self._resources[resource.uri] = (resource, handler)

    def register_resource_template(self, template: ResourceTemplate) -> None:
        """Register a resource URI template and enable the resources capability."""
        self._templates[template.uri_template] = template

    def register_prompt(self, prompt: Prompt, handler: PromptHandler) -> None:
        """Register a prompt template and enable the prompts capability."""
        self._prompts[prompt.name] = (prompt, handler)

    def capabilities(self) -> dict[str, Any]:
        """Derive MCP server capabilities strictly from registered handlers."""
        caps: dict[str, Any] = {}
        if self._tools:
            caps["tools"] = {}
        if self._resources or self._templates:
            caps["resources"] = {}
        if self._prompts:
            caps["prompts"] = {}
        return caps

    def _with_list_meta(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.cache_hints is not None and self.revision == REVISION_2026_07_28:
            return self.cache_hints.apply_to_list(payload)
        return payload

    def _handle_initialize(self, params: Mapping[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        negotiated = (
            requested
            if isinstance(requested, str) and requested in SUPPORTED_REVISIONS
            else self.revision
        )
        res: dict[str, Any] = {
            "protocolVersion": negotiated,
            "capabilities": self.capabilities(),
            "serverInfo": {"name": self.name, "version": self.version},
        }
        if self.instructions:
            res["instructions"] = self.instructions
        return res

    def _handle_discover(self) -> dict[str, Any]:
        if self.revision != REVISION_2026_07_28:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: server/discover")
        caps = self.capabilities()
        info = {"name": self.name, "version": self.version}
        res: dict[str, Any] = {
            "resultType": "discover",
            "protocolVersion": self.revision,
            "supportedVersions": list(self.supported_versions),
            "serverInfo": info,
            "capabilities": caps,
            "_meta": {META_SERVER_INFO: dict(info)},
        }
        if "tools" in caps:
            res["tools"] = [tool.to_wire() for tool, _ in self._tools.values()]
        if "resources" in caps:
            res["resources"] = [item.to_wire() for item, _ in self._resources.values()]
            res["resourceTemplates"] = [tpl.to_wire() for tpl in self._templates.values()]
        if "prompts" in caps:
            res["prompts"] = [prompt.to_wire() for prompt, _ in self._prompts.values()]
        if self.instructions:
            res["instructions"] = self.instructions
        return res

    def _handle_tools_list(self) -> dict[str, Any]:
        if not self._tools:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: tools/list")
        return self._with_list_meta({"tools": [t.to_wire() for t, _ in self._tools.values()]})

    def _handle_tools_call(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if not self._tools:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: tools/call")
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: missing tool name")
        raw_args = params.get("arguments", {})
        if not isinstance(raw_args, Mapping):
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: arguments must be an object")
        entry = self._tools.get(name)
        if entry is None:
            raise JsonRpcError(INVALID_PARAMS, f"Unknown tool: {name}", {"name": name})
        tool, handler = entry
        validate_object_schema(tool.input_schema, raw_args)
        return _format_tool_output(tool, handler(dict(raw_args)))

    def _handle_resources_list(self) -> dict[str, Any]:
        if not self._resources and not self._templates:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: resources/list")
        return self._with_list_meta(
            {"resources": [r.to_wire() for r, _ in self._resources.values()]}
        )

    def _handle_templates_list(self) -> dict[str, Any]:
        if not self._resources and not self._templates:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: resources/templates/list")
        return self._with_list_meta(
            {"resourceTemplates": [tpl.to_wire() for tpl in self._templates.values()]}
        )

    def _handle_resources_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if not self._resources and not self._templates:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: resources/read")
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: missing resource uri")
        entry = self._resources.get(uri)
        if entry is None:
            code = (
                INVALID_PARAMS
                if self.revision == REVISION_2026_07_28
                else LEGACY_RESOURCE_NOT_FOUND
            )
            raise JsonRpcError(code, f"Resource not found: {uri}", {"uri": uri})
        resource, handler = entry
        return _format_resource_output(uri, resource.mime_type, handler(uri))

    def _handle_prompts_list(self) -> dict[str, Any]:
        if not self._prompts:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: prompts/list")
        return self._with_list_meta({"prompts": [p.to_wire() for p, _ in self._prompts.values()]})

    def _handle_prompts_get(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if not self._prompts:
            raise JsonRpcError(METHOD_NOT_FOUND, "Method not found: prompts/get")
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: missing prompt name")
        raw_args = params.get("arguments", {})
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, Mapping):
            raise JsonRpcError(INVALID_PARAMS, "Invalid params: arguments must be an object")
        entry = self._prompts.get(name)
        if entry is None:
            raise JsonRpcError(INVALID_PARAMS, f"Unknown prompt: {name}", {"name": name})
        prompt, handler = entry
        args: dict[str, str] = {}
        for key, val in raw_args.items():
            if not isinstance(val, str):
                raise JsonRpcError(INVALID_PARAMS, f"Prompt argument {key!r} must be a string")
            args[str(key)] = val
        for arg in prompt.arguments:
            if arg.required and (arg.name not in args or not args[arg.name].strip()):
                raise JsonRpcError(
                    INVALID_PARAMS,
                    f"Missing required prompt argument: {arg.name}",
                    {"argument": arg.name},
                )
        return _format_prompt_output(prompt.description, handler(args))

    def _dispatch(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        routes: dict[str, Callable[[], dict[str, Any]]] = {
            "initialize": lambda: self._handle_initialize(params),
            "ping": lambda: {},
            "server/discover": self._handle_discover,
            "tools/list": self._handle_tools_list,
            "tools/call": lambda: self._handle_tools_call(params),
            "resources/list": self._handle_resources_list,
            "resources/templates/list": self._handle_templates_list,
            "resources/read": lambda: self._handle_resources_read(params),
            "prompts/list": self._handle_prompts_list,
            "prompts/get": lambda: self._handle_prompts_get(params),
        }
        target = routes.get(method)
        if target is None:
            raise JsonRpcError(METHOD_NOT_FOUND, f"Method not found: {method}")
        return target()

    def handle_request(self, req: Any) -> dict[str, Any] | None:
        """Dispatch a decoded JSON-RPC 2.0 request dict; returns None for notifications."""
        if not isinstance(req, Mapping):
            return _rpc_error(None, INVALID_REQUEST, "Invalid Request")
        has_id = "id" in req
        req_id = req.get("id")
        method = req.get("method")
        if req.get("jsonrpc") != "2.0" or not isinstance(method, str) or not method.strip():
            return _rpc_error(req_id, INVALID_REQUEST, "Invalid Request")
        raw_params = req.get("params")
        if raw_params is not None and not isinstance(raw_params, Mapping):
            if not has_id:
                return None
            return _rpc_error(req_id, INVALID_PARAMS, "Invalid params: expected object")
        params: Mapping[str, Any] = raw_params if raw_params is not None else {}
        if not has_id:
            return None
        if method == "notifications/initialized":
            return _rpc_result(req_id, {})
        try:
            return _rpc_result(req_id, self._dispatch(method, params))
        except JsonRpcError as exc:
            return _rpc_error(req_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # noqa: BLE001
            return _rpc_error(req_id, INTERNAL_ERROR, f"Internal error: {exc}")

    def handle_json(self, raw: bytes | str) -> str | None:
        """Parse and dispatch a raw JSON-RPC 2.0 payload; returns None for notifications."""
        try:
            text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
            decoded = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return json.dumps(_rpc_error(None, PARSE_ERROR, "Parse error"))
        response = self.handle_request(decoded)
        return json.dumps(response) if response is not None else None

    def handle_http(
        self, raw: bytes | str, *, origin: str | None = None
    ) -> tuple[int, str | None]:
        """Validate HTTP Origin (when configured) and dispatch a Streamable HTTP payload."""
        if self.origin_guard is not None and not self.origin_guard.is_allowed(origin):
            body = json.dumps(_rpc_error(None, INVALID_REQUEST, "Forbidden Origin"))
            return 403, body
        response_json = self.handle_json(raw)
        if response_json is None:
            return 202, None
        return 200, response_json
