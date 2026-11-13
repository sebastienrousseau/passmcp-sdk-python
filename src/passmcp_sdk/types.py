# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Shared MCP protocol constants, wire types, and JSON-RPC error models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

REVISION_2026_07_28 = "2026-07-28"
REVISION_2025_11_25 = "2025-11-25"
REVISION_2025_06_18 = "2025-06-18"
SUPPORTED_REVISIONS: tuple[str, ...] = (
    REVISION_2026_07_28,
    REVISION_2025_11_25,
    REVISION_2025_06_18,
)

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
LEGACY_RESOURCE_NOT_FOUND = -32002
HEADER_MISMATCH = -32020

META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"


class JsonRpcError(Exception):
    """Structured JSON-RPC 2.0 protocol error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_wire(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            payload["data"] = self.data
        return payload


@dataclass(frozen=True)
class ToolAnnotations:
    """MCP tool behavioral annotations."""

    title: str | None = None
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None

    def to_wire(self, fallback_read_only: bool = False) -> dict[str, Any]:
        read_only = fallback_read_only if self.read_only_hint is None else self.read_only_hint
        wire: dict[str, Any] = {"readOnlyHint": read_only}
        if self.title is not None:
            wire["title"] = self.title
        if self.destructive_hint is not None:
            wire["destructiveHint"] = self.destructive_hint
        if self.idempotent_hint is not None:
            wire["idempotentHint"] = self.idempotent_hint
        if self.open_world_hint is not None:
            wire["openWorldHint"] = self.open_world_hint
        return wire


@dataclass(frozen=True)
class Tool:
    """MCP tool descriptor with explicit safety annotations and JSON schemas."""

    name: str
    description: str = ""
    read_only_hint: bool = False
    input_schema: Mapping[str, Any] | None = None
    output_schema: Mapping[str, Any] | None = None
    title: str | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None
    annotations: ToolAnnotations | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Tool.name must be a non-empty string")
        if not isinstance(self.read_only_hint, bool):
            raise ValueError("Tool.read_only_hint must be a bool")

    @property
    def is_read_only(self) -> bool:
        if self.annotations is not None and self.annotations.read_only_hint is not None:
            return self.annotations.read_only_hint is True
        return self.read_only_hint is True

    def _build_annotations_wire(self) -> dict[str, Any]:
        if self.annotations is not None:
            return self.annotations.to_wire(fallback_read_only=self.read_only_hint)
        ann = ToolAnnotations(
            title=self.title,
            read_only_hint=self.read_only_hint,
            destructive_hint=self.destructive_hint,
            idempotent_hint=self.idempotent_hint,
            open_world_hint=self.open_world_hint,
        )
        return ann.to_wire()

    def to_wire(self) -> dict[str, Any]:
        schema = (
            dict(self.input_schema)
            if self.input_schema is not None
            else {"type": "object", "properties": {}}
        )
        wire: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": schema,
            "annotations": self._build_annotations_wire(),
        }
        if self.title:
            wire["title"] = self.title
        if self.output_schema is not None:
            wire["outputSchema"] = dict(self.output_schema)
        return wire

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> Tool:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Wire tool entry is missing a non-empty name")
        ann = data.get("annotations")
        read_only = (
            isinstance(ann, Mapping) and ann.get("readOnlyHint") is True
        ) or data.get("readOnlyHint") is True
        in_schema = data.get("inputSchema")
        out_schema = data.get("outputSchema")
        desc = data.get("description")
        title = data.get("title")
        return cls(
            name=name,
            description=desc if isinstance(desc, str) else "",
            read_only_hint=read_only,
            input_schema=dict(in_schema) if isinstance(in_schema, Mapping) else None,
            output_schema=dict(out_schema) if isinstance(out_schema, Mapping) else None,
            title=title if isinstance(title, str) else None,
        )


@dataclass(frozen=True)
class CallToolResult:
    """Structured MCP tools/call result supporting text and structuredContent."""

    content: tuple[Mapping[str, Any], ...]
    structured_content: Mapping[str, Any] | None = None
    is_error: bool = False

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"content": [dict(item) for item in self.content]}
        if self.structured_content is not None:
            wire["structuredContent"] = dict(self.structured_content)
        if self.is_error:
            wire["isError"] = True
        return wire


@dataclass(frozen=True)
class Resource:
    """MCP static resource descriptor."""

    uri: str
    name: str
    description: str = ""
    mime_type: str = "text/plain"
    title: str | None = None

    def __post_init__(self) -> None:
        if not self.uri.strip() or not self.name.strip():
            raise ValueError("Resource.uri and Resource.name must be non-empty")

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {
            "uri": self.uri,
            "name": self.name,
            "mimeType": self.mime_type,
        }
        if self.title:
            wire["title"] = self.title
        if self.description:
            wire["description"] = self.description
        return wire


@dataclass(frozen=True)
class ResourceTemplate:
    """MCP URI-template resource descriptor."""

    uri_template: str
    name: str
    description: str = ""
    mime_type: str | None = None
    title: str | None = None

    def __post_init__(self) -> None:
        if not self.uri_template.strip() or not self.name.strip():
            raise ValueError("ResourceTemplate.uri_template and name must be non-empty")

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"uriTemplate": self.uri_template, "name": self.name}
        if self.title:
            wire["title"] = self.title
        if self.description:
            wire["description"] = self.description
        if self.mime_type:
            wire["mimeType"] = self.mime_type
        return wire


@dataclass(frozen=True)
class ResourceContent:
    """MCP resource read payload item."""

    uri: str
    text: str | None = None
    blob: str | None = None
    mime_type: str = "text/plain"

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"uri": self.uri, "mimeType": self.mime_type}
        if self.text is not None:
            wire["text"] = self.text
        if self.blob is not None:
            wire["blob"] = self.blob
        return wire


@dataclass(frozen=True)
class PromptArgument:
    """MCP prompt argument metadata."""

    name: str
    description: str = ""
    required: bool = False

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"name": self.name, "required": self.required}
        if self.description:
            wire["description"] = self.description
        return wire


@dataclass(frozen=True)
class Prompt:
    """MCP prompt descriptor."""

    name: str
    description: str = ""
    arguments: tuple[PromptArgument, ...] = field(default_factory=tuple)
    title: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Prompt.name must be non-empty")

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"name": self.name}
        if self.title:
            wire["title"] = self.title
        if self.description:
            wire["description"] = self.description
        if self.arguments:
            wire["arguments"] = [arg.to_wire() for arg in self.arguments]
        return wire


@dataclass(frozen=True)
class PromptMessage:
    """MCP prompt message item."""

    role: str
    text: str

    def to_wire(self) -> dict[str, Any]:
        return {"role": self.role, "content": {"type": "text", "text": self.text}}
