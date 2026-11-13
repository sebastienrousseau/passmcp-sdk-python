# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""SEP-2549 cache hints and JSON Schema validation for MCP tool calls."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from passmcp_sdk.types import INVALID_PARAMS, JsonRpcError

VALID_CACHE_SCOPES = frozenset({"public", "private"})


class CacheHints:
    """SEP-2549 list response cache metadata supporting ttl_ms or (cacheable, ttl, scope)."""

    def __init__(
        self,
        ttl_ms: int | None = None,
        cache_scope: str | None = None,
        *,
        cacheable: bool | None = None,
        ttl: int | None = None,
        scope: str | None = None,
    ) -> None:
        resolved_scope = scope if scope is not None else (cache_scope or "private")
        resolved_ms = _resolve_ttl_ms(ttl_ms=ttl_ms, cacheable=cacheable, ttl=ttl)
        if resolved_scope not in VALID_CACHE_SCOPES:
            raise ValueError("CacheHints.cache_scope must be 'public' or 'private'")
        self.ttl_ms = resolved_ms
        self.cache_scope = resolved_scope

    @property
    def cacheable(self) -> bool:
        return self.ttl_ms > 0

    @property
    def ttl(self) -> int:
        return self.ttl_ms // 1000

    @property
    def scope(self) -> str:
        return self.cache_scope

    def to_meta(self) -> dict[str, Any]:
        return {"ttlMs": self.ttl_ms, "cacheScope": self.cache_scope}

    def apply_to_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload["ttlMs"] = self.ttl_ms
        payload["cacheScope"] = self.cache_scope
        payload["_meta"] = self.to_meta()
        return payload


def _resolve_ttl_ms(
    *, ttl_ms: int | None, cacheable: bool | None, ttl: int | None
) -> int:
    if ttl_ms is not None:
        if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int) or ttl_ms < 0:
            raise ValueError("CacheHints.ttl_ms must be an integer >= 0")
        return 0 if cacheable is False else ttl_ms
    if ttl is not None:
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
            raise ValueError("CacheHints.ttl must be an integer >= 0")
        return 0 if cacheable is False else ttl * 1000
    if cacheable is False:
        return 0
    raise ValueError("CacheHints requires ttl_ms, ttl, or cacheable=False")


def _matches_json_type(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return not isinstance(value, bool) and isinstance(value, int)
    if expected == "number":
        return not isinstance(value, bool) and isinstance(value, (int, float))
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    return True


def _validate_property_value(key: str, prop_schema: Mapping[str, Any], value: Any) -> None:
    expected = prop_schema.get("type")
    if isinstance(expected, str) and not _matches_json_type(expected, value):
        raise JsonRpcError(
            INVALID_PARAMS,
            f"Invalid argument {key!r}: expected {expected}",
            {"argument": key, "expected": expected},
        )
    if isinstance(expected, list) and not any(
        isinstance(t, str) and _matches_json_type(t, value) for t in expected
    ):
        raise JsonRpcError(
            INVALID_PARAMS,
            f"Invalid argument {key!r}: wrong type",
            {"argument": key},
        )
    allowed = prop_schema.get("enum")
    if isinstance(allowed, list) and value not in allowed:
        raise JsonRpcError(
            INVALID_PARAMS,
            f"Invalid argument {key!r}: value not in enum",
            {"argument": key},
        )


def validate_object_schema(
    schema: Mapping[str, Any] | None, arguments: Mapping[str, Any]
) -> None:
    """Validate MCP tool call arguments against an object JSON Schema."""
    if schema is None:
        return
    required = schema.get("required")
    if isinstance(required, list):
        for req_key in required:
            if isinstance(req_key, str) and req_key not in arguments:
                raise JsonRpcError(
                    INVALID_PARAMS,
                    f"Missing required argument: {req_key}",
                    {"argument": req_key},
                )
    raw_props = schema.get("properties")
    props: Mapping[str, Any] = raw_props if isinstance(raw_props, Mapping) else {}
    if schema.get("additionalProperties") is False:
        for key in arguments:
            if key not in props:
                raise JsonRpcError(
                    INVALID_PARAMS,
                    f"Unexpected argument: {key}",
                    {"argument": key},
                )
    for key, val in arguments.items():
        prop_schema = props.get(key)
        if isinstance(prop_schema, Mapping):
            _validate_property_value(key, prop_schema, val)
