# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""OAuth 2.1 S256 PKCE, WWW-Authenticate Bearer challenges, RFC 9728, and RFC 8414."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PKCE_UNRESERVED_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^\s,]+))')


class OAuthError(ValueError):
    """Raised when PKCE, challenge, or OAuth metadata validation fails."""


@dataclass(frozen=True)
class BearerChallenge:
    """Parsed HTTP WWW-Authenticate Bearer challenge parameters."""

    resource_metadata: str = ""
    scope: str = ""
    error: str = ""
    error_description: str = ""


@dataclass(frozen=True)
class ProtectedResourceMetadata:
    """Validated RFC 9728 OAuth 2.0 Protected Resource Metadata."""

    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: tuple[str, ...] = ()
    bearer_methods_supported: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizationServerMetadata:
    """Validated RFC 8414 OAuth 2.1 Authorization Server Metadata."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    code_challenge_methods_supported: tuple[str, ...]
    registration_endpoint: str = ""
    scopes_supported: tuple[str, ...] = ()


def generate_pkce_verifier(length: int = 64) -> str:
    """Generate an RFC 7636 PKCE code_verifier of 43..128 URL-safe base64url chars."""
    if isinstance(length, bool) or not isinstance(length, int) or not (43 <= length <= 128):
        raise OAuthError("PKCE code_verifier length must be between 43 and 128 characters")
    raw_bytes = secrets.token_bytes(96)
    encoded = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
    return encoded[:length]


def compute_s256_challenge(verifier: str) -> str:
    """Compute BASE64URL-NOPAD(SHA256(verifier)) per RFC 7636 S256."""
    if not isinstance(verifier, str) or not PKCE_UNRESERVED_RE.match(verifier):
        raise OAuthError("PKCE code_verifier must be 43..128 RFC 7636 unreserved characters")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_s256(verifier: str, challenge: str) -> bool:
    """Constant-time verification of an RFC 7636 S256 PKCE verifier against challenge."""
    if not isinstance(challenge, str) or not challenge.strip():
        return False
    try:
        expected = compute_s256_challenge(verifier)
    except OAuthError:
        return False
    return hmac.compare_digest(expected, challenge)


def _escape_quoted(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"')


def build_bearer_challenge(
    *,
    resource_metadata: str = "",
    scope: str = "",
    error: str = "",
    error_description: str = "",
) -> str:
    """Format an HTTP WWW-Authenticate Bearer challenge header value."""
    params: list[str] = []
    for key, val in (
        ("resource_metadata", resource_metadata),
        ("scope", scope),
        ("error", error),
        ("error_description", error_description),
    ):
        if val:
            params.append(f'{key}="{_escape_quoted(val)}"')
    return "Bearer" if not params else "Bearer " + ", ".join(params)


def parse_bearer_challenge(header_value: str) -> BearerChallenge:
    """Parse an HTTP WWW-Authenticate Bearer challenge header."""
    if not isinstance(header_value, str):
        raise OAuthError("WWW-Authenticate header must be a string")
    trimmed = header_value.strip()
    if not trimmed.lower().startswith("bearer"):
        raise OAuthError("WWW-Authenticate header does not start with Bearer scheme")
    rest = trimmed[6:].strip()
    if rest and not (header_value.strip()[6:7].isspace() or rest == ""):
        raise OAuthError("Invalid scheme prefix in WWW-Authenticate header")
    parsed: dict[str, str] = {}
    for match in AUTH_PARAM_RE.finditer(rest):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else (match.group(3) or "")
        parsed[key] = val
    return BearerChallenge(
        resource_metadata=parsed.get("resource_metadata", ""),
        scope=parsed.get("scope", ""),
        error=parsed.get("error", ""),
        error_description=parsed.get("error_description", ""),
    )


def _parse_https_url(
    url: str, label: str, *, allow_http_loopback: bool = False
) -> tuple[str, str, str]:
    if not isinstance(url, str) or not url.strip():
        raise OAuthError(f"{label} must be a non-empty URL")
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    loopback = (
        allow_http_loopback
        and parts.scheme == "http"
        and host in {"127.0.0.1", "localhost", "::1"}
    )
    if (parts.scheme != "https" and not loopback) or not parts.netloc:
        raise OAuthError(f"{label} must use https:// (got {url!r})")
    if parts.query or parts.fragment:
        raise OAuthError(f"{label} must not carry query or fragment: {url!r}")
    return parts.scheme.lower(), parts.netloc.lower(), parts.path


def protected_resource_metadata_urls(resource_url: str) -> tuple[str, ...]:
    """Derive RFC 9728 §3.1 well-known Protected Resource Metadata URLs (path-suffixed + root)."""
    scheme, netloc, path = _parse_https_url(
        resource_url, "resource URL", allow_http_loopback=True
    )
    clean_path = path.rstrip("/")
    root_url = urlunsplit((scheme, netloc, "/.well-known/oauth-protected-resource", "", ""))
    if not clean_path:
        return (root_url,)
    suffixed = urlunsplit(
        (scheme, netloc, f"/.well-known/oauth-protected-resource{clean_path}", "", "")
    )
    return (suffixed, root_url)


def protected_resource_metadata_url(resource_url: str) -> str:
    """Return the primary RFC 9728 §3.1 well-known Protected Resource Metadata URL."""
    return protected_resource_metadata_urls(resource_url)[0]


def authorization_server_metadata_url(issuer_url: str) -> str:
    """Derive the RFC 8414 §3 well-known Authorization Server Metadata URL."""
    scheme, netloc, path = _parse_https_url(issuer_url, "issuer URL")
    clean_path = path.rstrip("/")
    well_known = (
        f"/.well-known/oauth-authorization-server{clean_path}"
        if clean_path
        else "/.well-known/oauth-authorization-server"
    )
    return urlunsplit((scheme, netloc, well_known, "", ""))


def _decode_json_mapping(raw: bytes | str | Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if isinstance(raw, Mapping):
        return raw
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        decoded = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OAuthError(f"Invalid {label} JSON: {exc}") from exc
    if not isinstance(decoded, Mapping):
        raise OAuthError(f"{label} root must be a JSON object")
    return decoded


def _str_tuple(obj: Mapping[str, Any], key: str) -> tuple[str, ...]:
    raw = obj.get(key)
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) and x.strip() for x in raw):
        raise OAuthError(f"{key} must be an array of non-empty strings")
    return tuple(raw)


def _canonical_resource(url: str) -> str:
    scheme, netloc, path = _parse_https_url(url, "resource", allow_http_loopback=True)
    normalized_path = path.rstrip("/") if path != "/" else ""
    return urlunsplit((scheme, netloc, normalized_path, "", ""))


def validate_protected_resource_metadata(
    raw: bytes | str | Mapping[str, Any], expected_resource: str
) -> ProtectedResourceMetadata:
    """Validate RFC 9728 Protected Resource Metadata and enforce strict resource binding."""
    doc = _decode_json_mapping(raw, "Protected Resource Metadata")
    resource = doc.get("resource")
    if not isinstance(resource, str) or not resource.strip():
        raise OAuthError("Protected Resource Metadata is missing 'resource'")
    if _canonical_resource(resource) != _canonical_resource(expected_resource):
        raise OAuthError(
            f"Protected Resource Metadata resource mismatch: got {resource!r}, "
            f"expected {expected_resource!r}"
        )
    auth_servers = _str_tuple(doc, "authorization_servers")
    if not auth_servers:
        raise OAuthError("Protected Resource Metadata requires at least one authorization_server")
    for srv in auth_servers:
        _parse_https_url(srv, "authorization_server")
    return ProtectedResourceMetadata(
        resource=resource,
        authorization_servers=auth_servers,
        scopes_supported=_str_tuple(doc, "scopes_supported"),
        bearer_methods_supported=_str_tuple(doc, "bearer_methods_supported"),
    )


def validate_authorization_server_metadata(
    raw: bytes | str | Mapping[str, Any], expected_issuer: str | None = None
) -> AuthorizationServerMetadata:
    """Validate RFC 8414 Authorization Server Metadata against OAuth 2.1 S256 requirements."""
    doc = _decode_json_mapping(raw, "Authorization Server Metadata")
    issuer = doc.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip():
        raise OAuthError("Authorization Server Metadata is missing 'issuer'")
    _parse_https_url(issuer, "issuer")
    if expected_issuer is not None and issuer.rstrip("/") != expected_issuer.rstrip("/"):
        raise OAuthError(f"Issuer mismatch: got {issuer!r}, expected {expected_issuer!r}")
    auth_ep = doc.get("authorization_endpoint")
    token_ep = doc.get("token_endpoint")
    if not isinstance(auth_ep, str) or not auth_ep.strip():
        raise OAuthError("Authorization Server Metadata is missing 'authorization_endpoint'")
    if not isinstance(token_ep, str) or not token_ep.strip():
        raise OAuthError("Authorization Server Metadata is missing 'token_endpoint'")
    _parse_https_url(auth_ep, "authorization_endpoint", allow_http_loopback=True)
    _parse_https_url(token_ep, "token_endpoint", allow_http_loopback=True)
    methods = _str_tuple(doc, "code_challenge_methods_supported")
    if "S256" not in methods:
        raise OAuthError(
            "OAuth 2.1 requires 'S256' in code_challenge_methods_supported"
        )
    reg_ep = doc.get("registration_endpoint", "")
    if reg_ep is not None and not isinstance(reg_ep, str):
        raise OAuthError("registration_endpoint must be a string")
    return AuthorizationServerMetadata(
        issuer=issuer,
        authorization_endpoint=auth_ep,
        token_endpoint=token_ep,
        code_challenge_methods_supported=methods,
        registration_endpoint=reg_ep or "",
        scopes_supported=_str_tuple(doc, "scopes_supported"),
    )
