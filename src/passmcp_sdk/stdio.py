# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Newline-delimited UTF-8 JSON-RPC 2.0 stdio server and client transports."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

from passmcp_sdk.server import McpServer
from passmcp_sdk.types import INTERNAL_ERROR, JsonRpcError


def serve_stdio(
    server: McpServer,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Serve newline-delimited JSON-RPC 2.0 over stdio until EOF without stray stdout bytes."""
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    for raw_line in in_stream:
        stripped = raw_line.strip()
        if not stripped:
            continue
        response = server.handle_json(stripped)
        if response is None:
            continue
        compact = response.replace("\r", "").replace("\n", "")
        out_stream.write(compact + "\n")
        out_stream.flush()


class StdioTransport:
    """Line-delimited JSON-RPC 2.0 client transport over streams or a child process."""

    def __init__(
        self,
        writer: TextIO,
        reader: TextIO,
        *,
        process: subprocess.Popen[str] | None = None,
        worker: threading.Thread | None = None,
    ) -> None:
        self._writer = writer
        self._reader = reader
        self._process = process
        self._worker = worker
        self._closed = False

    @classmethod
    def from_streams(cls, writer: TextIO, reader: TextIO) -> StdioTransport:
        """Bind a StdioTransport to an existing (writer, reader) text stream pair."""
        return cls(writer, reader)

    @classmethod
    def from_in_memory_server(cls, server: McpServer) -> StdioTransport:
        """Run serve_stdio(server) in a background thread over OS pipe streams."""
        c2s_r, c2s_w = os.pipe()
        s2c_r, s2c_w = os.pipe()
        server_in = io.TextIOWrapper(os.fdopen(c2s_r, "rb"), encoding="utf-8", line_buffering=True)
        client_out = io.TextIOWrapper(os.fdopen(c2s_w, "wb"), encoding="utf-8", line_buffering=True)
        client_in = io.TextIOWrapper(os.fdopen(s2c_r, "rb"), encoding="utf-8", line_buffering=True)
        server_out = io.TextIOWrapper(os.fdopen(s2c_w, "wb"), encoding="utf-8", line_buffering=True)

        def _run() -> None:
            try:
                serve_stdio(server, stdin=server_in, stdout=server_out)
            finally:
                server_in.close()
                server_out.close()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        return cls(client_out, client_in, worker=thread)

    @classmethod
    def spawn(
        cls,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> StdioTransport:
        """Spawn a child MCP stdio server process over UTF-8 stdin/stdout pipes."""
        if not command:
            raise ValueError("StdioTransport.spawn requires a non-empty command sequence")
        proc = subprocess.Popen(  # noqa: S603
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=dict(env) if env is not None else None,
            cwd=cwd,
        )
        assert proc.stdin is not None and proc.stdout is not None
        return cls(proc.stdin, proc.stdout, process=proc)

    def __call__(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if self._closed:
            raise JsonRpcError(INTERNAL_ERROR, "StdioTransport is closed")
        frame = json.dumps(request, separators=(",", ":")) + "\n"
        self._writer.write(frame)
        self._writer.flush()
        if "id" not in request:
            return None
        line = self._reader.readline()
        if not line:
            raise JsonRpcError(INTERNAL_ERROR, "Unexpected EOF on stdio transport")
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise JsonRpcError(
                INTERNAL_ERROR, f"Invalid JSON frame from stdio server: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise JsonRpcError(INTERNAL_ERROR, "Non-object JSON-RPC frame from stdio server")
        return decoded

    def close(self) -> None:
        """Close stdin/stdout streams and terminate any spawned child process."""
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
        except OSError:
            pass
        if self._process is not None:
            try:
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            if self._process.stderr is not None:
                self._process.stderr.close()
        if self._worker is not None:
            self._worker.join(timeout=2.0)
        try:
            self._reader.close()
        except OSError:
            pass

    def __enter__(self) -> StdioTransport:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
