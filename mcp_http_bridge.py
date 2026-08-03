#!/usr/bin/env python3
"""Generic stdio <-> Streamable-HTTP MCP bridge for guest VM MCP servers.

Why this exists: guest MCP servers on this setup serve MCP directly over HTTP
(e.g. windbg mcp-windbg at http://<GUEST>:8000/mcp, IDA zeromcp at :13337/mcp).
Pointing Claude Code / Codex at that URL directly does NOT work on this host:
their node/electron network stack gets EHOSTUNREACH to the VMware host-only guest
(only curl/python can reach it). radare2's MCP works because it is a *local*
python stdio server that does the VM HTTP itself.

This bridge does the same for any streamable-http MCP endpoint: the AI client
launches it over stdio; this process (python, which CAN reach the guest)
transparently relays MCP JSON-RPC messages to the guest's /mcp endpoint, carrying
the Mcp-Session-Id. No extra deps — stdlib only.

Register as a stdio MCP server (target URL via argv[1] or MCP_HTTP_URL env):
  command = <malware venv python>, args = [<this file>, "http://172.16.217.129:8000/mcp"]

This is a generic copy of ida_mcp_bridge.py; use one instance per target URL.
"""
import json
import os
import sys
import urllib.request
import urllib.error

TARGET = (
    sys.argv[1] if len(sys.argv) > 1
    else os.environ.get("MCP_HTTP_URL", "http://172.16.217.129:8000/mcp")
)
PROTOCOL_VERSION = "2025-06-18"

_session_id = None


def _log(msg):
    # stderr only — never pollute the stdio JSON-RPC channel on stdout
    print(f"[mcp-bridge] {msg}", file=sys.stderr, flush=True)


def _post(raw_body: bytes):
    """POST one JSON-RPC message to the guest; return (status, headers, body_bytes)."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
    }
    if _session_id:
        headers["Mcp-Session-Id"] = _session_id
    req = urllib.request.Request(TARGET, data=raw_body, headers=headers, method="POST")
    resp = urllib.request.urlopen(req, timeout=120)
    return resp.status, resp.headers, resp.read()


def _extract_json_messages(content_type: str, body: bytes):
    """Guest returns either application/json (one object) or text/event-stream (SSE).
    Yield each JSON-RPC message as bytes (no trailing newline)."""
    ct = (content_type or "").lower()
    if "text/event-stream" in ct:
        for line in body.split(b"\n"):
            line = line.strip()
            if line.startswith(b"data:"):
                data = line[5:].strip()
                if data and data != b"[DONE]":
                    yield data
    else:
        body = body.strip()
        if body:
            yield body


def main():
    global _session_id
    _log(f"target={TARGET}")
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:
            _log(f"bad JSON from client, skipping: {e}")
            continue

        is_request = isinstance(msg, dict) and ("id" in msg)
        method = msg.get("method") if isinstance(msg, dict) else None

        try:
            status, headers, body = _post(line)
        except urllib.error.HTTPError as e:
            body = e.read()
            status, headers = e.code, e.headers
        except Exception as e:
            _log(f"POST failed for method={method}: {e}")
            if is_request:
                err = {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32001, "message": f"bridge transport error: {e}"},
                }
                stdout.write(json.dumps(err).encode() + b"\n")
                stdout.flush()
            continue

        # Capture session id from the initialize response so later calls reuse it.
        if method == "initialize":
            sid = headers.get("Mcp-Session-Id") if headers else None
            if sid:
                _session_id = sid
                _log(f"session established: {sid}")

        # Notifications (no id) expect no response body relayed to the client.
        if not is_request:
            continue

        for out in _extract_json_messages(
            headers.get("Content-Type") if headers else "application/json", body
        ):
            stdout.write(out + b"\n")
        stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
