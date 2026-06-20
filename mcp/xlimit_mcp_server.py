#!/usr/bin/env python3
"""
xLimit MCP server.

Exposes xLimit hosted synthesis (POST /proxy/synthesize) as a single MCP
tool, "xlimit_ask", over the stdio transport. Stdlib only, no mcp pip
package, no Node.

This is a different endpoint from client/xlimit_search.sh, which still
calls /search directly and returns raw ranked snippets. This server
returns synthesized prose guidance instead — see the tool description
below.

Protocol notes (MCP stdio transport):
    - Each JSON-RPC message is exactly one line of JSON on stdin/stdout.
    - stdout carries ONLY JSON-RPC messages; anything else (logs, errors)
      goes to stderr.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

TOKEN_FILE = Path.home() / ".config" / "xlimit" / "token.env"
SYNTHESIZE_URL = "https://api.xlimit.org/proxy/synthesize"
# Must stay above xlimit-agent's synthesis read timeout (currently 120s) so the two don't drift out of sync.
REQUEST_TIMEOUT_SECONDS = 150

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "xlimit"
SERVER_VERSION = "0.1.0"

TOOL_DEFINITION = {
    "name": "xlimit_ask",
    "description": (
        "Ask xLimit a security question and get back synthesized guidance "
        "that chains xLimit's methodology knowledge with real pattern and "
        "failure-mode experience. The response is prose guidance written "
        "to answer the question, not a list of raw reference snippets — "
        "treat it as advisory input to your own answer, not as source "
        "material to re-summarize, quote, or cite as a search result."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Natural language security question.",
            },
        },
        "required": ["query"],
    },
}


class XLimitToolError(Exception):
    """Raised for any condition that should surface as an MCP tool error."""


def read_token() -> str:
    if not TOKEN_FILE.is_file():
        raise XLimitToolError(f"token file not found at {TOKEN_FILE}")

    token = None
    for line in TOKEN_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("XLIMIT_API_TOKEN="):
            value = line.split("=", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            token = value

    if not token:
        raise XLimitToolError("XLIMIT_API_TOKEN is not set in token file")

    return token


def log_response_error(status: int, headers, raw_body: str) -> None:
    """Permanent stderr log for any non-2xx response, distinguishing a real
    xLimit API error (JSON body with a "detail" field) from an edge/transport
    block (e.g. a WAF returning a non-JSON page) so a future failure here
    doesn't need re-instrumenting to tell the two apart."""
    content_type = (headers.get("Content-Type") if headers else "") or ""
    if "application/json" in content_type.lower():
        try:
            detail = json.loads(raw_body).get("detail")
        except (json.JSONDecodeError, AttributeError):
            detail = None
        if detail is not None:
            print(f"xlimit_mcp_server: app-layer error (HTTP {status}): {detail}", file=sys.stderr)
            return
    print(f"xlimit_mcp_server: non-app-layer error (HTTP {status}): {raw_body[:100]!r}", file=sys.stderr)


def do_synthesize(query: str) -> dict:
    token = read_token()
    body = json.dumps({"query": query}).encode("utf-8")
    request = urllib.request.Request(
        SYNTHESIZE_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "xlimit-mcp-client/0.1.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = response.status
            raw_body = response.read().decode("utf-8", errors="replace")
            headers = response.headers
    except urllib.error.HTTPError as error:
        status = error.code
        raw_body = error.read().decode("utf-8", errors="replace")
        headers = error.headers
    except (urllib.error.URLError, TimeoutError) as error:
        raise XLimitToolError(f"network error contacting xLimit API: {error}")

    if status >= 400:
        log_response_error(status, headers, raw_body)

    if status in (401, 403):
        raise XLimitToolError("xLimit token expired or invalid — renew at app.xlimit.org")

    if status == 429:
        retry_after = headers.get("Retry-After") if headers else None
        message = "xLimit API rate limit exceeded (HTTP 429)"
        if retry_after:
            message += f", retry after {retry_after}s"
        raise XLimitToolError(message)

    if status >= 400:
        detail = None
        try:
            detail = json.loads(raw_body).get("detail")
        except (json.JSONDecodeError, AttributeError):
            pass
        message = f"xLimit API returned HTTP {status}"
        if detail:
            message += f": {detail}"
        raise XLimitToolError(message)

    try:
        return json.loads(raw_body)
    except json.JSONDecodeError:
        raise XLimitToolError("xLimit API returned a non-JSON response")


def format_answer(result: dict) -> str:
    answer = result.get("answer")
    if not answer:
        detail = result.get("detail")
        if detail:
            return f"xLimit returned: {detail}"
        return "No guidance returned."
    return answer


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def send_result(msg_id, result: dict) -> None:
    send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def send_tool_error(msg_id, text: str) -> None:
    send_result(msg_id, {"content": [{"type": "text", "text": text}], "isError": True})


def send_protocol_error(msg_id, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def handle_initialize(msg_id) -> None:
    send_result(
        msg_id,
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        },
    )


def handle_tools_list(msg_id) -> None:
    send_result(msg_id, {"tools": [TOOL_DEFINITION]})


def handle_tools_call(msg_id, params: dict) -> None:
    name = params.get("name")
    if name != "xlimit_ask":
        send_tool_error(msg_id, f"Unknown tool: {name}")
        return

    arguments = params.get("arguments") or {}
    query = arguments.get("query")

    if not query or not isinstance(query, str):
        send_tool_error(msg_id, "Missing required argument: query")
        return

    try:
        result = do_synthesize(query)
    except XLimitToolError as error:
        send_tool_error(msg_id, str(error))
        return
    except Exception as error:  # never let a tool call crash the server
        send_tool_error(msg_id, f"unexpected error calling xLimit API: {error}")
        return

    send_result(msg_id, {"content": [{"type": "text", "text": format_answer(result)}], "isError": False})


def handle_message(message: dict) -> None:
    method = message.get("method")
    has_id = "id" in message
    msg_id = message.get("id")

    try:
        if method == "initialize":
            handle_initialize(msg_id)
        elif method == "notifications/initialized":
            pass
        elif method == "ping":
            send_result(msg_id, {})
        elif method == "tools/list":
            handle_tools_list(msg_id)
        elif method == "tools/call":
            handle_tools_call(msg_id, message.get("params") or {})
        elif has_id:
            send_protocol_error(msg_id, -32601, f"Method not found: {method}")
        # unknown notifications (no id) are silently ignored per JSON-RPC
    except Exception as error:  # last-resort guard: never crash the server
        print(f"xlimit_mcp_server: unhandled error in {method}: {error}", file=sys.stderr)
        if has_id:
            send_protocol_error(msg_id, -32603, f"Internal error: {error}")


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if line == "":
            break  # EOF: client closed stdin
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            print(f"xlimit_mcp_server: ignoring malformed JSON-RPC line: {line!r}", file=sys.stderr)
            continue
        handle_message(message)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
