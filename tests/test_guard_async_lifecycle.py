"""A GuardClient's async connections close even when their event loop ends first.

The customer pattern: one GuardClient for the process, used from sync code,
with ``asyncio.run(guard.scan_async(...))`` per request. Each ``asyncio.run``
creates a loop, scans, and closes the loop. The client's connection pool was
bound to that loop, so a later ``close()`` (or the loop's garbage collection)
could no longer close its socket, and Python reported an unclosed transport.

These tests run against a local HTTP server, so they need no network.
"""

import asyncio
import gc
import json
import threading
import warnings
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from promptguard import GuardClient

_ALLOW = {"decision": "allow", "event_id": "evt_test", "confidence": 0.0, "threats": []}


class _GuardHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, so the client pools the connection

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = json.dumps(_ALLOW).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GuardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/v1"
    finally:
        server.shutdown()
        server.server_close()


def _resource_warnings(action) -> list[str]:
    """Run ``action``, force collection, and return any ResourceWarning text."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        action()
        gc.collect()
        gc.collect()
    return [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]


def test_asyncio_run_per_scan_then_close_leaks_no_socket(base_url: str) -> None:
    def scenario() -> None:
        with GuardClient(api_key="pg_test", base_url=base_url) as guard:
            for _ in range(3):
                decision = asyncio.run(guard.scan_async([{"role": "user", "content": "hi"}]))
                assert decision.allowed

    assert _resource_warnings(scenario) == []


def test_loop_garbage_collected_before_close_leaks_no_socket(base_url: str) -> None:
    guard = GuardClient(api_key="pg_test", base_url=base_url)

    def scenario() -> None:
        asyncio.run(guard.scan_async([{"role": "user", "content": "hi"}]))
        # The loop is gone and collected before anyone calls close().

    try:
        assert _resource_warnings(scenario) == []
    finally:
        guard.close()


def test_client_is_reused_within_one_loop(base_url: str) -> None:
    async def two_scans(guard: GuardClient) -> None:
        await guard.scan_async([{"role": "user", "content": "a"}])
        first = guard._ensure_async_client()
        await guard.scan_async([{"role": "user", "content": "b"}])
        assert guard._ensure_async_client() is first

    with GuardClient(api_key="pg_test", base_url=base_url) as guard:
        asyncio.run(two_scans(guard))


def test_the_finished_loop_is_not_kept_alive(base_url: str) -> None:
    import weakref

    loops: list[weakref.ref[asyncio.AbstractEventLoop]] = []

    async def scan(guard: GuardClient) -> None:
        loops.append(weakref.ref(asyncio.get_running_loop()))
        await guard.scan_async([{"role": "user", "content": "hi"}])

    with GuardClient(api_key="pg_test", base_url=base_url) as guard:
        asyncio.run(scan(guard))
        gc.collect()
        assert loops[0]() is None


def test_a_client_replaced_on_the_same_loop_is_the_one_closed(base_url: str) -> None:
    async def replace_then_finish(guard: GuardClient) -> None:
        await guard.scan_async([{"role": "user", "content": "a"}])
        await guard._ensure_async_client().aclose()
        await guard.scan_async([{"role": "user", "content": "b"}])

    def scenario() -> None:
        with GuardClient(api_key="pg_test", base_url=base_url) as guard:
            asyncio.run(replace_then_finish(guard))

    assert _resource_warnings(scenario) == []
