"""
Guard client - Calls the PromptGuard Guard API for content scanning.

This is used internally by auto-instrumentation patches and framework
integrations. It sends messages to POST /api/v1/guard and returns the
decision (allow / block / redact).
"""

import asyncio
import logging
import threading
import weakref
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

import httpx

from promptguard._resolve import resolve_credentials
from promptguard._version import __version__

logger = logging.getLogger("promptguard")


def event_page_url(value: object) -> str | None:
    """A recorded event's dashboard page as the API returned it, or ``None``
    when it is absent, empty or not an absolute http(s) URL.

    Only a web URL is passed on: the value ends up in error messages and logs,
    and in whatever UI renders them as a link.
    """
    if not isinstance(value, str) or not value:
        return None
    # urlsplit silently drops tabs and newlines before parsing, but the raw
    # value is what gets returned: a URL carrying whitespace or a control
    # character could forge a log line, so it is refused outright.
    if any(ch.isspace() or not ch.isprintable() for ch in value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    return value if parts.scheme in ("http", "https") and parts.netloc else None


def event_ref(decision: "GuardDecision") -> str:
    """How a log line names a decision's event: its id, and its dashboard page
    when the Guard API returned one."""
    page = f", {decision.dashboard_url}" if decision.dashboard_url else ""
    return f"event={decision.event_id}{page}"


class GuardDecision:
    """Result of a guard API call."""

    __slots__ = (
        "confidence",
        "dashboard_url",
        "decision",
        "event_id",
        "latency_ms",
        "redacted_messages",
        "threat_type",
        "threats",
    )

    def __init__(self, data: dict[str, Any]):
        decision = data.get("decision")
        if decision not in ("allow", "block", "redact"):
            # Contract v1.4.0: a malformed/empty body must NOT silently
            # default to allow. Raise the API-error type so the caller's
            # explicit fail-open / fail-closed policy governs instead.
            raise GuardApiError(f"Guard API returned an unknown decision: {decision!r}")
        self.decision: str = decision
        self.event_id: str = data.get("event_id", "")
        # The recorded event's page in the dashboard, to open it from a log or
        # an error. None when the Guard API recorded no event (a pgshadow
        # doctor probe) or is an Engine too old to return the field.
        self.dashboard_url: str | None = event_page_url(data.get("dashboard_url"))
        self.confidence: float = data.get("confidence", 0.0)
        self.threat_type: str | None = data.get("threat_type")
        self.redacted_messages: list[dict[str, str]] | None = data.get("redacted_messages")
        self.threats: list[dict[str, Any]] = data.get("threats", [])
        self.latency_ms: float = data.get("latency_ms", 0.0)

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def redacted(self) -> bool:
        return self.decision == "redact"

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class PromptGuardBlockedError(Exception):
    """Raised when PromptGuard blocks a request in enforce mode.

    ``dashboard_url`` is the blocked request's event page in the dashboard, also
    named at the end of the message; ``None`` when the Guard API returned none
    (see ``GuardDecision.dashboard_url``).
    """

    def __init__(self, decision: GuardDecision):
        self.decision = decision
        self.dashboard_url: str | None = decision.dashboard_url
        threat = decision.threat_type or "policy_violation"
        page = f". Event: {decision.dashboard_url}" if decision.dashboard_url else ""
        super().__init__(
            f"PromptGuard blocked this request: {threat} "
            f"(confidence={decision.confidence:.2f}, event_id={decision.event_id}){page}"
        )


class GuardApiError(Exception):
    """Raised when the Guard API is unreachable or returns an error.

    Only surfaced when ``fail_open=False``.  When ``fail_open=True``
    (the default), callers catch this and return an allow decision.
    """

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


async def _silent_aclose(client: httpx.AsyncClient) -> None:
    """Await ``client.aclose()``, swallowing any failure (best-effort)."""
    try:
        await client.aclose()
    except Exception:
        logger.debug("Async Guard client close failed", exc_info=True)


async def _close_when_loop_shuts_down(
    owner: "weakref.ref[GuardClient]", loop_ref: "weakref.ref[asyncio.AbstractEventLoop]"
) -> AsyncIterator[None]:
    """Suspended until ``loop`` shuts down, then closes that loop's client on it.

    An event loop finalizes the async generators it is running before it
    closes: ``asyncio.run`` and ``asyncio.Runner`` call ``shutdown_asyncgens()``
    while the loop still runs. That is the last moment the client's sockets,
    which belong to that loop, can be closed cleanly; once the loop is closed
    no other loop can close them. ``asyncio.run(guard.scan_async(...))`` per
    request is the pattern that needs it.
    """
    try:
        yield
    finally:
        guard, loop = owner(), loop_ref()
        if guard is not None and loop is not None:
            with guard._client_lock:
                client = guard._async_clients.pop(loop, None)
                # Drop this generator: it holds the loop (through the loop's
                # asyncgen finalizer), so keeping it would keep the loop alive.
                guard._loop_closers.pop(id(loop), None)
            if client is not None:
                await _silent_aclose(client)


def _best_effort_close_orphan(client: httpx.AsyncClient) -> None:
    """Best-effort close of a client whose event loop is gone.

    Called from ``close()`` and from the ``weakref.finalize`` hook when a
    loop is garbage-collected.  Runs the aclose on the current loop if one
    is running here, otherwise on a throwaway loop; failures are swallowed.
    """
    if client.is_closed:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    try:
        if loop is not None and loop.is_running():
            loop.create_task(_silent_aclose(client))
        else:
            asyncio.run(client.aclose())
    except Exception:
        logger.debug("Best-effort async Guard client close failed", exc_info=True)


class GuardClient:
    """HTTP client for the PromptGuard Guard API.

    Provides both sync and async methods.  The client itself never
    swallows errors; callers (patches, integrations) decide whether
    to fail open or closed based on configuration.

    ``timeout`` defaults to ``10.0`` seconds, the Guard scan is a fast,
    standalone call.  (The proxy client / ``Config`` default is ``30.0`` because
    it fronts the full upstream LLM call.)  ``api_key`` / ``base_url`` fall back
    to ``PROMPTGUARD_API_KEY`` / ``PROMPTGUARD_BASE_URL`` when omitted.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 10.0,
    ):
        # Route through the shared resolver so a missing key falls back to
        # PROMPTGUARD_API_KEY and, if still absent, raises the same actionable
        # ValueError as every other entry point (rather than a bare TypeError).
        resolved_key, resolved_url = resolve_credentials(api_key, base_url)
        self._api_key = resolved_key
        self._guard_url = f"{resolved_url.rstrip('/')}/guard"
        self._timeout = timeout
        self._sync_client: httpx.Client | None = None
        # An httpx.AsyncClient is bound to the event loop it was created on,
        # so keep one client per live loop.  Two loops scanning concurrently
        # (e.g. threads each running asyncio.run) each get their own client
        # instead of displacing, and killing in-flight scans of: the other.
        # Weak keys let a garbage-collected loop drop its entry; the paired
        # ``weakref.finalize`` best-effort closes the evicted client.
        self._async_clients: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, httpx.AsyncClient
        ] = weakref.WeakKeyDictionary()
        # One suspended _close_when_loop_shuts_down generator per loop, keyed
        # by id(loop). Each holds its loop strongly (the loop's asyncgen
        # finalizer), so it must not be a value keyed weakly by that loop; it
        # removes itself when the loop shuts down, and close() drops the rest.
        # An id cannot be reused while its entry stands, because the entry
        # keeps the loop alive.
        self._loop_closers: dict[int, AsyncIterator[None]] = {}
        self._client_lock = threading.Lock()

    def _get_headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self._api_key,
            "Content-Type": "application/json",
            "X-PromptGuard-SDK": "python-auto",
            "X-PromptGuard-Version": __version__,
        }

    def _ensure_sync_client(self) -> httpx.Client:
        # Double-checked locking: avoid two threads each building a client and
        # leaking one.
        if self._sync_client is None:
            with self._client_lock:
                if self._sync_client is None:
                    self._sync_client = httpx.Client(timeout=self._timeout)
        return self._sync_client

    def _ensure_async_client(self) -> httpx.AsyncClient:
        """Return the async client bound to the *current* running loop.

        Each live event loop gets its own client (per-loop map), so a scan on
        loop B never closes a client with in-flight scans on loop A.
        """
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            # scan_async() is always awaited inside a loop; anything else is
            # a caller bug that must not silently build an unbound client.
            raise GuardApiError("GuardClient async API used outside a running event loop") from exc
        with self._client_lock:
            client = self._async_clients.get(current_loop)
            if client is None or client.is_closed:
                client = httpx.AsyncClient(timeout=self._timeout)
                try:
                    self._async_clients[current_loop] = client
                    # Best-effort close when the loop itself is evicted
                    # (garbage-collected) so its connection pool isn't leaked.
                    weakref.finalize(current_loop, _best_effort_close_orphan, client)
                except TypeError:
                    # Exotic non-weakrefable loop: fall back to an uncached
                    # client (closed by the httpx finalizer / GC).
                    logger.debug("Event loop is not weak-referenceable; client not cached")
        return client

    async def _close_with_loop(self) -> None:
        """Arrange for this loop's client to close when the loop shuts down."""
        loop = asyncio.get_running_loop()
        try:
            loop_ref = weakref.ref(loop)
        except TypeError:
            return  # non-weakrefable loop: the uncached client path applies
        with self._client_lock:
            if id(loop) in self._loop_closers:
                return
            closer = _close_when_loop_shuts_down(weakref.ref(self), loop_ref)
            self._loop_closers[id(loop)] = closer
        # Advancing it once registers it with this loop (the asyncgen hooks)
        # and parks it at its ``yield``.
        await closer.__anext__()

    @staticmethod
    def _schedule_aclose(client: httpx.AsyncClient, loop: asyncio.AbstractEventLoop | None) -> None:
        """Best-effort close of ``client`` on the ``loop`` it was bound to.

        Only attempts anything when that loop is still alive and running; the
        aclose() is scheduled thread-safely so it runs inside that loop.
        """
        if loop is None or loop.is_closed() or not loop.is_running():
            return
        try:
            loop.call_soon_threadsafe(lambda: loop.create_task(_silent_aclose(client)))
        except RuntimeError:
            # Loop stopped/closed between the check and the schedule.
            logger.debug("Could not schedule aclose on client's loop", exc_info=True)

    def _check_response(self, resp: httpx.Response) -> GuardDecision:
        """Validate response status and parse into a GuardDecision.

        A malformed 200 body (non-JSON, or JSON that isn't an object, or an
        unknown ``decision``) is converted to a ``GuardApiError`` so callers'
        fail-open / fail-closed handling applies instead of an unhandled
        ``JSONDecodeError`` / ``AttributeError`` escaping the wrapper.
        """
        if resp.status_code >= 400:
            raise GuardApiError(
                f"Guard API returned {resp.status_code}: {resp.text[:200]}",
                status_code=resp.status_code,
            )
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise GuardApiError(
                f"Guard API returned a non-JSON body: {exc}",
                status_code=resp.status_code,
            ) from exc
        if not isinstance(data, dict):
            raise GuardApiError(
                f"Guard API returned an unexpected body type: {type(data).__name__}",
                status_code=resp.status_code,
            )
        # GuardDecision itself rejects unknown decisions (contract v1.4.0);
        # attach the HTTP status for callers that inspect it.
        try:
            return GuardDecision(data)
        except GuardApiError as exc:
            raise GuardApiError(str(exc), status_code=resp.status_code) from exc

    def scan(
        self,
        messages: list[dict[str, str]],
        direction: str = "input",
        model: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> GuardDecision:
        """Synchronous scan via the guard API."""
        payload = self._build_payload(messages, direction, model, context)
        client = self._ensure_sync_client()
        try:
            resp = client.post(self._guard_url, json=payload, headers=self._get_headers())
        except Exception as exc:
            raise GuardApiError(f"Guard API call failed: {exc}") from exc
        return self._check_response(resp)

    async def scan_async(
        self,
        messages: list[dict[str, str]],
        direction: str = "input",
        model: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> GuardDecision:
        """Asynchronous scan via the guard API."""
        payload = self._build_payload(messages, direction, model, context)
        client = self._ensure_async_client()
        await self._close_with_loop()
        try:
            resp = await client.post(self._guard_url, json=payload, headers=self._get_headers())
        except Exception as exc:
            raise GuardApiError(f"Guard API call failed: {exc}") from exc
        return self._check_response(resp)

    @staticmethod
    def _build_payload(
        messages: list[dict[str, str]],
        direction: str,
        model: str | None,
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "messages": messages,
            "direction": direction,
        }
        if model:
            payload["model"] = model
        if context:
            payload["context"] = context
        return payload

    def __enter__(self) -> "GuardClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> "GuardClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def close(self) -> None:
        """Close the sync client and best-effort close all async clients.

        Safe to call from sync code (e.g. ``init()`` re-init and
        ``shutdown()``): each async client is closed on the loop it belongs
        to if that loop is still running, otherwise via a throwaway loop, and
        any failure is swallowed.
        """
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None
        for loop, client in self._drain_async_clients():
            self._best_effort_close_async(client, loop)

    def _drain_async_clients(
        self,
    ) -> list[tuple[asyncio.AbstractEventLoop, httpx.AsyncClient]]:
        """Atomically take ownership of every cached (loop, client) pair.

        Also drops the loop-shutdown closers: their clients are being closed
        here, and a closer left behind would keep its loop alive.
        """
        with self._client_lock:
            items = list(self._async_clients.items())
            self._async_clients.clear()
            self._loop_closers.clear()
        return items

    def _best_effort_close_async(
        self,
        client: httpx.AsyncClient,
        loop: asyncio.AbstractEventLoop | None,
    ) -> None:
        """Close ``client`` on its own ``loop`` when possible, else orphan-close."""
        if loop is not None and not loop.is_closed() and loop.is_running():
            self._schedule_aclose(client, loop)
            return
        _best_effort_close_orphan(client)

    async def aclose(self) -> None:
        """Async close: awaits the current loop's client, best-effort for others."""
        try:
            current_loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        for loop, client in self._drain_async_clients():
            if loop is current_loop:
                await _silent_aclose(client)
            else:
                self._best_effort_close_async(client, loop)
