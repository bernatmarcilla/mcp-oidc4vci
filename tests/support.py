"""Shared test helpers for mocking outbound HTTP calls."""

from collections.abc import Callable

import httpx


def mock_async_client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[..., httpx.AsyncClient]:
    """Build a patch target for `httpx.AsyncClient` that routes requests through a MockTransport."""
    original_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original_async_client(*args, **kwargs)  # type: ignore[arg-type]

    return factory
