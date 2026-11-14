"""omega.federation_rate_limiter

Utility module providing a lightweight, thread‑safe rate‑limiter based on a token‑bucket
algorithm. It is intended for internal federation operations such as candidate
discovery, proposal submission and capability validation.

The limiter can be used directly via the ``RateLimiter`` class or through the
``@rate_limited`` decorator which applies a shared limiter to the decorated
callable.

Typical usage::

    from omega.federation_rate_limiter import rate_limited

    @rate_limited(calls=5, period=60)
    def fetch_candidate(...):
        ...

This will allow at most 5 calls per 60 seconds across all threads.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from functools import wraps
from typing import Callable, Deque, Optional

__all__ = ["RateLimiter", "rate_limited"]


class RateLimiter:
    """Thread‑safe token‑bucket rate limiter.

    Parameters
    ----------
    calls: int
        Maximum number of allowed calls within the given ``period``.
    period: float
        Time window in seconds over which ``calls`` are counted.
    """

    def __init__(self, calls: int, period: float) -> None:
        if calls <= 0:
            raise ValueError("calls must be a positive integer")
        if period <= 0:
            raise ValueError("period must be a positive number of seconds")
        self._max_calls: int = calls
        self._period: float = period
        self._lock = threading.Lock()
        # Store timestamps of recent successful calls
        self._timestamps: Deque[float] = deque()

    def _prune(self, now: float) -> None:
        """Remove timestamps older than the current period."""
        cutoff = now - self._period
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

    def allow(self) -> bool:
        """Return ``True`` if a call is permitted at the current moment.

        The method records the call timestamp when allowed. If the rate limit
        would be exceeded, it returns ``False`` without recording a timestamp.
        """
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            if len(self._timestamps) < self._max_calls:
                self._timestamps.append(now)
                return True
            return False

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Block until a call is allowed or ``timeout`` expires.

        Parameters
        ----------
        timeout: float or None
            Maximum time to wait in seconds. ``None`` means wait indefinitely.

        Returns
        -------
        bool
            ``True`` if the limiter granted permission before the timeout,
            ``False`` otherwise.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self.allow():
                return True
            # Compute sleep interval – a small fraction of the period for
            # responsiveness while avoiding busy‑waiting.
            sleep_sec = max(self._period / (self._max_calls * 2), 0.05)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                sleep_sec = min(sleep_sec, remaining)
            time.sleep(sleep_sec)


def rate_limited(calls: int, period: float, timeout: Optional[float] = None) -> Callable[[Callable], Callable]:
    """Decorator that applies a shared :class:`RateLimiter` to a function.

    Parameters
    ----------
    calls: int
        Maximum number of allowed invocations within ``period`` seconds.
    period: float
        Length of the time window in seconds.
    timeout: float or None, optional
        If provided, the wrapper will block up to ``timeout`` seconds waiting for
        the limiter to allow the call. When ``None`` (default) the call is
        dropped immediately if the limit is reached.
    """

    limiter = RateLimiter(calls, period)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if timeout is None:
                if not limiter.allow():
                    # Drop the call silently – caller can inspect return value
                    # to detect rate‑limit enforcement.
                    return None
                return func(*args, **kwargs)
            else:
                granted = limiter.wait(timeout)
                if not granted:
                    return None
                return func(*args, **kwargs)
        return wrapper
    return decorator
