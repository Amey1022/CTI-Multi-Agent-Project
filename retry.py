"""Retry helper for LLM rate limits (HTTP 429)."""

import re
import time


def _wait_seconds(message, default=15.0):

    """Reads 'try again in 1m3.5s' / '7.5s' / '350ms' from a Groq error."""

    m = re.search(r"try again in\s*(?:(\d+)m)?\s*([\d.]+)\s*(ms|s)", message)

    if not m:
        return default

    minutes = int(m.group(1) or 0)
    value = float(m.group(2))

    seconds = value / 1000 if m.group(3) == "ms" else value

    return minutes * 60 + seconds + 0.5


def call_with_retry(fn, retries=2, max_wait=45.0, sleep=time.sleep):

    """
    Calls fn(); on a rate-limit error waits the time the API asks for
    (capped at max_wait) and tries again, up to `retries` times.
    Any other error is raised immediately.
    """

    for attempt in range(retries + 1):

        try:
            return fn()

        except Exception as error:

            message = str(error).lower()

            limited = ("429" in message or "rate limit" in message
                       or "rate_limit" in message)

            if not limited or attempt == retries:
                raise

            wait = min(_wait_seconds(message), max_wait)
            print(f"Rate limited; waiting {wait:.1f}s "
                  f"(retry {attempt + 1}/{retries})...")
            sleep(wait)
