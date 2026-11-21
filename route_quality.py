"""Bounded, process-local Tor subscription measurements; never mining traffic."""
from collections import deque
import math
import statistics
import time

SAMPLE_LIMIT = 5
MIN_SAMPLES = 3
MAX_AGE = 900
PROBE_TIMEOUT = 20
PROBE_INTERVAL = 300
WARMUP_INTERVAL = 15
MIN_ADVANTAGE_MS = 100
MIN_ADVANTAGE_RATIO = 0.20
SUBSCRIBE = b'{"id":43,"method":"mining.subscribe","params":["arkpool-route-check"]}\n'


async def subscription_probe(connect, validate, close):
    """Caller bounds the complete operation; only subscribe, never authorize/submit."""
    writer = None
    started = time.monotonic()
    try:
        reader, writer = await connect()
        writer.write(SUBSCRIBE)
        await writer.drain()
        for _ in range(8):
            frame = validate(await reader.readline())
            if type(frame.get('id')) is int and frame['id'] == 43:
                result = frame.get('result')
                if ('method' in frame or frame.get('error') is not None
                        or not isinstance(result, list) or len(result) != 3
                        or not isinstance(result[0], list)
                        or not isinstance(result[1], str)
                        or len(result[1]) > 128 or len(result[1]) % 2
                        or any(c not in '0123456789abcdefABCDEF' for c in result[1])
                        or type(result[2]) is not int or not 1 <= result[2] <= 32):
                    raise ValueError('invalid subscription response')
                return (time.monotonic() - started) * 1000
        raise ValueError('subscription response missing')
    finally:
        if writer is not None:
            await close(writer)


class RouteQuality:
    def __init__(self):
        self.samples = {}

    def record(self, route, latency_ms, now=None):
        if latency_ms is not None and (type(latency_ms) not in (float, int)
                or not math.isfinite(latency_ms) or not 0 <= latency_ms <= PROBE_TIMEOUT * 1000):
            raise ValueError('invalid probe timing')
        now = time.monotonic() if now is None else now
        self.samples.setdefault(route, deque(maxlen=SAMPLE_LIMIT)).append((now, latency_ms))

    def snapshot(self, route, now=None):
        now = time.monotonic() if now is None else now
        rows = [(at, ms) for at, ms in self.samples.get(route, ()) if 0 <= now - at <= MAX_AGE]
        good = [ms for _, ms in rows if ms is not None]
        return {'samples': len(rows), 'successes': len(good),
                'last_success': rows[-1][1] is not None if rows else None,
                'median_ms': round(statistics.median(good), 1) if good else None,
                'last_sample_age_seconds': round(now - rows[-1][0], 1) if rows else None}

    def preference(self, ready, now=None):
        """Return a preference, not an eligibility decision or a connection change."""
        now = time.monotonic() if now is None else now
        if not ready:
            return None, 'no_ready'
        if len(ready) == 1:
            return ready[0], 'single_ready'
        values = {route: self.snapshot(route, now) for route in ready}
        if any(value['samples'] < MIN_SAMPLES for value in values.values()):
            return None, 'warming_up'
        # A recent failed probe cannot earn speed preference from older successes.
        reliable = [r for r in ready if values[r]['successes'] >= MIN_SAMPLES
                    and values[r]['last_success']]
        if not reliable:
            return None, 'insufficient_successes'
        rates = {r: values[r]['successes'] / values[r]['samples'] for r in ready}
        best = max(reliable, key=lambda r: rates[r])
        others = [r for r in ready if r != best]
        if all(rates[best] - rates[r] >= MIN_ADVANTAGE_RATIO - 1e-9 for r in others):
            return best, 'more_reliable'
        if len(reliable) != len(ready) or len(set(rates.values())) != 1:
            return None, 'similar'
        fastest = min(ready, key=lambda r: values[r]['median_ms'])
        fast_ms = values[fastest]['median_ms']
        if all(values[r]['median_ms'] - fast_ms >= max(
                MIN_ADVANTAGE_MS, values[r]['median_ms'] * MIN_ADVANTAGE_RATIO)
               for r in ready if r != fastest):
            return fastest, 'faster'
        return None, 'similar'
