from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


def _make_access_line(
    ts: datetime,
    ip: str,
    method: str,
    path: str,
    status: int,
    bytes_sent: int,
    ua: str,
    duration_ms: float,
) -> str:
    # Apache combined date: 10/Oct/2000:13:55:36 -0700
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{ua}" '
        f"rt={duration_ms:.1f}ms"
    )


def generate_sample_log_text(
    minutes: int = 180,
    base_rps: float = 1.2,
    anomaly_minute: int = 120,
) -> str:
    rng = random.Random(42)
    now = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0)
    start = now - timedelta(minutes=minutes)

    paths = ["/", "/login", "/api/search", "/api/items", "/checkout", "/healthz"]
    agents = ["Mozilla/5.0", "curl/8.0", "python-requests/2.31"]
    methods = ["GET", "POST"]

    lines: list[str] = []
    for i in range(minutes):
        ts = start + timedelta(minutes=i)
        minute_load = base_rps * 60.0
        if i == anomaly_minute:
            minute_load *= 8.0

        n = int(rng.gauss(mu=minute_load, sigma=max(5.0, minute_load * 0.1)))
        n = max(0, n)

        for _ in range(n):
            ip = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
            path = rng.choice(paths)
            method = rng.choice(methods)
            ua = rng.choice(agents)

            status = 200
            duration_ms = abs(rng.gauss(55, 25))
            if i == anomaly_minute:
                if rng.random() < 0.35:
                    status = rng.choice([500, 502, 503, 504])
                    duration_ms += abs(rng.gauss(900, 400))
            else:
                if rng.random() < 0.02:
                    status = 500
                    duration_ms += abs(rng.gauss(300, 150))

            bytes_sent = int(max(0, rng.gauss(1500, 800)))
            lines.append(_make_access_line(ts, ip, method, path, status, bytes_sent, ua, duration_ms))

    return "\n".join(lines) + "\n"


def get_bundled_sample_log_text() -> str:
    return generate_sample_log_text()

