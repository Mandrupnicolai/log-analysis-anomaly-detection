from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

import pandas as pd


_APACHE_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+\S+)?"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
    r"(?:\s+(?P<rest>.*))?$"
)

_GENERIC_TS_LEVEL = re.compile(
    r"^(?P<ts>"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{3,6})?"
    r"(?:Z|[+-]\d{2}:\d{2})?"
    r")\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b"
    r"[:\s-]+(?P<msg>.*)$",
    re.IGNORECASE,
)

_DURATION_MS = re.compile(
    r"\b(?:duration|latency|response_time|responsetime|rt|took)\b\s*[:=]?\s*(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>ms|s)?\b",
    re.IGNORECASE,
)

_STATUS_IN_LINE = re.compile(r"\bstatus\s*[:=]\s*(\d{3})\b", re.IGNORECASE)


def _parse_isoish_timestamp(value: str) -> datetime | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    raw = raw.replace(",", ".")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_apache_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None


def _duration_ms_from_text(text: str) -> float | None:
    match = _DURATION_MS.search(text)
    if not match:
        return None
    num = float(match.group("num"))
    unit = (match.group("unit") or "ms").lower()
    if unit == "s":
        return num * 1000.0
    return num


def _as_level(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().upper()
    if s == "WARNING":
        return "WARN"
    if s == "FATAL":
        return "CRITICAL"
    if s in {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"}:
        return s
    return None


def _row_from_json(obj: dict[str, Any], raw: str) -> dict[str, Any] | None:
    ts = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or obj.get("ts")
    dt = None
    if isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    elif isinstance(ts, str):
        dt = _parse_isoish_timestamp(ts)

    if not dt:
        return None

    level = _as_level(obj.get("level") or obj.get("severity") or obj.get("log.level"))
    msg = obj.get("message") or obj.get("msg") or obj.get("event") or ""

    status = obj.get("status") or obj.get("http.status_code")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None

    duration_ms = obj.get("duration_ms") or obj.get("latency_ms") or obj.get("response_time_ms")
    try:
        duration_ms = float(duration_ms) if duration_ms is not None else None
    except (TypeError, ValueError):
        duration_ms = None
    if duration_ms is None and isinstance(msg, str):
        duration_ms = _duration_ms_from_text(msg)

    ip = obj.get("ip") or obj.get("client_ip") or obj.get("remote_addr")
    path = obj.get("path") or obj.get("url") or obj.get("http.path")
    method = obj.get("method") or obj.get("http.method")

    return {
        "timestamp": dt,
        "level": level or "INFO",
        "message": str(msg),
        "raw": raw,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": duration_ms,
        "source": "json",
    }


def _row_from_apache(line: str) -> dict[str, Any] | None:
    match = _APACHE_COMBINED.match(line)
    if not match:
        return None
    dt = _parse_apache_ts(match.group("ts"))
    if not dt:
        return None
    b = match.group("bytes")
    bytes_sent = None if b == "-" else int(b)
    status = int(match.group("status"))
    rest = match.group("rest") or ""
    duration_ms = _duration_ms_from_text(rest) or _duration_ms_from_text(line)
    return {
        "timestamp": dt,
        "level": "ERROR" if status >= 500 else "INFO",
        "message": f'{match.group("method")} {match.group("path")} {status}',
        "raw": line,
        "ip": match.group("ip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "status": status,
        "bytes": bytes_sent,
        "user_agent": match.group("ua"),
        "duration_ms": duration_ms,
        "source": "access",
    }


def _row_from_generic(line: str) -> dict[str, Any] | None:
    match = _GENERIC_TS_LEVEL.match(line)
    if not match:
        return None
    dt = _parse_isoish_timestamp(match.group("ts"))
    if not dt:
        return None
    level = _as_level(match.group("level")) or "INFO"
    msg = match.group("msg").strip()
    duration_ms = _duration_ms_from_text(line)
    status = None
    m = _STATUS_IN_LINE.search(line)
    if m:
        status = int(m.group(1))
    return {
        "timestamp": dt,
        "level": level,
        "message": msg,
        "raw": line,
        "status": status,
        "duration_ms": duration_ms,
        "source": "generic",
    }


def parse_lines(lines: Iterable[str]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for line in lines:
        raw = line.rstrip("\n")
        if not raw.strip():
            continue

        row = None
        if raw.lstrip().startswith("{") and raw.rstrip().endswith("}"):
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    row = _row_from_json(obj, raw)
            except json.JSONDecodeError:
                row = None

        if row is None:
            row = _row_from_apache(raw)
        if row is None:
            row = _row_from_generic(raw)
        if row is None:
            continue

        rows.append(row)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp")

    if "level" not in df.columns:
        df["level"] = "INFO"
    df["level"] = df["level"].fillna("INFO").astype(str).str.upper()
    df.loc[df["level"] == "WARNING", "level"] = "WARN"

    status = df["status"] if "status" in df.columns else pd.Series([None] * len(df))
    level_errorish = df["level"].isin(["ERROR", "CRITICAL"])
    status_errorish = pd.to_numeric(status, errors="coerce") >= 500
    df["is_error"] = (level_errorish | status_errorish.fillna(False)).astype(bool)

    if "message" not in df.columns:
        df["message"] = ""
    if "raw" not in df.columns:
        df["raw"] = df["message"]

    return df.reset_index(drop=True)

