from __future__ import annotations

from typing import Any

import pandas as pd
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from logdash.anomalies import detect_anomalies
from logdash.features import aggregate_features
from logdash.parsing import parse_lines
from logdash.sample_data import get_bundled_sample_log_text


app = FastAPI(title="Logdash API", version="1.0.0")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="web", html=True), name="web")


def _df_to_records(df: pd.DataFrame, *, limit: int | None = None) -> list[dict[str, Any]]:
    if limit is not None:
        df = df.head(limit)
    out = df.copy()
    for c in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[c]):
            out[c] = out[c].dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return out.where(pd.notna(out), None).to_dict(orient="records")


@app.post("/api/analyze")
async def analyze(
    files: list[UploadFile] = File(default=[]),
    use_sample: bool = Form(default=False),
    bucket: str = Form(default="5min"),
    method: str = Form(default="isolation_forest"),
    contamination: float = Form(default=0.02),
    z_threshold: float = Form(default=3.5),
) -> JSONResponse:
    if use_sample or not files:
        lines = get_bundled_sample_log_text().splitlines()
    else:
        lines: list[str] = []
        for f in files:
            data = await f.read()
            text = data.decode("utf-8", errors="replace")
            lines.extend(text.splitlines())

    df_logs = parse_lines(lines)
    if df_logs.empty:
        return JSONResponse(
            status_code=400,
            content={"error": "Could not parse any usable timestamps from the provided logs."},
        )

    df_features = aggregate_features(df_logs, bucket=bucket)
    df_scored = detect_anomalies(
        df_features,
        method=method,
        contamination=contamination,
        z_threshold=z_threshold,
    )

    top_paths = []
    if "path" in df_logs.columns:
        top_paths = (
            df_logs["path"]
            .dropna()
            .astype(str)
            .value_counts()
            .head(15)
            .reset_index()
            .rename(columns={"index": "path", "path": "count"})
            .to_dict(orient="records")
        )

    top_ips = []
    if "ip" in df_logs.columns:
        top_ips = (
            df_logs["ip"]
            .dropna()
            .astype(str)
            .value_counts()
            .head(15)
            .reset_index()
            .rename(columns={"index": "ip", "ip": "count"})
            .to_dict(orient="records")
        )

    overall_error_rate = float(df_logs["is_error"].mean()) if "is_error" in df_logs.columns else 0.0

    content = {
        "summary": {
            "total_events": int(len(df_logs)),
            "start": df_logs["timestamp"].min().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "end": df_logs["timestamp"].max().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "buckets": int(len(df_scored)),
            "anomalous_buckets": int(df_scored["is_anomaly"].sum()) if "is_anomaly" in df_scored else 0,
            "overall_error_rate": overall_error_rate,
        },
        "bucket": bucket,
        "method": method,
        "scored": _df_to_records(df_scored),
        "top_paths": top_paths,
        "top_ips": top_ips,
        "logs_preview": _df_to_records(
            df_logs.sort_values("timestamp", ascending=False)[
                [c for c in ["timestamp", "level", "message", "ip", "path", "status", "duration_ms", "raw"] if c in df_logs.columns]
            ],
            limit=500,
        ),
    }
    return JSONResponse(content=content)
