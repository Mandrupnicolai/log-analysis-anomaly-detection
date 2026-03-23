from __future__ import annotations

import pandas as pd


def aggregate_features(df_logs: pd.DataFrame, bucket: str = "5min") -> pd.DataFrame:
    if df_logs.empty:
        return pd.DataFrame()
    if "timestamp" not in df_logs.columns:
        raise ValueError("df_logs must include a timestamp column")

    df = df_logs.copy()
    df = df.set_index("timestamp").sort_index()

    out = pd.DataFrame(index=df.resample(bucket).size().index)
    out.index.name = "bucket_start"
    out["count"] = df.resample(bucket).size()
    out["error_count"] = df["is_error"].resample(bucket).sum().astype("int64")
    out["error_rate"] = (out["error_count"] / out["count"].clip(lower=1)).astype("float64")

    if "duration_ms" in df.columns:
        duration = pd.to_numeric(df["duration_ms"], errors="coerce")
        out["mean_duration_ms"] = duration.resample(bucket).mean()
        out["p95_duration_ms"] = duration.resample(bucket).quantile(0.95)
    else:
        out["mean_duration_ms"] = pd.NA
        out["p95_duration_ms"] = pd.NA

    if "ip" in df.columns:
        out["unique_ips"] = df["ip"].resample(bucket).nunique(dropna=True).astype("int64")
    else:
        out["unique_ips"] = 0

    if "path" in df.columns:
        out["unique_paths"] = df["path"].resample(bucket).nunique(dropna=True).astype("int64")
    else:
        out["unique_paths"] = 0

    out = out.reset_index()
    out["count"] = out["count"].fillna(0).astype("int64")
    out["error_count"] = out["error_count"].fillna(0).astype("int64")
    return out

