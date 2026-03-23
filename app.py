from __future__ import annotations

import io
from typing import Iterable

import pandas as pd
import streamlit as st

from logdash.anomalies import detect_anomalies
from logdash.features import aggregate_features
from logdash.parsing import parse_lines
from logdash.sample_data import get_bundled_sample_log_text
from logdash.viz import (
    anomaly_timeline_figure,
    top_n_bar_figure,
    volume_timeline_figure,
)


st.set_page_config(page_title="Log analysis + anomaly detection", layout="wide")

st.title("Log analysis dashboard (with anomaly detection)")


def _read_uploaded_files(files: Iterable) -> list[str]:
    lines: list[str] = []
    for f in files:
        data = f.getvalue()
        try:
            text = data.decode("utf-8", errors="replace")
        except AttributeError:
            text = str(data)
        lines.extend(text.splitlines())
    return lines


with st.sidebar:
    st.header("Data")
    uploaded = st.file_uploader(
        "Upload log file(s)",
        type=None,
        accept_multiple_files=True,
        help="Any text logs; JSON-per-line, access logs, or generic app logs.",
    )
    use_sample = st.toggle("Use bundled sample log", value=not uploaded)
    st.divider()
    st.header("Analysis")
    bucket = st.selectbox("Time bucket", ["1min", "5min", "15min", "1H"], index=1)
    method = st.selectbox("Anomaly method", ["Isolation Forest", "Robust z-score (MAD)"])
    contamination = st.slider(
        "Isolation Forest: contamination",
        min_value=0.001,
        max_value=0.20,
        value=0.02,
        step=0.001,
        disabled=(method != "Isolation Forest"),
    )
    z_threshold = st.slider(
        "Robust z-score: threshold",
        min_value=2.0,
        max_value=10.0,
        value=3.5,
        step=0.1,
        disabled=(method != "Robust z-score (MAD)"),
    )


if use_sample:
    lines = get_bundled_sample_log_text().splitlines()
else:
    if not uploaded:
        st.info("Upload one or more log files, or enable the sample log in the sidebar.")
        st.stop()
    lines = _read_uploaded_files(uploaded)

if not lines:
    st.warning("No log lines found.")
    st.stop()

with st.spinner("Parsing logs…"):
    df_logs = parse_lines(lines)

if df_logs.empty:
    st.error("Could not parse any usable timestamps from the provided logs.")
    st.stop()

st.caption(
    f"Parsed {len(df_logs):,} lines "
    f"({df_logs['timestamp'].min()} → {df_logs['timestamp'].max()})."
)

with st.spinner("Aggregating features…"):
    df_features = aggregate_features(df_logs, bucket=bucket)

method_key = "isolation_forest" if method == "Isolation Forest" else "robust_z"

with st.spinner("Detecting anomalies…"):
    df_scored = detect_anomalies(
        df_features,
        method=method_key,
        contamination=contamination,
        z_threshold=z_threshold,
    )

col_a, col_b, col_c, col_d = st.columns(4)
col_a.metric("Total events", f"{len(df_logs):,}")
col_b.metric("Buckets", f"{len(df_scored):,}")
col_c.metric("Anomalous buckets", f"{int(df_scored['is_anomaly'].sum()):,}")
col_d.metric("Error rate (overall)", f"{(df_logs['is_error'].mean() * 100):.2f}%")

tab_overview, tab_anoms, tab_raw = st.tabs(["Overview", "Anomalies", "Raw logs"])

with tab_overview:
    left, right = st.columns([2, 1], gap="large")
    with left:
        st.subheader("Volume")
        st.plotly_chart(volume_timeline_figure(df_scored), use_container_width=True)
        st.subheader("Anomaly score")
        st.plotly_chart(anomaly_timeline_figure(df_scored), use_container_width=True)
    with right:
        st.subheader("Top paths")
        if "path" in df_logs.columns and df_logs["path"].notna().any():
            st.plotly_chart(top_n_bar_figure(df_logs, "path", n=15), use_container_width=True)
        else:
            st.caption("No path field detected.")

        st.subheader("Top IPs")
        if "ip" in df_logs.columns and df_logs["ip"].notna().any():
            st.plotly_chart(top_n_bar_figure(df_logs, "ip", n=15), use_container_width=True)
        else:
            st.caption("No IP field detected.")

with tab_anoms:
    st.subheader("Anomalous buckets")
    cols = [
        "bucket_start",
        "count",
        "error_count",
        "error_rate",
        "mean_duration_ms",
        "p95_duration_ms",
        "unique_ips",
        "unique_paths",
        "anomaly_score",
    ]
    present = [c for c in cols if c in df_scored.columns]
    st.dataframe(
        df_scored.loc[df_scored["is_anomaly"], present].sort_values(
            ["anomaly_score"], ascending=False
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Inspect logs around a bucket")
    bucket_choices = df_scored.loc[df_scored["is_anomaly"], "bucket_start"]
    if bucket_choices.empty:
        st.caption("No anomalies detected with the current settings.")
    else:
        chosen_ts = st.selectbox(
            "Bucket",
            bucket_choices.tolist(),
            format_func=lambda x: pd.Timestamp(x).strftime("%Y-%m-%d %H:%M:%S %Z"),
        )
        start = pd.Timestamp(chosen_ts)
        end = start + pd.Timedelta(bucket)
        nearby = df_logs[(df_logs["timestamp"] >= start) & (df_logs["timestamp"] < end)]
        st.write(f"{len(nearby):,} events in the selected bucket.")
        st.dataframe(
            nearby.sort_values("timestamp")[["timestamp", "level", "message", "raw"]].head(500),
            use_container_width=True,
            hide_index=True,
        )

with tab_raw:
    st.subheader("Parsed logs (preview)")
    st.dataframe(
        df_logs.sort_values("timestamp", ascending=False).head(1000),
        use_container_width=True,
        hide_index=True,
    )
    csv = df_logs.to_csv(index=False).encode("utf-8")
    st.download_button("Download parsed CSV", data=csv, file_name="parsed_logs.csv")
