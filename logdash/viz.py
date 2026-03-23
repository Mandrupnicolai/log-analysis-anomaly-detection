from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def volume_timeline_figure(df_scored: pd.DataFrame) -> go.Figure:
    df = df_scored.copy()
    fig = px.line(df, x="bucket_start", y="count", title=None)
    if "is_anomaly" in df.columns:
        anoms = df[df["is_anomaly"]]
        if not anoms.empty:
            fig.add_trace(
                go.Scatter(
                    x=anoms["bucket_start"],
                    y=anoms["count"],
                    mode="markers",
                    name="Anomaly",
                )
            )
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), height=320)
    return fig


def anomaly_timeline_figure(df_scored: pd.DataFrame) -> go.Figure:
    df = df_scored.copy()
    fig = px.line(df, x="bucket_start", y="anomaly_score", title=None)
    if "is_anomaly" in df.columns:
        anoms = df[df["is_anomaly"]]
        if not anoms.empty:
            fig.add_trace(
                go.Scatter(
                    x=anoms["bucket_start"],
                    y=anoms["anomaly_score"],
                    mode="markers",
                    name="Anomaly",
                )
            )
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), height=320)
    return fig


def top_n_bar_figure(df_logs: pd.DataFrame, column: str, n: int = 15) -> go.Figure:
    counts = (
        df_logs[column]
        .dropna()
        .astype(str)
        .value_counts()
        .head(n)
        .reset_index()
        .rename(columns={"index": column, column: "count"})
    )
    fig = px.bar(counts, x="count", y=column, orientation="h")
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), height=360)
    fig.update_yaxes(categoryorder="total ascending")
    return fig

