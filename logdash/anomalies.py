from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


_FEATURE_COLUMNS = [
    "count",
    "error_count",
    "error_rate",
    "mean_duration_ms",
    "p95_duration_ms",
    "unique_ips",
    "unique_paths",
]


def _robust_z(series: pd.Series) -> pd.Series:
    x = pd.to_numeric(series, errors="coerce").astype("float64")
    med = np.nanmedian(x)
    mad = np.nanmedian(np.abs(x - med))
    if not np.isfinite(mad) or mad == 0:
        return pd.Series(np.zeros(len(x), dtype="float64"), index=series.index)
    return 0.6745 * (x - med) / mad


def _detect_robust_z(df: pd.DataFrame, z_threshold: float) -> pd.DataFrame:
    scored = df.copy()
    z_scores = {}
    for c in _FEATURE_COLUMNS:
        if c in scored.columns:
            z_scores[c] = _robust_z(scored[c]).abs()

    if not z_scores:
        scored["anomaly_score"] = 0.0
        scored["is_anomaly"] = False
        return scored

    z_df = pd.DataFrame(z_scores)
    scored["anomaly_score"] = z_df.max(axis=1).fillna(0.0)
    scored["is_anomaly"] = scored["anomaly_score"] >= float(z_threshold)
    return scored


def _detect_isolation_forest(df: pd.DataFrame, contamination: float) -> pd.DataFrame:
    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import RobustScaler

    scored = df.copy()
    cols = [c for c in _FEATURE_COLUMNS if c in scored.columns]
    if not cols:
        scored["anomaly_score"] = 0.0
        scored["is_anomaly"] = False
        return scored

    X = scored[cols].copy()
    for c in cols:
        X[c] = pd.to_numeric(X[c], errors="coerce").astype("float64")
    X = X.fillna(0.0)

    if len(X) < 10:
        scored["anomaly_score"] = 0.0
        scored["is_anomaly"] = False
        return scored

    pipe = Pipeline(
        steps=[
            ("scale", RobustScaler(with_centering=True, with_scaling=True)),
            (
                "iforest",
                IsolationForest(
                    n_estimators=300,
                    contamination=float(contamination),
                    random_state=42,
                ),
            ),
        ]
    )
    pipe.fit(X)

    decision = pipe.named_steps["iforest"].decision_function(pipe.named_steps["scale"].transform(X))
    score = -decision
    scored["anomaly_score"] = pd.Series(score, index=scored.index).astype("float64")

    labels = pipe.predict(X)
    scored["is_anomaly"] = labels == -1
    return scored


def detect_anomalies(
    df_features: pd.DataFrame,
    method: str = "isolation_forest",
    contamination: float = 0.02,
    z_threshold: float = 3.5,
) -> pd.DataFrame:
    if df_features.empty:
        return df_features.copy()

    m = (method or "").strip().lower()
    if m in {"robust_z", "robust-z", "mad", "z"}:
        return _detect_robust_z(df_features, z_threshold=z_threshold)
    if m in {"isolation_forest", "iforest", "isoforest"}:
        return _detect_isolation_forest(df_features, contamination=contamination)
    raise ValueError(f"Unknown method: {method}")

