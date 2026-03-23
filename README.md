# Log analysis dashboard (with anomaly detection)

Streamlit dashboard for exploring logs (web/access logs and generic app logs) and flagging anomalous time windows.

## Run

Prereq: Python 3.10+ installed and available on your PATH.

```powershell
cd "C:\Users\Nicolai Mandrup\Documents\Playground\log-analysis-with-anomaly-detection"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

## Run as a website (FastAPI)

This serves a website at `/` and an API at `/api/analyze`.

```powershell
cd "C:\Users\Nicolai Mandrup\Documents\Playground\log-analysis-with-anomaly-detection"
.\.venv\Scripts\Activate.ps1
uvicorn server:app --reload --port 8502
```

Then open `http://127.0.0.1:8502`.

## Use

- Upload one or more log files, or load the bundled sample log.
- Pick a time bucket (e.g., 1 minute / 5 minutes).
- Choose anomaly method:
  - `Isolation Forest` (multivariate; good default)
  - `Robust z-score (MAD)` (per-metric; explainable)

## Notes

- Parsing supports:
  - JSON-per-line logs (common in structured logging)
  - Apache/Nginx “combined” style access logs
  - Generic `timestamp level message` lines (best effort)
- Anomalies are computed on aggregated features (volume, error rate, latency, uniques).
- The website uses Plotly via a CDN script tag in `web/index.html` (so it needs internet access when you load the page).
