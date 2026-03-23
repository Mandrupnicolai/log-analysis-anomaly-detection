function $(id) {
  return document.getElementById(id);
}

const SETTINGS_KEY = "logdash_settings_v1";

const DEFAULTS = {
  useSample: true,
  bucket: "5min",
  method: "isolation_forest",
  contamination: "0.02",
  zThreshold: "3.5",
};

let lastData = null;
let selectedBucket = null;
let logsPreview = [];

function setStatus(text, kind = "muted") {
  const el = $("status");
  el.textContent = text || "";
  el.classList.remove("ok", "error");
  if (kind === "ok") el.classList.add("ok");
  if (kind === "error") el.classList.add("error");
}

function showLoading(on) {
  $("loading").hidden = !on;
}

function fmtPct(x) {
  if (x == null || Number.isNaN(x)) return "-";
  return `${(x * 100).toFixed(2)}%`;
}

function fmtNum(x) {
  if (x == null || Number.isNaN(x)) return "-";
  if (typeof x !== "number") x = Number(x);
  if (!Number.isFinite(x)) return "-";
  if (Math.abs(x) >= 1000) return x.toLocaleString(undefined, { maximumFractionDigits: 2 });
  return x.toFixed(2).replace(/\.00$/, "");
}

function parseIso(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function fmtWhen(iso) {
  const d = parseIso(iso);
  if (!d) return String(iso);
  return d.toLocaleString();
}

function saveSettings() {
  const settings = {
    useSample: $("useSample").checked,
    bucket: $("bucket").value,
    method: $("method").value,
    contamination: $("contamination").value,
    zThreshold: $("zThreshold").value,
  };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw);
    return { ...DEFAULTS, ...parsed };
  } catch {
    return DEFAULTS;
  }
}

function applySettings(s) {
  $("useSample").checked = !!s.useSample;
  $("bucket").value = s.bucket || DEFAULTS.bucket;
  $("method").value = s.method || DEFAULTS.method;
  $("contamination").value = s.contamination ?? DEFAULTS.contamination;
  $("zThreshold").value = s.zThreshold ?? DEFAULTS.zThreshold;
}

function syncInputs() {
  const method = $("method").value;
  $("contamination").disabled = method !== "isolation_forest";
  $("zThreshold").disabled = method !== "robust_z";

  $("methodHelp").textContent =
    method === "isolation_forest"
      ? "Scores buckets using multiple signals (volume, errors, latency, uniques)."
      : "Flags buckets where any metric deviates strongly from the typical baseline.";

  const sample = $("useSample").checked;
  $("files").disabled = sample;
  const count = $("files").files ? $("files").files.length : 0;
  $("filesHelp").textContent = sample
    ? "Disabled while sample data is enabled."
    : count
      ? `${count} file(s) selected.`
      : "JSONL, access logs, or timestamped app logs.";

  saveSettings();
}

function renderKpis(summary) {
  const items = [
    { label: "Total events", value: (summary.total_events ?? 0).toLocaleString() },
    { label: "Buckets", value: (summary.buckets ?? 0).toLocaleString() },
    { label: "Anomalous buckets", value: (summary.anomalous_buckets ?? 0).toLocaleString() },
    { label: "Error rate", value: fmtPct(summary.overall_error_rate ?? 0) },
  ];
  $("kpis").innerHTML = items
    .map((k) => `<div class="kpi"><div class="label">${k.label}</div><div class="value">${k.value}</div></div>`)
    .join("");

  $("rangeMeta").textContent =
    summary.start && summary.end ? `${fmtWhen(summary.start)} → ${fmtWhen(summary.end)}` : "";
}

function chartLayoutBase() {
  return {
    margin: { l: 44, r: 10, t: 6, b: 34 },
    paper_bgcolor: "rgba(0,0,0,0)",
    plot_bgcolor: "rgba(0,0,0,0)",
    font: { color: "#e6e6e6" },
    xaxis: { type: "date", gridcolor: "rgba(255,255,255,0.06)" },
    yaxis: { gridcolor: "rgba(255,255,255,0.06)" },
    showlegend: true,
    legend: { orientation: "h" },
  };
}

function renderVolumeChart(scored) {
  const x = scored.map((r) => r.bucket_start);
  const y = scored.map((r) => r.count ?? 0);
  const anoms = scored.filter((r) => r.is_anomaly);

  const traces = [{ x, y, type: "scatter", mode: "lines", name: "Count", line: { color: "#7aa2f7" } }];
  if (anoms.length) {
    traces.push({
      x: anoms.map((r) => r.bucket_start),
      y: anoms.map((r) => r.count ?? 0),
      type: "scatter",
      mode: "markers",
      name: "Anomaly",
      marker: { color: "rgba(255,99,132,0.95)", size: 8 },
    });
  }

  Plotly.newPlot("volumeChart", traces, chartLayoutBase(), { displayModeBar: false, responsive: true });
  $("volumeChart").on("plotly_click", (ev) => {
    const x0 = ev?.points?.[0]?.x;
    if (x0) setFocus(String(x0));
  });
}

function renderScoreChart(scored) {
  const x = scored.map((r) => r.bucket_start);
  const y = scored.map((r) => r.anomaly_score ?? 0);
  const anoms = scored.filter((r) => r.is_anomaly);

  const traces = [{ x, y, type: "scatter", mode: "lines", name: "Score", line: { color: "#9ece6a" } }];
  if (anoms.length) {
    traces.push({
      x: anoms.map((r) => r.bucket_start),
      y: anoms.map((r) => r.anomaly_score ?? 0),
      type: "scatter",
      mode: "markers",
      name: "Anomaly",
      marker: { color: "rgba(255,99,132,0.95)", size: 8 },
    });
  }

  Plotly.newPlot("scoreChart", traces, chartLayoutBase(), { displayModeBar: false, responsive: true });
  $("scoreChart").on("plotly_click", (ev) => {
    const x0 = ev?.points?.[0]?.x;
    if (x0) setFocus(String(x0));
  });
}

function renderBarChart(el, rows, labelKey) {
  const container = document.getElementById(el);
  if (!rows || !rows.length) {
    Plotly.purge(el);
    container.innerHTML = `<div class="badge">No data</div>`;
    return;
  }
  const y = rows.map((r) => r[labelKey]);
  const x = rows.map((r) => r.count);

  Plotly.newPlot(
    el,
    [{ x, y, type: "bar", orientation: "h", marker: { color: "rgba(122,162,247,0.65)" } }],
    {
      margin: { l: 130, r: 10, t: 6, b: 34 },
      paper_bgcolor: "rgba(0,0,0,0)",
      plot_bgcolor: "rgba(0,0,0,0)",
      font: { color: "#e6e6e6" },
      xaxis: { gridcolor: "rgba(255,255,255,0.06)" },
      yaxis: { gridcolor: "rgba(255,255,255,0.06)", automargin: true, categoryorder: "total ascending" },
      showlegend: false,
    },
    { displayModeBar: false, responsive: true }
  );
}

function renderTable(el, rows, columns, { onRowClick, selectedKey, selectedValue } = {}) {
  const table = document.getElementById(el);
  table.innerHTML = "";

  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  columns.forEach((c) => {
    const th = document.createElement("th");
    th.textContent = c.label;
    trh.appendChild(th);
  });
  thead.appendChild(trh);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    if (selectedKey && selectedValue != null && row[selectedKey] === selectedValue) {
      tr.classList.add("selected");
    }
    columns.forEach((c) => {
      const td = document.createElement("td");
      const v = row[c.key];
      if (c.html) td.innerHTML = c.html(v, row);
      else td.textContent = v == null ? "" : String(v);
      tr.appendChild(td);
    });
    if (onRowClick) {
      tr.style.cursor = "pointer";
      tr.addEventListener("click", () => onRowClick(row));
    }
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
}

function renderAnomsTable(scored) {
  const anoms = scored
    .filter((r) => r.is_anomaly)
    .sort((a, b) => (b.anomaly_score ?? 0) - (a.anomaly_score ?? 0))
    .map((r) => ({
      ...r,
      bucket_start: r.bucket_start,
      count: r.count ?? 0,
      error_rate: r.error_rate == null ? "" : fmtPct(r.error_rate),
      mean_duration_ms: r.mean_duration_ms == null ? "" : fmtNum(r.mean_duration_ms),
      p95_duration_ms: r.p95_duration_ms == null ? "" : fmtNum(r.p95_duration_ms),
      anomaly_score: r.anomaly_score == null ? "" : fmtNum(r.anomaly_score),
    }));

  const cols = [
    { key: "bucket_start", label: "bucket_start" },
    { key: "count", label: "count" },
    { key: "error_count", label: "errors" },
    { key: "error_rate", label: "error_rate" },
    { key: "p95_duration_ms", label: "p95_ms" },
    { key: "unique_ips", label: "uniq_ips" },
    { key: "unique_paths", label: "uniq_paths" },
    {
      key: "anomaly_score",
      label: "score",
      html: (v) => `<span class="badge anom">${v || ""}</span>`,
    },
  ];

  renderTable("anomsTable", anoms, cols, {
    onRowClick: (row) => setFocus(row.bucket_start),
    selectedKey: "bucket_start",
    selectedValue: selectedBucket,
  });
}

function filterLogs(rows, needle) {
  const n = (needle || "").trim().toLowerCase();
  if (!n) return rows;
  return rows.filter((r) => {
    const hay = [
      r.timestamp,
      r.level,
      r.status,
      r.duration_ms,
      r.ip,
      r.path,
      r.message,
      r.raw,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.includes(n);
  });
}

function renderLogsTable(rows, needle = "") {
  const cooked = filterLogs(rows || [], needle).slice(0, 300).map((r) => ({
    ...r,
    duration_ms: r.duration_ms == null ? "" : fmtNum(r.duration_ms),
  }));

  const cols = [
    { key: "timestamp", label: "timestamp" },
    { key: "level", label: "level" },
    { key: "status", label: "status" },
    { key: "duration_ms", label: "duration_ms" },
    { key: "ip", label: "ip" },
    { key: "path", label: "path" },
    { key: "message", label: "message" },
  ];
  renderTable("logsTable", cooked, cols);
}

function relayoutFocusLine(bucketStartIso) {
  const x0 = bucketStartIso;
  const shape = {
    type: "line",
    xref: "x",
    yref: "paper",
    x0,
    x1: x0,
    y0: 0,
    y1: 1,
    line: { color: "rgba(122,162,247,0.45)", width: 2, dash: "dot" },
  };
  Plotly.relayout("volumeChart", { shapes: [shape] });
  Plotly.relayout("scoreChart", { shapes: [shape] });
}

function renderFocus(record) {
  if (!record) {
    $("focusEmpty").hidden = false;
    $("focusCard").hidden = true;
    return;
  }
  $("focusEmpty").hidden = true;
  $("focusCard").hidden = false;

  $("focusWhen").textContent = fmtWhen(record.bucket_start);
  $("focusBucket").textContent = $("bucket").value;

  const isAnom = !!record.is_anomaly;
  const flagEl = $("focusFlag");
  flagEl.classList.toggle("anom", isAnom);
  flagEl.textContent = isAnom ? "Anomaly" : "Normal";

  const kvs = [
    { k: "Count", v: (record.count ?? 0).toLocaleString() },
    { k: "Errors", v: (record.error_count ?? 0).toLocaleString() },
    { k: "Error rate", v: record.error_rate == null ? "-" : fmtPct(record.error_rate) },
    { k: "Mean ms", v: record.mean_duration_ms == null ? "-" : fmtNum(record.mean_duration_ms) },
    { k: "P95 ms", v: record.p95_duration_ms == null ? "-" : fmtNum(record.p95_duration_ms) },
    { k: "Unique IPs", v: (record.unique_ips ?? 0).toLocaleString() },
    { k: "Unique paths", v: (record.unique_paths ?? 0).toLocaleString() },
    { k: "Score", v: record.anomaly_score == null ? "-" : fmtNum(record.anomaly_score) },
  ];
  $("focusGrid").innerHTML = kvs
    .map((x) => `<div class="kv"><div class="k">${x.k}</div><div class="v">${x.v}</div></div>`)
    .join("");
}

function setFocus(bucketStartIso) {
  if (!lastData?.scored?.length) return;
  const key = String(bucketStartIso);
  selectedBucket = key;
  const record = lastData.scored.find((r) => String(r.bucket_start) === key) || null;
  renderFocus(record);
  relayoutFocusLine(key);
  renderAnomsTable(lastData.scored);
}

async function checkHealth() {
  const chip = $("healthChip");
  const val = chip.querySelector(".chipVal");
  try {
    const r = await fetch("/api/health");
    if (!r.ok) throw new Error("bad");
    const j = await r.json();
    if (j.status !== "ok") throw new Error("bad");
    chip.classList.remove("down");
    chip.classList.add("ok");
    val.textContent = "ok";
  } catch {
    chip.classList.remove("ok");
    chip.classList.add("down");
    val.textContent = "down";
  }
}

function resetAll() {
  localStorage.removeItem(SETTINGS_KEY);
  applySettings(DEFAULTS);
  syncInputs();
  $("logFilter").value = "";
  setStatus("Reset to defaults.");
}

// init
applySettings(loadSettings());
syncInputs();
checkHealth();
setInterval(checkHealth, 10000);

["useSample", "bucket", "method", "contamination", "zThreshold", "files"].forEach((id) => {
  $(id).addEventListener("change", syncInputs);
});

$("resetBtn").addEventListener("click", resetAll);

$("logFilter").addEventListener("input", () => {
  renderLogsTable(logsPreview, $("logFilter").value);
});

$("analyzeForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  setStatus("Analyzing…");
  $("analyzeBtn").disabled = true;
  showLoading(true);

  try {
    const fd = new FormData();
    fd.append("use_sample", $("useSample").checked ? "true" : "false");
    fd.append("bucket", $("bucket").value);
    fd.append("method", $("method").value);
    fd.append("contamination", $("contamination").value);
    fd.append("z_threshold", $("zThreshold").value);

    const files = $("files").files || [];
    for (const f of files) fd.append("files", f, f.name);

    const resp = await fetch("/api/analyze", { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status})`);

    lastData = data;
    logsPreview = data.logs_preview || [];

    renderKpis(data.summary || {});
    renderVolumeChart(data.scored || []);
    renderScoreChart(data.scored || []);
    renderBarChart("pathsChart", data.top_paths, "path");
    renderBarChart("ipsChart", data.top_ips, "ip");
    renderAnomsTable(data.scored || []);
    renderLogsTable(logsPreview, $("logFilter").value);

    const best =
      (data.scored || []).filter((r) => r.is_anomaly).sort((a, b) => (b.anomaly_score ?? 0) - (a.anomaly_score ?? 0))[0] ||
      (data.scored || [])[0];
    if (best?.bucket_start) setFocus(best.bucket_start);
    else renderFocus(null);

    setStatus(`Done. Parsed ${(data.summary?.total_events ?? 0).toLocaleString()} events.`, "ok");
  } catch (err) {
    setStatus(`Error: ${err.message || String(err)}`, "error");
    renderFocus(null);
  } finally {
    showLoading(false);
    $("analyzeBtn").disabled = false;
  }
});
