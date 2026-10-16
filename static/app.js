const $ = (id) => document.getElementById(id);
const form = $("scan-form");
const scanButton = $("scan-button");
const scanState = $("scan-state");
const toast = $("toast");
let toastTimer;

$("today").textContent = new Date().toLocaleDateString(undefined, {
  weekday: "short", month: "short", day: "numeric", year: "numeric"
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

function showToast(message, kind = "") {
  toast.textContent = message;
  toast.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 4000);
}

function setState(kind, title, detail) {
  scanState.className = `scan-state ${kind || ""}`;
  scanState.querySelector(".state-mark").textContent =
    kind === "loading" ? "…" : kind === "error" ? "!" : "✓";
  scanState.querySelector("b").textContent = title;
  scanState.querySelector("small").textContent = detail;
  const right = scanState.querySelector(".state-right");
  if (right) right.textContent = kind === "loading" ? "RUNNING" : kind === "error" ? "REVIEW" : "READY";
}

function severityClass(severity) {
  const key = String(severity || "info").toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(key) ? key : "info";
}

function formatDate(value) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
  });
}

function shortTarget(value) {
  try {
    const u = new URL(value);
    return u.hostname + (u.pathname !== "/" ? u.pathname : "");
  } catch { return String(value ?? "Unknown target"); }
}

async function api(url, options = {}) {
  const response = await fetch(url, { cache: "no-store", ...options });
  let data;
  try { data = await response.json(); }
  catch { throw new Error(`The server returned an unreadable response (${response.status}).`); }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function renderFindings(scans) {
  const allRows = scans
    .flatMap(scan => (Array.isArray(scan.findings) ? scan.findings : [])
      .map(f => ({ ...f, target: scan.target, checked_at: scan.checked_at })));
  const rows = allRows.slice(0, 8);
  $("nav-findings").textContent = allRows.filter(r => r.severity !== "info").length;
  $("findings-body").innerHTML = rows.length ? rows.map(f => `
    <tr>
      <td><div class="finding-title">${escapeHtml(f.title)}</div><div class="finding-category">${escapeHtml(f.category)}</div></td>
      <td class="target-cell" title="${escapeHtml(f.target)}">${escapeHtml(shortTarget(f.target))}</td>
      <td><span class="severity ${severityClass(f.severity)}">${escapeHtml(f.severity || "info")}</span></td>
      <td>${escapeHtml(formatDate(f.checked_at))}</td>
    </tr>`).join("") :
    '<tr><td colspan="4" class="empty-row">No findings yet. Run your first assessment to see results.</td></tr>';
}

function renderRisk(scans) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  scans.forEach(s => (s.findings || []).forEach(f => { counts[severityClass(f.severity)]++; }));
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) {
    $("risk-breakdown").innerHTML = '<div class="empty-visual"><div class="empty-ring"><span>—</span></div><p>No scan data yet</p><small>Run a scan to populate analytics.</small></div>';
    return;
  }
  const order = ["critical", "high", "medium", "low", "info"];
  $("risk-breakdown").innerHTML = `<div class="risk-summary"><div><strong>${total}</strong><span>total observations</span></div><span class="risk-summary-note">Across ${scans.length} recent scans</span></div><div class="risk-bars">${order.map(key => `
    <div class="risk-row"><span>${key[0].toUpperCase() + key.slice(1)}</span><div class="risk-track"><div class="risk-fill ${key}" style="width:${Math.max(counts[key] ? 3 : 0, counts[key] / total * 100)}%"></div></div><span class="risk-num">${counts[key]}</span></div>`).join("")}</div>`;
}

function renderHistory(scans) {
  $("history-list").innerHTML = scans.length ? scans.slice(0, 5).map(s => `
    <div class="history-item">
      <div class="history-icon ${s.error ? "failed" : ""}">${s.error ? "!" : "↗"}</div>
      <div class="history-main"><b title="${escapeHtml(s.target)}">${escapeHtml(shortTarget(s.target))}</b><small>${escapeHtml(formatDate(s.checked_at))} <span>·</span> ${s.http_status ? `HTTP ${escapeHtml(s.http_status)}` : "No HTTP response"} <span>·</span> ${(s.findings || []).length} observations</small></div>
      <span class="history-status ${s.error ? "failed" : "saved"}">${s.error ? "REVIEW" : "SAVED"}</span>
    </div>`).join("") : '<div class="empty-row">Your scan history will appear here.</div>';
}

async function refresh() {
  const [summary, history] = await Promise.all([api("/api/summary"), api("/api/scans")]);
  $("stat-assets").textContent = summary.assets_assessed ?? 0;
  $("stat-scans").textContent = summary.scans_completed ?? 0;
  $("stat-findings").textContent = summary.open_findings ?? 0;
  $("stat-critical").textContent = summary.critical_findings ?? 0;
  renderFindings(history.scans || []);
  renderRisk(history.scans || []);
  renderHistory(history.scans || []);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = $("target").value.trim();
  if (!target) return;
  scanButton.disabled = true;
  scanButton.innerHTML = '<span>…</span> Assessing <b class="button-arrow">↻</b>';
  setState("loading", "Assessment in progress", "Connecting to the target and reviewing response headers. This may take a few seconds.");
  try {
    const result = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    const resultFindings = Array.isArray(result.findings) ? result.findings : [];
    const issueCount = resultFindings.filter(f => f.severity !== "info").length;
    if (result.error && !result.http_status) {
      setState("error", "Assessment incomplete", result.error);
      showToast("No security conclusion can be drawn from a failed connection.", "error");
    } else {
      setState("", "Assessment saved", `HTTP ${result.http_status} · ${resultFindings.length} observations · ${result.duration_ms ?? "—"} ms`);
      showToast(`Assessment saved. ${issueCount} non-informational observation(s) recorded.`);
    }
    await refresh();
  } catch (error) {
    setState("error", "Assessment failed", error.message || "Unexpected error");
    showToast(error.message || "The assessment could not be completed.", "error");
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = '<span>⌕</span> Run assessment <b>→</b>';
  }
});

refresh().catch(() => {
  setState("error", "Backend unavailable", "Start the local Python server with: python3 app.py");
  showToast("Could not connect to the SentinelX API. Check that the local server is running.", "error");
});
