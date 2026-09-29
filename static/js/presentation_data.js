// Module data is served from the canonical Python registry (modules.py)
// via GET /api/modules. This file now holds only the presenter logic.
let MODULES = [];

// ── STATE ────────────────────────────────────────────────────────────────────
let currentIdx = 0;
let safeMode = 0;

// ── INIT ─────────────────────────────────────────────────────────────────────
function init() {
  buildSidebar();
  renderModule(0);
  document.addEventListener("keydown", onKey);
  // Push state to server for notes sync
  pushState(0);
}

function buildSidebar() {
  const sidebar = document.getElementById("sidebar");
  MODULES.forEach((m, i) => {
    if (i === 0) return; // skip intro in sidebar
    const el = document.createElement("div");
    el.className = "sidebar-item";
    el.dataset.idx = i;
    el.innerHTML = `
      <span style="font-size:11px;">${m.title.split("—")[0].trim()}</span>
      ${m.sev ? `<span class="sev sev-${m.sev[0].toLowerCase()}">${m.sev[0]}</span>` : ''}
    `;
    el.onclick = () => navigate(i - currentIdx);
    sidebar.appendChild(el);
  });
}

function updateSidebar() {
  document.querySelectorAll(".sidebar-item").forEach(el => {
    el.classList.toggle("active", parseInt(el.dataset.idx) === currentIdx);
  });
}

// ── NAVIGATION ───────────────────────────────────────────────────────────────
function navigate(delta) {
  const next = currentIdx + delta;
  if (next < 0 || next >= MODULES.length) return;
  currentIdx = next;
  renderModule(currentIdx);
  pushState(currentIdx);
}

function onKey(e) {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  if (e.key === "ArrowRight" || e.key === "ArrowDown") navigate(1);
  if (e.key === "ArrowLeft"  || e.key === "ArrowUp")   navigate(-1);
  if (e.key === "Escape") closeFullscreen();
  if (e.key === "f" || e.key === "F") openFullscreen();
}

function renderModule(idx) {
  const m = MODULES[idx];

  // Update counter + progress
  document.getElementById("mod-num").textContent = idx;
  const pct = idx === 0 ? 0 : (idx / (MODULES.length - 1)) * 100;
  document.getElementById("progress-fill").style.width = pct + "%";

  // Update buttons
  document.getElementById("btn-prev").disabled = (idx === 0);
  document.getElementById("btn-next").disabled = (idx === MODULES.length - 1);

  // Update sidebar
  updateSidebar();

  // Update demo iframe
  const demoUrl = buildDemoUrl(m.demoUrl);
  document.getElementById("demo-iframe").src = demoUrl;
  document.getElementById("demo-url-display").textContent = demoUrl;
  document.getElementById("fs-iframe").src = demoUrl;
  document.getElementById("fs-title").textContent = m.title;

  // Update safe pill
  updateSafePill();

  // Render theory
  if (m.intro) {
    renderIntro();
  } else {
    renderTheory(m);
  }
}

function buildDemoUrl(base) {
  if (!base) return "/";
  const sep = base.includes("?") ? "&" : "?";
  return `${base}${sep}safe=${safeMode}`;
}

// ── THEORY RENDERER ──────────────────────────────────────────────────────────
function renderIntro() {
  const el = document.getElementById("theory-scroll");
  el.innerHTML = `
    <div class="intro-slide">
      <div class="intro-title">VULNLAB</div>
      <div class="intro-sub">Web Application Security — Live Demo Platform</div>
      <div class="intro-meta">Yuvraj Todankar · Cybevion · University Cybersecurity Program</div>
      <div class="intro-grid">
        <div class="intro-card">
          <div class="num" style="color:var(--red);">14</div>
          <div class="lbl">Vulnerability Modules</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--green);">2×</div>
          <div class="lbl">Vuln + Safe Mode Per Module</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--blue);">OWASP</div>
          <div class="lbl">Top 10 Aligned</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--yellow);">← →</div>
          <div class="lbl">Keyboard Navigation</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--purple);">F</div>
          <div class="lbl">Fullscreen Demo</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--cyan);">🗒</div>
          <div class="lbl">Speaker Notes Sync</div>
        </div>
      </div>
      <div style="margin-top:2rem;font-size:12px;color:var(--gray);">Press → or click Next to begin</div>
    </div>
  `;
}

function renderTheory(m) {
  const el = document.getElementById("theory-scroll");

  const severityColor = { CRITICAL: "var(--red)", HIGH: "var(--yellow)", MEDIUM: "var(--blue)" };
  const sc = severityColor[m.sev] || "var(--gray)";

  // Build how-it-works HTML
  const howHtml = (m.how || []).map(step => `
    <div class="flow-step">
      <div class="flow-num">${step.n}</div>
      <div class="flow-text">
        ${step.text}
        ${step.code ? `<span class="flow-code">${escHtml(step.code)}</span>` : ""}
      </div>
    </div>
  `).join("");

  // Build payloads HTML
  const payloadHtml = (m.payloads || []).map(p => `
    <div class="payload-item" onclick="injectPayload(${JSON.stringify(p.code)})">
      <div class="payload-code">${escHtml(p.code)}</div>
      <div class="payload-desc">${escHtml(p.desc)}</div>
    </div>
  `).join("");

  el.innerHTML = `
    <div class="mod-header">
      <div class="mod-owasp">
        <span style="color:${sc};font-weight:700;">${m.sev || ""}</span>
        ${m.sev ? " · " : ""}${m.owasp}
      </div>
      <div class="mod-title">${escHtml(m.title)}</div>
      <div class="mod-tagline">${escHtml(m.tagline)}</div>
    </div>

    <div class="section">
      <div class="section-title">What is it</div>
      <div class="what-box">${escHtml(m.what)}</div>
    </div>

    <div class="section">
      <div class="section-title">How it works</div>
      <div class="flow">${howHtml}</div>
    </div>

    <div class="section">
      <div class="section-title">Real-World Impact</div>
      <div class="impact-box">
        <div class="impact-title">${escHtml(m.impact?.title || "")}</div>
        <div class="impact-case">${m.impact?.text || ""}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Attack Payloads — Click to load in demo</div>
      <div class="payload-list">${payloadHtml}</div>
    </div>

    <div class="section">
      <div class="section-title">The Fix — Code Diff</div>
      <div class="diff-block diff-vuln">
        <div class="diff-header">❌ VULNERABLE</div>
        <div class="diff-code">${escHtml(m.vuln_code || "")}</div>
      </div>
      <div class="diff-block diff-safe">
        <div class="diff-header">✓ PATCHED</div>
        <div class="diff-code">${escHtml(m.safe_code || "")}</div>
      </div>
    </div>
  `;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── SAFE MODE ────────────────────────────────────────────────────────────────
function setSafe(val) {
  safeMode = val;
  updateSafePill();
  // Reload both iframes with new safe mode
  const m = MODULES[currentIdx];
  const url = buildDemoUrl(m.demoUrl);
  document.getElementById("demo-iframe").src = url;
  document.getElementById("fs-iframe").src = url;
  document.getElementById("demo-url-display").textContent = url;
}

function updateSafePill() {
  document.getElementById("pill-vuln").className = safeMode === 0 ? "active-vuln" : "";
  document.getElementById("pill-safe").className = safeMode === 1 ? "active-safe" : "";
  document.getElementById("fs-pill-vuln").className = safeMode === 0 ? "active-vuln" : "";
  document.getElementById("fs-pill-safe").className = safeMode === 1 ? "active-safe" : "";
}

// ── FULLSCREEN ───────────────────────────────────────────────────────────────
function openFullscreen() {
  document.getElementById("fs-overlay").classList.add("active");
  const m = MODULES[currentIdx];
  document.getElementById("fs-iframe").src = buildDemoUrl(m.demoUrl);
}

function closeFullscreen() {
  document.getElementById("fs-overlay").classList.remove("active");
}

function reloadDemo() {
  const m = MODULES[currentIdx];
  const url = buildDemoUrl(m.demoUrl);
  document.getElementById("demo-iframe").src = url;
  document.getElementById("fs-iframe").src = url;
}

// ── PAYLOAD INJECTION ────────────────────────────────────────────────────────
function injectPayload(code) {
  // Try to set it in the demo iframe's first text input / textarea
  try {
    const iframe = document.getElementById("fs-overlay").classList.contains("active")
      ? document.getElementById("fs-iframe")
      : document.getElementById("demo-iframe");
    const doc = iframe.contentDocument || iframe.contentWindow.document;
    const input = doc.querySelector("input[type=text]:not([type=hidden]),input:not([type]),textarea");
    if (input) {
      input.value = code;
      input.focus();
    }
  } catch(e) {
    // Cross-origin — just copy to clipboard
    navigator.clipboard?.writeText(code);
    alert("Payload copied to clipboard:\n" + code);
  }
}

// ── SERVER SYNC (notes window) ───────────────────────────────────────────────
function pushState(idx) {
  fetch("/api/presentation/state", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ module: idx })
  }).catch(() => {});
}

// Bootstrap: load the module registry, then start the presenter.
fetch('/api/modules')
  .then(r => r.json())
  .then(data => { MODULES = data; init(); })
  .catch(err => {
    document.getElementById('theory-scroll').innerHTML =
      '<div style="padding:2rem;color:var(--red);">Failed to load modules: ' + err + '</div>';
  });
