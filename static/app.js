const form = document.querySelector("#analysisForm");
const fileInput = document.querySelector("#evtxFiles");
const fileDrop = document.querySelector("#fileDrop");
const fileSummary = document.querySelector("#fileSummary");
const analyzeButton = document.querySelector("#analyzeButton");
const loading = document.querySelector("#loading");
const errorBox = document.querySelector("#errorBox");
const reportView = document.querySelector("#reportView");
const findingsView = document.querySelector("#findingsView");
const summaryView = document.querySelector("#summaryView");
const healthStatus = document.querySelector("#healthStatus");
const agentBackend = document.querySelector("#agentBackend");
const progressFill = document.querySelector("#progressFill");
const progressCat = document.querySelector("#progressCat");
const loadingText = document.querySelector("#loadingText");

let lastReport = "";
let lastAnalysis = null;
let maxUploadBytes = 512 * 1024 * 1024;
let progressTimer = null;
let progressStart = 0;

async function loadHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    healthStatus.textContent = data.ok ? "서버 연결됨" : "서버 오류";
    if (data.max_upload_bytes) {
      maxUploadBytes = data.max_upload_bytes;
    }
    if (data.default_agent_backend && agentBackend) {
      agentBackend.value = data.default_agent_backend;
    }
  } catch {
    healthStatus.textContent = "서버 연결 실패";
  }
}

function updateFileSummary() {
  const files = [...fileInput.files];
  if (!files.length) {
    fileSummary.textContent = "선택된 파일 없음";
    return;
  }
  const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
  const limitText = totalBytes > maxUploadBytes ? " / 업로드 제한 초과" : "";
  fileSummary.textContent = `${files.length}개 파일 / ${formatBytes(totalBytes)}${limitText}`;
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function setBusy(isBusy) {
  analyzeButton.disabled = isBusy;
  loading.classList.toggle("hidden", !isBusy);
  if (isBusy) {
    startProgress();
  } else {
    stopProgress();
  }
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  const selectedFiles = [...fileInput.files];
  const initialFormData = new FormData(form);
  if (!selectedFiles.length) {
    showError("EVTX 또는 XML 파일을 선택하세요.");
    return;
  }

  if (!initialFormData.get("start_time") || !initialFormData.get("end_time")) {
    showError("분석 제한: 시작 시간과 종료 시간을 모두 입력하세요.");
    return;
  }

  const totalBytes = selectedFiles.reduce((sum, file) => sum + file.size, 0);
  if (totalBytes > maxUploadBytes) {
    showError(`선택한 파일 총량이 ${formatBytes(maxUploadBytes)} 업로드 제한을 초과했습니다. 분석 시간 범위를 좁히거나 파일 묶음을 나누어 실행하세요.`);
    return;
  }

  const formData = new FormData(form);
  formData.delete("files");
  for (const file of selectedFiles) {
    formData.append("files", file);
  }

  setBusy(true);
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      const parserErrors = data.parser?.errors?.length ? `\n${data.parser.errors.join("\n")}` : "";
      throw new Error(`${data.error || "분석 요청 실패"}${parserErrors}`);
    }

    lastReport = data.report_markdown;
    lastAnalysis = data.analysis;
    renderReport(lastReport, data.llm);
    renderFindings(data.analysis.findings || []);
    renderSummary(data.analysis);
    activateTab("report");
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
});

fileInput.addEventListener("change", updateFileSummary);

for (const eventName of ["dragenter", "dragover"]) {
  fileDrop.addEventListener(eventName, (event) => {
    event.preventDefault();
    fileDrop.classList.add("dragging");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  fileDrop.addEventListener(eventName, (event) => {
    event.preventDefault();
    fileDrop.classList.remove("dragging");
  });
}

fileDrop.addEventListener("drop", (event) => {
  fileInput.files = event.dataTransfer.files;
  updateFileSummary();
});

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});

function activateTab(name) {
  document.querySelectorAll(".tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === name);
  });
  reportView.classList.toggle("hidden", name !== "report");
  findingsView.classList.toggle("hidden", name !== "findings");
  summaryView.classList.toggle("hidden", name !== "summary");
}

function renderReport(markdown, llm) {
  let status = "";
  if (llm?.backend === "codex_dev") {
    const duration = Number.isFinite(llm.duration_seconds) ? ` / ${llm.duration_seconds.toFixed(1)}초` : "";
    status = llm.used
      ? `<p><strong>에이전트:</strong> Codex 개발 검증 사용됨${duration}</p>`
      : `<p><strong>에이전트:</strong> Codex 개발 검증 실패 - 규칙 기반 보고서 사용${llm?.error ? ` (${escapeHtml(llm.error)})` : ""}</p>`;
  } else if (llm?.backend === "rule") {
    status = `<p><strong>에이전트:</strong> 규칙 기반</p>`;
  } else {
    status = llm?.used
      ? `<p><strong>에이전트:</strong> LM Studio Qwen 사용됨 (${escapeHtml(llm.model)})</p>`
      : `<p><strong>에이전트:</strong> LM Studio Qwen 미사용${llm?.error ? ` - ${escapeHtml(llm.error)}` : ""}</p>`;
  }
  reportView.innerHTML = `${status}${markdownToHtml(markdown)}`;
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsView.innerHTML = `<p>현재 룰 기준으로 탐지된 이상 활동이 없습니다.</p>`;
    return;
  }
  findingsView.innerHTML = `<div class="finding-list">${findings.map(renderFinding).join("")}</div>`;
}

function renderFinding(finding) {
  const evidenceRows = (finding.evidence || [])
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.time || "-")}</td>
        <td>${escapeHtml(item.event_id || "-")}</td>
        <td>${escapeHtml(item.host || "-")}</td>
        <td>${escapeHtml(item.account || "-")}</td>
        <td>${escapeHtml(item.source_ip || "-")}</td>
        <td>${escapeHtml(item.command_line || item.process || "-")}</td>
      </tr>`,
    )
    .join("");
  return `<section class="finding ${escapeHtml(finding.severity || "info")}">
    <h3>${escapeHtml(finding.title)}</h3>
    <div class="meta">
      <span class="pill">${escapeHtml(finding.severity)}</span>
      <span class="pill">신뢰도 ${escapeHtml(finding.confidence)}</span>
      <span class="pill">${Number(finding.event_count || 0).toLocaleString()}건</span>
      <span class="pill">${escapeHtml(finding.first_seen || "-")} ~ ${escapeHtml(finding.last_seen || "-")}</span>
    </div>
    <p>${escapeHtml(finding.description || "")}</p>
    <table class="evidence-table">
      <thead><tr><th>시간</th><th>ID</th><th>호스트</th><th>계정</th><th>원본</th><th>명령/프로세스</th></tr></thead>
      <tbody>${evidenceRows}</tbody>
    </table>
  </section>`;
}

function renderSummary(analysis) {
  const summary = analysis.summary || {};
  const scope = analysis.scope || {};
  summaryView.innerHTML = `<div class="summary-grid">
    ${renderScope(scope)}
    ${renderCounter("이벤트 ID", summary.top_event_ids)}
    ${renderCounter("호스트", summary.top_hosts)}
    ${renderCounter("계정", summary.top_accounts)}
    ${renderCounter("원본 IP", summary.top_source_ips)}
    ${renderCounter("프로바이더", summary.top_providers)}
  </div>`;
}

function renderScope(scope) {
  return `<section class="summary-block">
    <h3>분석 범위</h3>
    <table>
      <tbody>
        <tr><td>시작</td><td>${escapeHtml(scope.start_utc || "미지정")}</td></tr>
        <tr><td>종료</td><td>${escapeHtml(scope.end_utc || "미지정")}</td></tr>
        <tr><td>로드</td><td>${Number(scope.records_loaded || 0).toLocaleString()}건</td></tr>
        <tr><td>범위 내</td><td>${Number(scope.records_in_range || 0).toLocaleString()}건</td></tr>
        <tr><td>전체 확인</td><td>${Number(scope.records_seen || 0).toLocaleString()}건</td></tr>
      </tbody>
    </table>
  </section>`;
}

function renderCounter(title, items = []) {
  const rows = items.length
    ? items
        .map((item) => `<tr><td>${escapeHtml(item.value)}</td><td>${Number(item.count || 0).toLocaleString()}</td></tr>`)
        .join("")
    : `<tr><td>없음</td><td>0</td></tr>`;
  return `<section class="summary-block"><h3>${escapeHtml(title)}</h3><table><tbody>${rows}</tbody></table></section>`;
}

function markdownToHtml(markdown) {
  const lines = markdown.split(/\r?\n/);
  const html = [];
  let inList = false;
  for (const line of lines) {
    if (line.startsWith("### ")) {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
      html.push(`<h3>${inlineMarkdown(line.slice(4))}</h3>`);
    } else if (line.startsWith("## ")) {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
      html.push(`<h2>${inlineMarkdown(line.slice(3))}</h2>`);
    } else if (line.startsWith("# ")) {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
      html.push(`<h1>${inlineMarkdown(line.slice(2))}</h1>`);
    } else if (line.startsWith("- ") || line.startsWith("  - ")) {
      if (!inList) {
        html.push("<ul>");
        inList = true;
      }
      html.push(`<li>${inlineMarkdown(line.replace(/^\s*-\s/, ""))}</li>`);
    } else if (line.trim() === "") {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
    } else {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
      html.push(`<p>${inlineMarkdown(line)}</p>`);
    }
  }
  if (inList) html.push("</ul>");
  return html.join("");
}

function inlineMarkdown(value) {
  return escapeHtml(value).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function startProgress() {
  progressStart = Date.now();
  updateProgress(5, "파일 업로드 준비 중");
  clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    const elapsed = Math.floor((Date.now() - progressStart) / 1000);
    let percent = Math.min(88, 8 + elapsed * 2);
    let message = "파일 업로드 중";
    if (elapsed > 6) {
      message = "EVTX 파싱 및 시간 범위 필터링 중";
      percent = Math.min(70, 25 + elapsed * 1.5);
    }
    if (elapsed > 20) {
      message = agentBackend?.value === "codex_dev" ? "Codex 에이전트 보고서 생성 중" : "보고서 생성 중";
      percent = Math.min(92, 55 + elapsed * 0.8);
    }
    updateProgress(percent, `${message} (${elapsed}초)`);
  }, 500);
}

function stopProgress() {
  clearInterval(progressTimer);
  progressTimer = null;
  updateProgress(100, "완료");
  setTimeout(() => {
    if (!progressTimer) {
      updateProgress(0, "분석 준비 중");
    }
  }, 250);
}

function updateProgress(percent, message) {
  const clamped = Math.max(0, Math.min(100, percent));
  const catPosition = 4 + clamped * 0.92;
  progressFill.style.width = `${clamped}%`;
  progressCat.style.left = `${catPosition}%`;
  loadingText.textContent = message;
}

loadHealth();
