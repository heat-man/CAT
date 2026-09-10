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
const savePdfButton = document.querySelector("#savePdfButton");
const tabList = document.querySelector(".tab-list");
const healthStatus = document.querySelector("#healthStatus");
const progressFill = document.querySelector("#progressFill");
const progressCat = document.querySelector("#progressCat");
const loadingText = document.querySelector("#loadingText");
const catSelector = document.querySelector("#catSelector");
const mainCatImage = document.querySelector("#mainCatImage");
const previousCatButton = document.querySelector("#previousCatButton");
const nextCatButton = document.querySelector("#nextCatButton");
const historyButton = document.querySelector("#historyButton");
const historyDialog = document.querySelector("#historyDialog");
const historyList = document.querySelector("#historyList");
const historyStorageStatus = document.querySelector("#historyStorageStatus");
const closeHistoryButton = document.querySelector("#closeHistoryButton");
const clearHistoryButton = document.querySelector("#clearHistoryButton");

const ANALYSIS_HISTORY_KEY = "cat.analysis_history.v1";
const ANALYSIS_HISTORY_MAX_ENTRIES = 10;
const ANALYSIS_HISTORY_MAX_TOTAL_CHARS = 1500000;
const ANALYSIS_HISTORY_MAX_ENTRY_CHARS = 350000;
const ANALYSIS_HISTORY_MAX_REPORT_CHARS = 180000;
const HISTORY_FORBIDDEN_KEYS = /(?:^|_)(?:api_?key|private_?key|authorization|token|access_?token|refresh_?token|auth_?token|bearer_?token|id_?token|session_?token|cookie|password|secret|credential|raw(?:_xml)?|file_content|uploaded_file_content)(?:_|$)/i;

const C2_SCORE_COMPONENT_LABELS = Object.freeze({
  high_risk_port: "고위험 목적지 포트",
  user_writable_process: "사용자 쓰기 가능 경로의 프로세스",
  suspicious_command: "의심 명령줄",
  suspicious_parent_or_lolbin: "의심 부모 프로세스 또는 LOLBin",
  known_tunnel_client: "알려진 터널링 도구",
  sensitive_loopback_tunnel: "민감 서비스 loopback 터널",
  high_entropy_dns: "고엔트로피 DNS 이름",
  periodic_beacon: "주기적 반복 통신",
  process_fanout: "단일 프로세스의 다수 목적지 통신",
  unusual_network_process: "비일반적 네트워크 프로세스",
  nonstandard_port: "비표준 목적지 포트",
});

const NETWORK_FINDING_RULE_IDS = new Set([
  "suspicious_network_connection",
  "possible_network_beacon",
  "suspicious_dns_network_activity",
  "possible_process_fanout",
]);

const CAT_IMAGES = Object.freeze([
  {
    id: "cat_staring.jpg",
    src: "/asset/cat_staring.jpg",
    alt: "이불 속에서 카메라를 바라보는 회색 고양이",
  },
  {
    id: "cat.jpg",
    src: "/asset/cat.jpg",
    alt: "선글라스를 쓴 회색 고양이",
  },
  {
    id: "cat_down.jpg",
    src: "/asset/cat_down.jpg",
    alt: "소파 등받이를 내려오는 회색 고양이",
  },
  {
    id: "cat_dress.jpg",
    src: "/asset/cat_dress.jpg",
    alt: "빨간 드레스를 입은 회색 고양이",
  },
  {
    id: "cat_sleep.jpg",
    src: "/asset/cat_sleep.jpg",
    alt: "이불 속에서 얼굴을 내민 회색 고양이",
  },
  {
    id: "cat_sleep2.jpg",
    src: "/asset/cat_sleep2.jpg",
    alt: "침대에서 웅크려 자는 회색 고양이",
  },
]);

let lastReport = "";
let lastAnalysis = null;
let maxUploadBytes = 512 * 1024 * 1024;
let progressTimer = null;
let progressStart = 0;
let currentCatImageIndex = 0;

async function loadHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    healthStatus.textContent = data.ok ? "서버 연결됨" : "서버 오류";
    healthStatus.dataset.state = data.ok ? "online" : "offline";
    if (data.max_upload_bytes) {
      maxUploadBytes = data.max_upload_bytes;
    }
  } catch {
    healthStatus.textContent = "서버 연결 실패";
    healthStatus.dataset.state = "offline";
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
  if (savePdfButton) {
    savePdfButton.disabled = isBusy || !String(lastReport || "").trim();
  }
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
  // The web app uses the server's configured backend, endpoint and model.
  // Discard legacy fields instead of reviving older browser preferences.
  for (const key of ["agent_backend", "lm_url", "lm_model", "use_llm"]) {
    formData.delete(key);
  }
  formData.set("auto_expand_time_range", "true");
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
    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      const detail = responseText.trim().slice(0, 500);
      throw new Error(
        `서버가 JSON이 아닌 응답을 반환했습니다 (HTTP ${response.status})${detail ? `: ${detail}` : ""}`,
      );
    }
    if (!response.ok || !data.ok) {
      const parserErrors = data.parser?.errors?.length ? `\n${data.parser.errors.join("\n")}` : "";
      throw new Error(`${data.error || "분석 요청 실패"}${parserErrors}`);
    }

    lastReport = String(data.report_markdown || "");
    lastAnalysis = resolveAnalysisPayload(data);
    renderReport(lastReport, data.llm, lastAnalysis);
    try {
      renderFindings(lastAnalysis);
    } catch (renderError) {
      findingsView.innerHTML = `<p>탐지 결과 렌더링 경고: ${escapeHtml(renderError.message)}</p>`;
    }
    try {
      renderSummary(lastAnalysis);
    } catch (renderError) {
      summaryView.innerHTML = `<p>요약 렌더링 경고: ${escapeHtml(renderError.message)}</p>`;
    }
    try {
      saveAnalysisHistory(lastReport, lastAnalysis, data.llm);
    } catch {
      if (historyStorageStatus) {
        historyStorageStatus.textContent = "분석은 완료했지만 브라우저 이력 저장에 실패했습니다.";
      }
    }
    activateTab("report");
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
});

fileInput.addEventListener("change", updateFileSummary);
savePdfButton?.addEventListener("click", saveReportAsPdf);
historyButton?.addEventListener("click", openAnalysisHistory);
closeHistoryButton?.addEventListener("click", closeAnalysisHistory);
clearHistoryButton?.addEventListener("click", clearAnalysisHistory);
historyList?.addEventListener("click", handleHistoryAction);
historyDialog?.addEventListener("click", handleHistoryBackdropClick);
previousCatButton?.addEventListener("click", () => selectCatImage(-1));
nextCatButton?.addEventListener("click", () => selectCatImage(1));
catSelector?.addEventListener("keydown", handleCatSelectorKeydown);

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
tabList?.addEventListener("keydown", handleTabKeydown);

function activateTab(name) {
  document.querySelectorAll(".tab").forEach((button) => {
    const selected = button.dataset.tab === name;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  reportView.classList.toggle("hidden", name !== "report");
  findingsView.classList.toggle("hidden", name !== "findings");
  summaryView.classList.toggle("hidden", name !== "summary");
}

function handleTabKeydown(event) {
  if (!tabList) return;
  const buttons = [...tabList.querySelectorAll(".tab")];
  const currentIndex = buttons.indexOf(document.activeElement);
  if (currentIndex < 0) return;

  let targetIndex;
  if (event.key === "ArrowRight") targetIndex = (currentIndex + 1) % buttons.length;
  else if (event.key === "ArrowLeft") {
    targetIndex = (currentIndex - 1 + buttons.length) % buttons.length;
  } else if (event.key === "Home") targetIndex = 0;
  else if (event.key === "End") targetIndex = buttons.length - 1;
  else return;

  event.preventDefault();
  const target = buttons[targetIndex];
  activateTab(target.dataset.tab);
  target.focus();
}

function saveReportAsPdf() {
  if (!String(lastReport || "").trim()) {
    showError("먼저 분석을 실행해 보고서를 생성하세요.");
    return;
  }
  if (typeof window.print !== "function") {
    showError("이 브라우저에서는 보고서 인쇄 기능을 사용할 수 없습니다.");
    return;
  }

  clearError();
  activateTab("report");
  const originalTitle = document.title;
  let titleRestored = false;
  const restoreTitle = () => {
    if (titleRestored) return;
    titleRestored = true;
    document.title = originalTitle;
    window.removeEventListener("afterprint", restoreTitle);
  };

  document.title = buildReportPdfTitle(new Date());
  window.addEventListener("afterprint", restoreTitle);
  try {
    window.print();
  } catch {
    showError("브라우저가 인쇄 창을 열지 못했습니다. 브라우저의 인쇄 정책을 확인하세요.");
    restoreTitle();
    return;
  }
  window.setTimeout(restoreTitle, 1000);
}

function buildReportPdfTitle(now) {
  const pad = (value) => String(value).padStart(2, "0");
  const date = [now.getFullYear(), pad(now.getMonth() + 1), pad(now.getDate())].join("");
  const time = [pad(now.getHours()), pad(now.getMinutes()), pad(now.getSeconds())].join("");
  return `CAT-report-${date}-${time}`;
}

function renderReport(markdown, llm, analysis = {}) {
  let status = "";
  if (llm?.backend === "codex_dev") {
    const duration = Number.isFinite(llm.duration_seconds) ? ` / ${llm.duration_seconds.toFixed(1)}초` : "";
    status = llm.used
      ? `<p><strong>에이전트:</strong> Codex 개발 검증 사용됨${duration}</p>`
      : `<p><strong>에이전트:</strong> Codex 개발 검증 실패 - 규칙 기반 보고서 사용${llm?.error ? ` (${escapeHtml(llm.error)})` : ""}</p>`;
  } else if (llm?.backend === "rule") {
    status = `<p><strong>에이전트:</strong> 규칙 기반 탐지/보고서 사용됨</p>`;
  } else {
    const warnings = Array.isArray(llm?.validation_warnings)
      ? llm.validation_warnings.filter((item) => typeof item === "string" && item.trim())
      : [];
    const warningTitle = llm?.structured_report_recovered
      ? "응답 보정 안내"
      : "LM 응답 안내";
    const inputScopeNotice = renderLmInputScopeNotice(llm);
    status = llm?.used
      ? `<p><strong>에이전트:</strong> LM Studio 사용됨 (${escapeHtml(llm.model)})${llm.validation_mode === "relaxed" ? " / 자유 형식" : " / strict 검증"}</p>${inputScopeNotice}${
          warnings.length
            ? `<div class="llm-warning"><strong>${warningTitle}:</strong><ul>${warnings.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>`
            : ""
        }`
      : `<p><strong>에이전트:</strong> ${llm?.report_fallback_used ? "로컬 보고서로 복구됨 · 완료된 청크 요약 보존" : "LM Studio 미사용"}${llm?.error ? ` - ${escapeHtml(llm.error)}` : ""}</p>`;
  }
  reportView.innerHTML = `${renderParserWarning(analysis)}${status}${renderHierarchicalLmStatus(llm)}${markdownToHtml(String(markdown || ""))}${renderPrintAnalysisAppendix(analysis, llm)}${renderPrintNetworkAppendix(analysis)}`;
}

function renderHierarchicalLmStatus(llm) {
  if (!llm || typeof llm !== "object" || Array.isArray(llm)) return "";
  const hasMetadata = [
    "hierarchical_analysis_enabled",
    "hierarchical_analysis_used",
    "hierarchical_chunk_count",
    "hierarchical_skip_reason",
  ].some((key) => Object.prototype.hasOwnProperty.call(llm, key));
  if (!hasMetadata) return "";

  const enabled = llm.hierarchical_analysis_enabled === true;
  const used = llm.hierarchical_analysis_used === true;
  const chunkCount = finiteCount(llm.hierarchical_chunk_count) ?? 0;
  const completed = finiteCount(llm.hierarchical_chunks_completed) ?? 0;
  const failed = finiteCount(llm.hierarchical_chunks_failed) ?? 0;
  const recovered = finiteCount(llm.hierarchical_chunks_recovered) ?? 0;
  const selected = finiteCount(llm.hierarchical_selected_evidence_count);
  const source = finiteCount(llm.hierarchical_source_evidence_count);
  const omitted = finiteCount(llm.hierarchical_evidence_omitted) ?? 0;
  const repetitionsOmitted = finiteCount(llm.hierarchical_repetition_omitted) ?? 0;
  const skipReasonLabels = {
    strict_validation_enabled: "strict 검증 모드",
    disabled_by_environment: "서버 설정으로 비활성화",
    insufficient_distinct_evidence: "분할에 필요한 고유 근거 부족",
    fits_single_request_window: "단일 요청 범위에 포함 가능",
    pipeline_error: "분할 분석 준비 오류",
    not_evaluated: "평가되지 않음",
  };
  const state = used
    ? "사용됨"
    : enabled
      ? "사용 조건 미충족"
      : "사용 안 함";
  const details = [];
  if (used || chunkCount) {
    details.push(`시간 청크 ${chunkCount}개 · LM 완료 ${completed}개 · 로컬 근거 보완 ${recovered}개`);
    if (failed > recovered) details.push(`미복구 ${failed - recovered}개`);
  }
  if (selected !== null && (used || selected > 0 || (source ?? 0) > 0)) {
    details.push(source !== null ? `선별 근거 ${selected}/${source}건` : `선별 근거 ${selected}건`);
  }
  if (omitted) details.push(`청크 입력 제외 ${omitted}건`);
  if (repetitionsOmitted) details.push(`반복 근거 축약 ${repetitionsOmitted}건`);
  if (llm.hierarchical_source_limit_reached === true) details.push("원천 증거 수집 상한 도달");
  if (!used && llm.hierarchical_skip_reason) {
    details.push(skipReasonLabels[llm.hierarchical_skip_reason] || llm.hierarchical_skip_reason);
  }
  const warningCount = uniqueText([
    ...asList(llm.hierarchical_validation_warnings),
    ...asList(llm.validation_warnings).filter((item) =>
      typeof item === "string" && (item.includes("청크") || item.includes("계층형")),
    ),
  ]).length;
  if (warningCount) details.push(`관련 경고 ${warningCount}건`);
  return `<div class="lm-hierarchical-status${failed || warningCount ? " has-warning" : ""}">
    <strong>계층형 분할 분석:</strong> ${escapeHtml(state)}${details.length ? ` · ${details.map(escapeHtml).join(" · ")}` : ""}
  </div>`;
}

function renderLmInputScopeNotice(llm) {
  if (llm?.input_truncated !== true) return "";
  const countPairs = [
    ["finding", llm.input_findings, llm.source_findings ?? llm.input_source_findings],
    ["의심 이벤트", llm.input_suspicious_events, llm.source_suspicious_events ?? llm.input_source_suspicious_events],
    ["시나리오", llm.input_scenario_candidates, llm.source_scenario_candidates ?? llm.input_source_scenario_candidates],
    ["타임라인", llm.input_timeline, llm.source_timeline ?? llm.input_source_timeline],
    ["네트워크 그룹", llm.input_network_groups, llm.input_source_network_groups],
    ["프로세스 fan-out 후보", llm.input_network_fanout_candidates, llm.input_source_network_fanout_candidates],
  ];
  const counts = countPairs
    .filter(([, included]) => Number.isFinite(included))
    .map(([label, included, source]) =>
      Number.isFinite(source)
        ? `${label} ${included}/${source}`
        : `${label} ${included}`,
    )
    .join(", ");
  const countText = counts ? ` (${escapeHtml(counts)})` : "";
  return `<div class="llm-warning"><strong>LM 입력 범위 안내:</strong> 전체 CAT 분석 중 우선순위가 높은 근거 일부만 LM Studio에 전달되었습니다${countText}. 보고서의 증거 한계와 탐지 결과 탭을 함께 확인하세요.</div>`;
}

function renderParserWarning(analysis) {
  const safeAnalysis = analysis && typeof analysis === "object" ? analysis : {};
  const parser = safeAnalysis.parser && typeof safeAnalysis.parser === "object"
    ? safeAnalysis.parser
    : {};
  const scope = safeAnalysis.scope && typeof safeAnalysis.scope === "object"
    ? safeAnalysis.scope
    : {};
  const errors = asList(parser.errors)
    .filter((item) => typeof item === "string" && item.trim());
  const truncated = parser.truncated === true || scope.truncated === true;
  if (!errors.length && !truncated) return "";
  const recordLimitReached = parser.record_limit_reached === true ||
    scope.record_limit_reached === true;
  const networkScanComplete = parser.network_scan_complete === true ||
    scope.network_scan_complete === true;
  const networkSpoolLimitReached = parser.network_spool_limit_reached === true;
  const networkRecordsSeen = finiteCount(parser.network_records_seen);
  const networkRecordsSpooled = finiteCount(parser.network_records_spooled);
  let scopeMessage = "일부 파일 또는 레코드만 분석되었을 수 있습니다.";
  if (networkSpoolLimitReached) {
    const countDetail = networkRecordsSeen !== null && networkRecordsSpooled !== null
      ? ` 확인된 C2 관련 이벤트 ${formatC2Score(networkRecordsSeen)}건 중 ${formatC2Score(networkRecordsSpooled)}건만 로컬 C2 분석에 반영되었습니다.`
      : " 이후 C2 관련 이벤트 일부가 로컬 C2 분석에서 제외되었습니다.";
    scopeMessage = `C2 분석 스풀 전체 상한에 도달했습니다.${countDetail}`;
  } else if (recordLimitReached && networkScanComplete && !errors.length) {
    scopeMessage = "일반 분석 이벤트는 보관 상한까지 포함되었지만 C2 관련 이벤트는 입력 끝까지 별도 스캔했습니다.";
  }
  const details = errors.length
    ? `<ul>${errors.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "";
  return `<div class="parser-warning"><strong>입력 파싱 경고:</strong> ${escapeHtml(scopeMessage)}${details}</div>`;
}

function readPreference(key) {
  try {
    return window.localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function writePreference(key, value) {
  try {
    if (value) window.localStorage.setItem(key, value);
    else window.localStorage.removeItem(key);
  } catch {
    // Storage can be disabled by browser policy; the current form value still works.
  }
}

function readAnalysisHistory() {
  try {
    const raw = window.localStorage.getItem(ANALYSIS_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry) =>
      entry &&
      typeof entry === "object" &&
      typeof entry.id === "string" &&
      typeof entry.created_at === "string" &&
      typeof entry.report_markdown === "string" &&
      entry.analysis &&
      typeof entry.analysis === "object" &&
      !Array.isArray(entry.analysis),
    ).slice(0, ANALYSIS_HISTORY_MAX_ENTRIES);
  } catch {
    return [];
  }
}

function writeAnalysisHistory(entries) {
  const bounded = entries
    .filter((entry) => {
      try {
        return JSON.stringify(entry).length <= ANALYSIS_HISTORY_MAX_ENTRY_CHARS;
      } catch {
        return false;
      }
    })
    .slice(0, ANALYSIS_HISTORY_MAX_ENTRIES);
  while (bounded.length && JSON.stringify(bounded).length > ANALYSIS_HISTORY_MAX_TOTAL_CHARS) {
    bounded.pop();
  }
  while (bounded.length) {
    try {
      window.localStorage.setItem(ANALYSIS_HISTORY_KEY, JSON.stringify(bounded));
      return true;
    } catch {
      // A full or disabled storage area must not make the forensic analysis fail.
      bounded.pop();
    }
  }
  try {
    window.localStorage.removeItem(ANALYSIS_HISTORY_KEY);
  } catch {
    // Storage can be disabled by browser policy.
  }
  return false;
}

function saveAnalysisHistory(reportMarkdown, analysis, llm) {
  if (!String(reportMarkdown || "").trim()) return;
  const entry = createAnalysisHistoryEntry(reportMarkdown, analysis, llm);
  const entries = readAnalysisHistory().filter((item) => item.id !== entry.id);
  entries.unshift(entry);
  const stored = writeAnalysisHistory(entries);
  if (!stored && historyStorageStatus) {
    historyStorageStatus.textContent = "브라우저 저장 공간이 부족하거나 차단되어 이력을 저장하지 못했습니다.";
  }
}

function createAnalysisHistoryEntry(reportMarkdown, analysis, llm) {
  const createdAt = new Date();
  const reportText = String(reportMarkdown || "");
  const reportWasTruncated = reportText.length > ANALYSIS_HISTORY_MAX_REPORT_CHARS;
  const safeReport = truncateHistoryText(
    reportText,
    ANALYSIS_HISTORY_MAX_REPORT_CHARS,
    "\n\n[브라우저 분석 이력 용량 제한으로 이후 보고서 내용이 생략되었습니다.]",
  );
  const tiers = [
    { arrayLimit: 100, objectLimit: 200, stringLimit: 20000, depthLimit: 10 },
    { arrayLimit: 40, objectLimit: 120, stringLimit: 8000, depthLimit: 9 },
    { arrayLimit: 16, objectLimit: 80, stringLimit: 4000, depthLimit: 8 },
    { arrayLimit: 6, objectLimit: 50, stringLimit: 2000, depthLimit: 7 },
  ];
  const base = {
    version: 1,
    id: `analysis-${createdAt.getTime()}-${Math.random().toString(36).slice(2, 9)}`,
    created_at: createdAt.toISOString(),
    title: historyReportTitle(safeReport),
    report_markdown: safeReport,
    llm: historyLmMetadata(llm),
    basic_summary: buildHistoryBasicSummary(analysis),
  };
  for (let index = 0; index < tiers.length; index += 1) {
    const limits = { ...tiers[index], truncated: false };
    const safeAnalysis = historySafeClone(analysis || {}, limits);
    const snapshot = {
      ...base,
      history_snapshot_truncated: reportWasTruncated || limits.truncated,
      analysis: safeAnalysis,
    };
    if (JSON.stringify(snapshot).length <= ANALYSIS_HISTORY_MAX_ENTRY_CHARS) {
      return snapshot;
    }
  }
  const fallback = {
    ...base,
    report_markdown: truncateHistoryText(safeReport, 80000),
    history_snapshot_truncated: true,
    analysis: historySafeClone(historyAnalysisFallback(analysis), tiers.at(-1)),
  };
  if (JSON.stringify(fallback).length <= ANALYSIS_HISTORY_MAX_ENTRY_CHARS) return fallback;
  return {
    ...base,
    report_markdown: truncateHistoryText(safeReport, 60000),
    history_snapshot_truncated: true,
    analysis: minimalHistoryAnalysis(analysis),
  };
}

function historySafeClone(value, limits, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === "string") {
    if (value.length > limits.stringLimit) limits.truncated = true;
    return truncateHistoryText(value, limits.stringLimit);
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value !== "object") return displayValue(value);
  if (depth >= limits.depthLimit) {
    limits.truncated = true;
    return "[깊이 제한으로 생략]";
  }
  if (seen.has(value)) {
    limits.truncated = true;
    return "[순환 참조 생략]";
  }
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > limits.arrayLimit) limits.truncated = true;
    const result = value
      .slice(0, limits.arrayLimit)
      .map((item) => historySafeClone(item, limits, depth + 1, seen));
    seen.delete(value);
    return result;
  }
  const result = {};
  const entries = Object.entries(value);
  if (entries.length > limits.objectLimit) limits.truncated = true;
  for (const [key, item] of entries.slice(0, limits.objectLimit)) {
    const normalizedKey = key
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/[^a-z0-9]+/gi, "_")
      .toLowerCase();
    if (HISTORY_FORBIDDEN_KEYS.test(normalizedKey)) continue;
    result[key] = historySafeClone(item, limits, depth + 1, seen);
  }
  seen.delete(value);
  return result;
}

function historyAnalysisFallback(analysis) {
  const source = analysis && typeof analysis === "object" && !Array.isArray(analysis)
    ? analysis
    : {};
  return {
    scope: source.scope,
    parser: source.parser,
    summary: source.summary,
    detection_meta: source.detection_meta,
    suspicious_event_scope: source.suspicious_event_scope,
    findings: asList(source.findings).slice(0, 12),
    suspicious_events: asList(source.suspicious_events).slice(0, 20),
    scenario_candidates: asList(source.scenario_candidates).slice(0, 8),
    attack_scenarios: asList(source.attack_scenarios).slice(0, 8),
    intrusion_chain: source.intrusion_chain,
    report_evidence_scope: source.report_evidence_scope,
    endpoint_rule_scope: source.endpoint_rule_scope,
    adaptive_time_range: source.adaptive_time_range,
    network_activity: source.network_activity,
    history_limitation: "브라우저 저장 한도로 대표 분석 근거만 보존되었습니다.",
  };
}

function minimalHistoryAnalysis(analysis) {
  const source = analysis && typeof analysis === "object" && !Array.isArray(analysis)
    ? analysis
    : {};
  const chain = source.intrusion_chain && typeof source.intrusion_chain === "object"
    ? source.intrusion_chain
    : {};
  const origin = chain.origin_process && typeof chain.origin_process === "object"
    ? chain.origin_process
    : null;
  const activity = source.network_activity && typeof source.network_activity === "object"
    ? source.network_activity
    : {};
  const summary = source.summary && typeof source.summary === "object"
    ? source.summary
    : {};
  const counterKeys = [
    "top_event_ids",
    "top_hosts",
    "top_accounts",
    "top_source_ips",
    "top_destination_ips",
    "top_destination_domains",
    "top_providers",
  ];
  const compactSummary = {};
  for (const key of counterKeys) compactSummary[key] = asList(summary[key]).slice(0, 8);
  return historySafeClone(
    {
      scope: source.scope,
      parser: {
        errors: asList(source.parser?.errors).slice(0, 5),
        truncated: source.parser?.truncated,
        record_limit_reached: source.parser?.record_limit_reached,
        network_scan_complete: source.parser?.network_scan_complete,
        network_spool_limit_reached: source.parser?.network_spool_limit_reached,
      },
      summary: compactSummary,
      detection_meta: source.detection_meta,
      suspicious_event_scope: source.suspicious_event_scope,
      findings: asList(source.findings).slice(0, 3),
      suspicious_events: asList(source.suspicious_events).slice(0, 5),
      scenario_candidates: asList(source.scenario_candidates).slice(0, 2),
      intrusion_chain: {
        status: chain.status,
        candidate_only: chain.candidate_only,
        confidence: chain.confidence,
        confidence_scope: chain.confidence_scope,
        origin_process: origin,
        origin_assessment: chain.origin_assessment,
        initiating_process_candidate: chain.initiating_process_candidate,
        observed_trigger_process: chain.observed_trigger_process,
        upstream_process_context: asList(chain.upstream_process_context).slice(0, 8),
        file_provenance: asList(chain.file_provenance).slice(0, 8),
        payload_artifacts: asList(chain.payload_artifacts).slice(0, 8),
        related_events: asList(chain.related_events).slice(0, 8),
        related_event_scope: {
          ...chain.related_event_scope,
          included_event_count: Math.min(asList(chain.related_events).length, 8),
          omitted_event_count: (Number(chain.related_event_scope?.omitted_event_count) || 0)
            + Math.max(0, asList(chain.related_events).length - 8),
          truncated: chain.related_event_scope?.truncated === true || asList(chain.related_events).length > 8,
        },
        steps: asList(chain.steps).slice(0, 8),
        truncated: chain.truncated === true || asList(chain.steps).length > 8,
        chain_truncated: chain.chain_truncated === true || asList(chain.steps).length > 8,
        limitations: [
          ...asList(chain.limitations).slice(0, 6),
          "브라우저 이력 용량 상한으로 침해 체인의 대표 단계만 보존되었습니다.",
        ],
      },
      adaptive_time_range: source.adaptive_time_range,
      network_activity: {
        ...Object.fromEntries(
          Object.entries(activity).filter(([, value]) => !Array.isArray(value)),
        ),
        connections: asList(activity.connections).filter(isC2Candidate).slice(0, 3),
        process_fanout_candidates: asList(activity.process_fanout_candidates).slice(0, 3),
      },
      history_limitation: "브라우저 저장 한도로 요약과 대표 분석 근거만 보존되었습니다.",
    },
    { arrayLimit: 12, objectLimit: 40, stringLimit: 1500, depthLimit: 7 },
  );
}

function historyLmMetadata(llm) {
  if (!llm || typeof llm !== "object" || Array.isArray(llm)) return {};
  const allowedKeys = [
    "backend",
    "used",
    "model",
    "duration_seconds",
    "validation_mode",
    "structured_report_validated",
    "structured_report_recovered",
    "unstructured_report_used",
    "validation_warnings",
    "input_truncated",
    "input_findings",
    "source_findings",
    "input_suspicious_events",
    "source_suspicious_events",
    "input_scenario_candidates",
    "source_scenario_candidates",
    "input_timeline",
    "source_timeline",
    "input_network_groups",
    "input_source_network_groups",
    "input_network_fanout_candidates",
    "input_source_network_fanout_candidates",
    "input_intrusion_chain",
    "input_adaptive_time_range",
    "input_hierarchical_context",
    "input_limitation",
    "lm_request_count",
    "hierarchical_analysis_enabled",
    "hierarchical_analysis_used",
    "hierarchical_skip_reason",
    "hierarchical_pipeline_error",
    "hierarchical_source_evidence_count",
    "hierarchical_unique_evidence_count",
    "hierarchical_selected_evidence_count",
    "hierarchical_evidence_included",
    "hierarchical_evidence_omitted",
    "hierarchical_repetition_omitted",
    "hierarchical_source_limit_reached",
    "hierarchical_chunk_count",
    "hierarchical_chunks_completed",
    "hierarchical_chunks_failed",
    "hierarchical_chunks_recovered",
    "report_fallback_used",
    "chunk_summaries_preserved",
    "partial_report_used",
    "report_evidence_count",
    "report_evidence_appended",
    "report_evidence_scope",
    "hierarchical_round_count",
    "hierarchical_request_count",
    "hierarchical_transport_request_count",
    "hierarchical_request_input_chars",
    "hierarchical_context_chars",
    "hierarchical_chunk_max_chars",
    "hierarchical_chunk_max_events",
    "hierarchical_chunks",
    "hierarchical_validation_warnings",
  ];
  const safe = {};
  for (const key of allowedKeys) {
    if (Object.prototype.hasOwnProperty.call(llm, key)) safe[key] = llm[key];
  }
  return historySafeClone(
    safe,
    { arrayLimit: 20, objectLimit: 80, stringLimit: 2000, depthLimit: 6 },
  );
}

function buildHistoryBasicSummary(analysis) {
  const safe = analysis && typeof analysis === "object" && !Array.isArray(analysis)
    ? analysis
    : {};
  const scope = safe.scope && typeof safe.scope === "object" ? safe.scope : {};
  const summary = safe.summary && typeof safe.summary === "object" ? safe.summary : {};
  const intrusionChain = safe.intrusion_chain && typeof safe.intrusion_chain === "object"
    ? safe.intrusion_chain
    : {};
  const originProcess = intrusionChain.origin_process && typeof intrusionChain.origin_process === "object"
    ? intrusionChain.origin_process
    : {};
  const topHost = asList(summary.top_hosts)[0];
  return {
    start_utc: displayValue(scope.start_utc),
    end_utc: displayValue(scope.end_utc),
    records_in_range: finiteCount(scope.records_in_range),
    finding_count: asList(safe.findings).length,
    suspicious_event_count: finiteCount(safe.detection_meta?.suspicious_events_total) ??
      asList(safe.suspicious_events).length,
    scenario_count: finiteCount(safe.detection_meta?.scenario_candidates_total) ??
      asList(safe.scenario_candidates).length,
    top_host: displayValue(topHost?.value),
    origin_process: displayValue(originProcess.process),
  };
}

function truncateHistoryText(value, limit, suffix = "…") {
  const text = String(value ?? "");
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - suffix.length))}${suffix}`;
}

function historyReportTitle(reportMarkdown) {
  const line = String(reportMarkdown || "")
    .split(/\r?\n/)
    .map((item) => item.replace(/^#{1,6}\s*/, "").trim())
    .find(Boolean);
  return truncateHistoryText(line || "CAT 침해사고 분석", 100);
}

function openAnalysisHistory() {
  renderAnalysisHistory();
  if (!historyDialog) return;
  if (typeof historyDialog.showModal === "function") historyDialog.showModal();
  else historyDialog.setAttribute("open", "");
}

function closeAnalysisHistory() {
  if (!historyDialog) return;
  if (typeof historyDialog.close === "function") historyDialog.close();
  else historyDialog.removeAttribute("open");
}

function handleHistoryBackdropClick(event) {
  if (event.target === historyDialog) closeAnalysisHistory();
}

function renderAnalysisHistory() {
  if (!historyList) return;
  const entries = readAnalysisHistory();
  if (historyStorageStatus) {
    historyStorageStatus.textContent = `${entries.length}/${ANALYSIS_HISTORY_MAX_ENTRIES}건 보관 중`;
  }
  clearHistoryButton && (clearHistoryButton.disabled = entries.length === 0);
  if (!entries.length) {
    historyList.innerHTML = '<p class="history-empty" role="listitem">저장된 분석 이력이 없습니다.</p>';
    return;
  }
  historyList.innerHTML = entries.map(renderAnalysisHistoryItem).join("");
}

function renderAnalysisHistoryItem(entry) {
  const basic = entry.basic_summary && typeof entry.basic_summary === "object"
    ? entry.basic_summary
    : {};
  const storedLlm = entry.llm && typeof entry.llm === "object" ? entry.llm : {};
  const when = formatHistoryTimestamp(entry.created_at);
  const range = basic.start_utc || basic.end_utc
    ? `${basic.start_utc || "시작 미지정"} ~ ${basic.end_utc || "종료 미지정"}`
    : "분석 시간 범위 미기록";
  const counts = [
    basic.records_in_range === null || basic.records_in_range === undefined
      ? ""
      : `범위 내 ${Number(basic.records_in_range).toLocaleString()}건`,
    `의심 이벤트 ${Number(basic.suspicious_event_count || 0).toLocaleString()}건`,
    `시나리오 ${Number(basic.scenario_count || 0).toLocaleString()}건`,
    storedLlm.hierarchical_analysis_used === true
      ? `분할 분석 ${Number(storedLlm.hierarchical_chunks_completed || 0).toLocaleString()}/${Number(storedLlm.hierarchical_chunk_count || 0).toLocaleString()} 청크`
      : "",
  ].filter(Boolean);
  const snapshotNotice = entry.history_snapshot_truncated === true
    ? '<span class="history-limit">저장 용량에 맞춘 대표 근거</span>'
    : "";
  return `<article class="history-item" role="listitem" data-history-id="${escapeHtml(entry.id)}">
    <div class="history-item-heading">
      <div>
        <h3>${escapeHtml(entry.title || "CAT 침해사고 분석")}</h3>
        <time datetime="${escapeHtml(entry.created_at)}">${escapeHtml(when)}</time>
      </div>
      ${snapshotNotice}
    </div>
    <p>${escapeHtml(range)}</p>
    <div class="meta">${counts.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("")}</div>
    ${basic.top_host ? `<p><strong>대표 호스트:</strong> ${escapeHtml(basic.top_host)}</p>` : ""}
    ${basic.origin_process ? `<p><strong>최초 침해 프로세스 후보:</strong> ${escapeHtml(basic.origin_process)}</p>` : ""}
    <div class="history-item-actions">
      <button type="button" data-history-action="restore">열기</button>
      <button type="button" data-history-action="delete" class="danger-button">삭제</button>
    </div>
  </article>`;
}

function formatHistoryTimestamp(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value || "시간 미기록";
  return new Intl.DateTimeFormat("ko-KR", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(parsed);
}

function handleHistoryAction(event) {
  const button = event.target.closest?.("button[data-history-action]");
  const item = button?.closest?.("[data-history-id]");
  if (!button || !item) return;
  const id = item.dataset.historyId;
  const entries = readAnalysisHistory();
  const entry = entries.find((candidate) => candidate.id === id);
  if (!entry) return;
  if (button.dataset.historyAction === "restore") {
    restoreAnalysisHistoryEntry(entry);
    return;
  }
  if (button.dataset.historyAction === "delete") {
    if (!window.confirm("이 분석 이력을 삭제하시겠습니까? 삭제 후 복구할 수 없습니다.")) return;
    writeAnalysisHistory(entries.filter((candidate) => candidate.id !== id));
    renderAnalysisHistory();
  }
}

function restoreAnalysisHistoryEntry(entry) {
  lastReport = String(entry.report_markdown || "");
  const restoredAnalysis = entry.analysis && typeof entry.analysis === "object"
    ? entry.analysis
    : {};
  lastAnalysis = {
    ...restoredAnalysis,
    history_snapshot_truncated: entry.history_snapshot_truncated === true,
  };
  try {
    renderReport(lastReport, entry.llm || {}, lastAnalysis);
  } catch {
    closeAnalysisHistory();
    showError("저장된 분석 이력을 복원하지 못했습니다. 이력을 삭제하고 원본 로그를 다시 분석하세요.");
    return;
  }
  try {
    renderFindings(lastAnalysis);
  } catch (renderError) {
    findingsView.innerHTML = `<p>저장된 탐지 결과 렌더링 경고: ${escapeHtml(renderError.message)}</p>`;
  }
  try {
    renderSummary(lastAnalysis);
  } catch (renderError) {
    summaryView.innerHTML = `<p>저장된 요약 렌더링 경고: ${escapeHtml(renderError.message)}</p>`;
  }
  if (savePdfButton) savePdfButton.disabled = !lastReport.trim();
  activateTab("report");
  closeAnalysisHistory();
}

function clearAnalysisHistory() {
  const entries = readAnalysisHistory();
  if (!entries.length) return;
  if (!window.confirm("저장된 분석 이력을 모두 삭제하시겠습니까? 삭제 후 복구할 수 없습니다.")) return;
  try {
    window.localStorage.removeItem(ANALYSIS_HISTORY_KEY);
  } catch {
    // Storage can be disabled by browser policy.
  }
  renderAnalysisHistory();
}

function initializeCatSelector() {
  if (!mainCatImage || !CAT_IMAGES.length) return;
  let preferredId = readPreference("cat.main_image");
  // Reset earlier saved photos once so the requested new main image is visible.
  // Choices made with the carousel after this migration still persist normally.
  if (!readPreference("cat.main_image_staring_default_v2")) {
    preferredId = "cat_staring.jpg";
    writePreference("cat.main_image", preferredId);
    writePreference("cat.main_image_staring_default_v2", "done");
  }
  const preferredIndex = CAT_IMAGES.findIndex((item) => item.id === preferredId);
  currentCatImageIndex = preferredIndex >= 0 ? preferredIndex : 0;
  renderCatImage();
}

function selectCatImage(direction) {
  if (!mainCatImage || !CAT_IMAGES.length) return;
  currentCatImageIndex = (
    currentCatImageIndex + direction + CAT_IMAGES.length
  ) % CAT_IMAGES.length;
  renderCatImage();
  writePreference("cat.main_image", CAT_IMAGES[currentCatImageIndex].id);
}

function renderCatImage() {
  if (!mainCatImage) return;
  const selected = CAT_IMAGES[currentCatImageIndex];
  mainCatImage.src = selected.src;
  mainCatImage.alt = selected.alt;
}

function handleCatSelectorKeydown(event) {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  event.preventDefault();
  selectCatImage(event.key === "ArrowLeft" ? -1 : 1);
}

function initializeCatCursor() {
  const cursor = document.querySelector("#catCursor");
  const cursorImage = document.querySelector("#catCursorImage");
  if (!cursor || !cursorImage || typeof window.matchMedia !== "function") return;
  const pointerMode = window.matchMedia("(hover: hover) and (pointer: fine)");
  const motionMode = window.matchMedia("(prefers-reduced-motion: reduce)");
  let imageReady = cursorImage.complete && cursorImage.naturalWidth > 0;
  let frame = 0;
  let pointerX = 0;
  let pointerY = 0;

  const hide = () => {
    if (frame) window.cancelAnimationFrame(frame);
    frame = 0;
    cursor.hidden = true;
    cursor.classList.remove("is-pressed");
    document.documentElement.classList.remove("cat-cursor-active");
  };
  const draw = () => {
    frame = 0;
    if (!imageReady || !pointerMode.matches || motionMode.matches || document.hidden) {
      hide();
      return;
    }
    // Keep the raised paw near the actual click point in both sprite halves.
    cursor.style.transform = `translate3d(${pointerX}px, ${pointerY}px, 0) translate(-25%, -12%)`;
    cursor.hidden = false;
    document.documentElement.classList.add("cat-cursor-active");
  };
  const move = (event, pressed = event.buttons > 0) => {
    if (event.pointerType !== "mouse" || !imageReady || !pointerMode.matches || motionMode.matches) {
      hide();
      return;
    }
    // A modal dialog lives above ordinary z-index layers. Keep the cursor in its layer.
    const container = event.target?.closest?.("dialog[open]") || document.body;
    if (cursor.parentElement !== container) container.append(cursor);
    cursor.classList.toggle("is-pressed", pressed);
    pointerX = event.clientX;
    pointerY = event.clientY;
    if (!frame) frame = window.requestAnimationFrame(draw);
  };
  cursorImage.addEventListener("load", () => { imageReady = cursorImage.naturalWidth > 0; });
  cursorImage.addEventListener("error", () => { imageReady = false; hide(); });
  document.addEventListener("pointermove", move, { passive: true });
  // Capture also observes presses/releases on controls that stop propagation.
  document.addEventListener("pointerdown", (event) => move(event, true), { passive: true, capture: true });
  document.addEventListener("pointerup", (event) => move(event), { passive: true, capture: true });
  document.documentElement.addEventListener("pointerleave", hide);
  document.addEventListener("pointercancel", hide);
  document.addEventListener("lostpointercapture", hide);
  document.addEventListener("dragstart", hide);
  document.addEventListener("visibilitychange", hide);
  document.addEventListener("close", hide, true);
  document.addEventListener("keydown", (event) => { if (event.key === "Tab") hide(); });
  window.addEventListener("blur", hide);
  window.addEventListener("beforeprint", hide);
  pointerMode.addEventListener?.("change", hide);
  motionMode.addEventListener?.("change", hide);
}

function resolveAnalysisPayload(data) {
  const response = data && typeof data === "object" ? data : {};
  const analysis =
    response.analysis &&
    typeof response.analysis === "object" &&
    !Array.isArray(response.analysis)
      ? response.analysis
      : {};
  return {
    ...analysis,
    parser: analysis.parser ?? response.parser,
    suspicious_events: analysis.suspicious_events ?? response.suspicious_events,
    scenario_candidates: analysis.scenario_candidates ?? response.scenario_candidates,
    attack_scenarios: analysis.attack_scenarios ?? response.attack_scenarios,
  };
}

function renderFindings(analysisOrFindings) {
  const analysis = Array.isArray(analysisOrFindings)
    ? { findings: analysisOrFindings }
    : analysisOrFindings || {};
  const findings = Array.isArray(analysis.findings)
    ? analysis.findings.filter((item) => item && typeof item === "object")
    : [];
  const suspiciousEvents = Array.isArray(analysis.suspicious_events)
    ? analysis.suspicious_events.filter((item) => item && typeof item === "object")
    : [];
  const canonicalScenarios = Array.isArray(analysis.scenario_candidates)
    ? analysis.scenario_candidates.filter((item) => item && typeof item === "object")
    : [];
  const compatibleScenarios = Array.isArray(analysis.attack_scenarios)
    ? analysis.attack_scenarios.filter((item) => item && typeof item === "object")
    : [];
  const scenarioCandidates = canonicalScenarios.length
    ? canonicalScenarios
    : compatibleScenarios;
  const networkActivity =
    analysis.network_activity &&
    typeof analysis.network_activity === "object" &&
    !Array.isArray(analysis.network_activity)
      ? analysis.network_activity
      : null;

  let suspiciousHtml = "";
  if (suspiciousEvents.length) {
    suspiciousHtml = suspiciousEvents.map(renderSuspiciousEvent).join("");
  } else if (findings.length) {
    suspiciousHtml = findings.map(renderFinding).join("");
  } else {
    suspiciousHtml = `<p>현재 룰 기준으로 탐지된 의심 이벤트가 없습니다.</p>`;
  }

  const scenarioHtml = scenarioCandidates.length
    ? scenarioCandidates.map(renderScenarioCandidate).join("")
    : `<p>연결 근거를 충족하는 2개 이상의 이벤트가 없어 구조화된 공격 시나리오 후보가 없습니다. 개별 의심 이벤트와 보고서 탭을 함께 확인하세요.</p>`;

  findingsView.innerHTML = `${renderParserWarning(analysis)}${renderDetectionMeta(analysis.detection_meta, analysis.suspicious_event_scope)}
    ${renderIntrusionChain(analysis.intrusion_chain)}
    <section aria-labelledby="suspiciousEventsTitle">
      <h2 id="suspiciousEventsTitle">의심 이벤트</h2>
      <div class="finding-list">${suspiciousHtml}</div>
    </section>
    ${renderNetworkActivityGroups(networkActivity)}
    <section aria-labelledby="scenarioCandidatesTitle">
      <h2 id="scenarioCandidatesTitle">공격 시나리오 후보</h2>
      <div class="finding-list">${scenarioHtml}</div>
    </section>`;
}

function renderIntrusionChain(chain) {
  if (!chain || typeof chain !== "object" || Array.isArray(chain)) return "";
  const origin = chain.origin_process && typeof chain.origin_process === "object"
    ? chain.origin_process
    : null;
  const steps = asList(chain.steps).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const limitations = uniqueText(asList(chain.limitations));
  const status = escapeHtml(chain.status || "근거 부족");
  if (!origin) {
    return `<section class="intrusion-chain" aria-label="침해 시발점 프로세스 추적">
      <h2>침해 시발점 프로세스 추적</h2>
      <p><strong>식별 상태:</strong> ${status}</p>
      <p>현재 EVTX/XML 근거만으로 시작 프로세스를 안전하게 식별하지 못했습니다.</p>
      ${renderOriginReviewLogs(chain)}
      ${renderValueList("분석 한계", limitations.slice(0, 6))}
    </section>`;
  }
  const parentContext = origin.parent_context && typeof origin.parent_context === "object"
    ? origin.parent_context
    : {};
  const originDetails = uniqueText([
    origin.process,
    origin.process_id ? `PID ${origin.process_id}` : "",
    origin.process_guid ? `GUID ${origin.process_guid}` : "",
    origin.start_time,
  ]);
  const parentDetails = uniqueText([
    origin.parent_process || parentContext.process,
    origin.parent_process_id || parentContext.process_id
      ? `PID ${origin.parent_process_id || parentContext.process_id}`
      : "",
    origin.parent_process_guid || parentContext.process_guid
      ? `GUID ${origin.parent_process_guid || parentContext.process_guid}`
      : "",
  ]);
  const stepRows = steps.map((step) => {
    const destination = formatNetworkEndpoint(
      step.destination_hostname || step.destination_ip,
      step.destination_port,
    );
    const evidenceRefs = uniqueText([
      ...asList(step.event_refs),
      ...asList(step.source_refs),
    ]);
    return `<tr>
      <td>${escapeHtml(step.order || "-")}</td>
      <td>${escapeHtml(step.time || "시간 불명")}</td>
      <td>${escapeHtml(step.phase || step.event_kind || "관측 행위")}</td>
      <td>${renderMultilineCell([
        step.process,
        step.process_id ? `PID ${step.process_id}` : "",
        step.process_guid ? `GUID ${step.process_guid}` : "",
      ])}</td>
      <td>${renderMultilineCell([
        step.query_name ? `DNS ${step.query_name}` : "",
        destination,
        step.target_filename,
        step.command_line,
        step.assessment,
      ])}${renderDecodedPowershell(step.decoded_powershell)}</td>
      <td>${evidenceRefs.length ? evidenceRefs.map(escapeHtml).join("<br>") : "-"}</td>
    </tr>`;
  }).join("");
  return `<section class="intrusion-chain" aria-label="침해 시발점 프로세스 추적">
    <h2>침해 시발점 프로세스 추적</h2>
    <p><strong>판정:</strong> 침해 확정이 아닌 시작 프로세스 후보 · 연결 신뢰도 ${escapeHtml(chain.confidence || "unknown")}</p>
    <p><strong>시작 후보:</strong> ${originDetails.length ? originDetails.map(escapeHtml).join(" / ") : "확인 불가"}</p>
    ${origin.command_line ? `<p><strong>명령줄:</strong> <code>${escapeHtml(origin.command_line)}</code></p>` : ""}
    ${renderOriginInvestigation(chain)}
    ${renderDecodedPowershell(origin.decoded_powershell)}
    ${parentDetails.length ? `<p><strong>부모 문맥:</strong> ${parentDetails.map(escapeHtml).join(" / ")}</p>` : ""}
    ${renderOriginReviewLogs(chain)}
    ${stepRows ? "<h3>연결된 후속 행위</h3>" : ""}
    ${stepRows ? `<table class="evidence-table intrusion-chain-table">
      <thead><tr><th>순서</th><th>시간</th><th>단계</th><th>프로세스</th><th>행위·목적지</th><th>근거</th></tr></thead>
      <tbody>${stepRows}</tbody>
    </table>` : "<p>표시할 후속 단계가 없습니다.</p>"}
    ${chain.truncated === true ? '<p class="scope-note"><strong>범위 주의:</strong> 상한에 맞춘 대표 체인입니다.</p>' : ""}
    ${renderValueList("체인 분석 한계", limitations)}
  </section>`;
}

function renderOriginReviewLogs(chain) {
  const events = asList(chain.related_events).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const scope = chain.related_event_scope || {};
  if (!events.length && !scope.truncated) return "";
  const rows = events.map((item) => {
    const refs = uniqueText([
      item.source_ref,
      ...asList(item.source_refs),
      ...asList(item.event_refs),
      item.source_file ? `${item.source_file}${item.record_id != null ? `#${item.record_id}` : ""}` : "",
    ]);
    const fields = item.fields && typeof item.fields === "object" && !Array.isArray(item.fields)
      ? Object.entries(item.fields).map(([name, value]) => `${name}: ${displayValue(value)}`).join("\n")
      : "";
    const details = uniqueText([
      eventValue(item, "process", "Image", "NewProcessName", "Application"),
      eventValue(item, "command_line", "CommandLine"),
      fields,
    ]).join("\n");
    return `<tr>
      <td>${renderMultilineCell([
        item.review_reason || "원인 프로세스와 연결된 로그",
        item.relationship_basis,
      ])}</td>
      <td>${renderMultilineCell([
        item.time || "시간 불명", `Event ID ${item.event_id ?? "미상"}`, item.host, item.provider, item.channel, ...refs,
      ])}</td>
      <td><pre><code>${escapeHtml(details || "상세 필드 없음")}</code></pre>
        ${renderDecodedPowershell(item.decoded_powershell)}
        ${asList(item.text_truncated_fields).length ? `<p class="scope-note">원문 필드 일부 생략: ${renderMultilineCell(item.text_truncated_fields)}</p>` : ""}
      </td>
    </tr>`;
  }).join("");
  return `<section class="origin-review" aria-label="분석관 우선 검토 로그">
    <h3>분석관 우선 검토 로그</h3>
    <p>침해 시발점과의 연결 근거를 검토할 수 있도록 관련 레코드와 원본 위치를 제공합니다.</p>
    ${rows ? `<table class="evidence-table"><thead><tr><th>검토 이유·연결 근거</th><th>시간·원본 로그</th><th>프로세스·명령·이벤트 필드</th></tr></thead><tbody>${rows}</tbody></table>` : ""}
    ${scope.truncated ? `<p class="scope-note">보존 상한으로 관련 로그 ${escapeHtml(scope.omitted_event_count ?? "일부")}건이 생략되었습니다.</p>` : ""}
    ${renderValueList("관련 로그 보존 한계", scope.limitations)}
  </section>`;
}

function renderOriginInvestigation(chain) {
  const trigger = chain.observed_trigger_process;
  const context = asList(chain.upstream_process_context).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const provenance = asList(chain.file_provenance).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const assessment = chain.origin_assessment;
  const assessmentText = typeof assessment === "string" ? assessment
    : assessment?.description || assessment?.assessment || assessment?.note || chain.origin_process?.assessment;
  const contextRows = context.map((item) => `<tr>
    <td>${escapeHtml(item.start_time || item.time || "시간 불명")}</td>
    <td>${renderMultilineCell([item.process, item.process_id ? `PID ${item.process_id}` : "", item.command_line])}</td>
    <td>${renderMultilineCell([item.relationship_basis || item.parent_link_basis, item.assessment || item.note, item.source_ref])}</td>
  </tr>`).join("");
  const fileRows = provenance.map((item) => `<tr>
    <td>${escapeHtml(item.time || item.creation_time || "시간 불명")}</td>
    <td>${escapeHtml(item.target_filename || item.path || item.target_file || "-")}</td>
    <td>${renderMultilineCell([item.creator_process?.process || item.creator_process || item.process, item.creator_process_id ? `PID ${item.creator_process_id}` : "", item.relationship_basis, item.source_ref, ...asList(item.source_refs), item.assessment || item.note, item.limitation])}</td>
  </tr>`).join("");
  const artifacts = asList(chain.payload_artifacts).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const artifactRows = artifacts.map((item) => `<tr>
    <td>${escapeHtml(item.process || "-")}</td>
    <td>${escapeHtml(item.referenced_path || "-")}</td>
    <td>${renderMultilineCell([item.source_ref, ...asList(item.creation_source_refs), item.limitation])}</td>
  </tr>`).join("");
  return `${assessmentText ? `<p><strong>최초 유발 원인 평가:</strong> ${escapeHtml(assessmentText)}</p>` : ""}
    ${trigger?.process ? `<p><strong>관측된 의심 실행:</strong> ${escapeHtml(trigger.process)}${trigger.process_id ? ` / PID ${escapeHtml(trigger.process_id)}` : ""} · ${escapeHtml(trigger.start_time || "시작 시각 불명")}</p>` : ""}
    ${contextRows ? `<h3>상위 프로세스 추적 근거</h3><table class="evidence-table"><thead><tr><th>시간</th><th>프로세스·명령</th><th>연결 근거</th></tr></thead><tbody>${contextRows}</tbody></table>` : ""}
    ${fileRows ? `<h3>실행 파일 유입·생성 근거</h3><table class="evidence-table"><thead><tr><th>시간</th><th>생성 파일</th><th>생성 프로세스·원본 근거</th></tr></thead><tbody>${fileRows}</tbody></table>` : ""}
    ${artifactRows ? `<h3>실행 도구에 전달된 파일</h3><table class="evidence-table"><thead><tr><th>실행 도구</th><th>참조한 파일</th><th>참조·생성 근거와 한계</th></tr></thead><tbody>${artifactRows}</tbody></table>` : ""}
    ${renderValueList("최초 유입 확인에 필요한 근거", assessment?.missing_evidence)}`;
}

function renderDecodedPowershell(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.status === "not_encoded") return "";
  const scripts = asList(value.decoded_scripts).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const statusLabels = {
    decoded: "디코딩됨", partial: "일부 디코딩", invalid: "디코딩 불가",
    failed: "디코딩 불가", unsupported: "정적 디코딩 범위 밖",
  };
  const bodies = scripts.map((item) => `<div class="decoded-script">
    <p>${renderMultilineCell([
      item.source, item.method, item.encoding, item.depth ? `깊이 ${item.depth}` : "",
    ])}</p>
    <pre><code>${escapeHtml(item.text || "")}</code></pre>
    ${renderValueList("정적 분석 신호", item.signals)}
    ${item.text_truncated ? '<p class="scope-note">디코딩 본문이 보존 상한으로 일부 생략되었습니다.</p>' : ""}
  </div>`).join("");
  return `<section class="decoded-powershell" aria-label="PowerShell Base64 정적 분석">
    <h4>PowerShell Base64 분석 · ${escapeHtml(statusLabels[value.status] || value.status || "검사됨")}</h4>
    <p>실행 없이 디코딩한 내용입니다. 실제 실행 및 침해 여부는 프로세스·통신 근거와 함께 판단합니다.</p>
    ${bodies}${renderValueList("디코딩 한계", value.warnings)}
  </section>`;
}

function renderNetworkActivityGroups(activity) {
  if (!activity) return "";
  const connections = asList(activity.connections).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const fanoutCandidates = asList(activity.process_fanout_candidates).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const groupHtml = connections.length
    ? connections.map(renderNetworkConnectionGroup).join("")
    : `<p>현재 입력에서 정규화할 수 있는 네트워크 연결 그룹이 없습니다.</p>`;
  const fanoutHtml = fanoutCandidates.length
    ? fanoutCandidates.map(renderProcessFanoutCandidate).join("")
    : `<p>현재 입력에서 프로세스 fan-out 후보가 없습니다.</p>`;
  const scope = activity.limitation
    ? `<p><strong>분석 범위와 한계:</strong> ${escapeHtml(activity.limitation)}</p>`
    : "";
  const candidateSummary = renderC2CandidateSummary(
    activity,
    connections,
    fanoutCandidates,
  );
  return `<section aria-labelledby="networkActivityTitle">
    <h2 id="networkActivityTitle">네트워크 통신 그룹</h2>
    <p>프로세스·목적지·포트·프로토콜·방향이 같은 통신을 묶은 조사용 요약입니다. 외부 또는 반복 통신이라는 이유만으로 침해가 확정되지는 않습니다.</p>
    ${candidateSummary}
    ${scope}
    <div class="finding-list">${groupHtml}</div>
    <h3>프로세스 fan-out 후보</h3>
    <p>같은 프로세스 인스턴스가 10분 안에 여러 외부 목적지 또는 포트로 통신한 경우를 별도로 요약합니다.</p>
    <div class="finding-list">${fanoutHtml}</div>
  </section>`;
}

function isC2Candidate(group) {
  return group?.c2_candidate === true ||
    (group?.c2_candidate === undefined && group?.suspicious === true);
}

function finiteCount(value) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "boolean") return null;
  const count = Number(value);
  return Number.isSafeInteger(count) && count >= 0 ? count : null;
}

function renderC2CandidateSummary(activity, connections, fanoutCandidates) {
  const displayedConnectionCandidates = connections.filter(isC2Candidate).length;
  const reportedConnectionTotal = finiteCount(activity.suspicious_group_count);
  const reportedFanoutTotal = finiteCount(activity.process_fanout_candidate_count);
  const connectionTotal = reportedConnectionTotal ??
    displayedConnectionCandidates;
  const fanoutTotal = reportedFanoutTotal ??
    fanoutCandidates.length;
  const aggregateTotal = reportedConnectionTotal !== null && reportedFanoutTotal !== null
    ? connectionTotal + fanoutTotal
    : finiteCount(activity.c2_candidate_count) ?? connectionTotal + fanoutTotal;
  const connectionLowerBound = activity.group_state_limit_reached === true ||
    activity.correlation_index_limit_reached === true;
  const fanoutLowerBound = activity.fanout_state_limit_reached === true;
  const aggregateLowerBound = connectionLowerBound || fanoutLowerBound;
  const displayLimited = connectionTotal > displayedConnectionCandidates ||
    fanoutTotal > fanoutCandidates.length;
  const displayNotice = displayLimited
    ? ` 표시된 상세는 목적지 그룹 ${displayedConnectionCandidates}/${formatC2Score(connectionTotal)}건, 프로세스 fan-out ${fanoutCandidates.length}/${formatC2Score(fanoutTotal)}건입니다.`
    : "";
  return `<p><strong>C2 통신 후보 합계(휴리스틱):</strong> ${escapeHtml(boundedCountLabel(aggregateTotal, aggregateLowerBound))} (목적지 그룹 ${escapeHtml(boundedCountLabel(connectionTotal, connectionLowerBound))}, 프로세스 fan-out ${escapeHtml(boundedCountLabel(fanoutTotal, fanoutLowerBound))}). 실제 명령제어 통신 판정이 아닙니다.${escapeHtml(displayNotice)}</p>`;
}

function renderNetworkConnectionGroup(group) {
  const destinationPort = eventValue(
    group,
    "destination_port",
    "DestinationPort",
    "DestPort",
  );
  const destinationIps = uniqueText([
    eventValue(group, "destination_ip", "DestinationIp", "DestAddress"),
    ...asList(group.destination_ips),
  ]);
  const destinationAddresses = destinationIps.length
    ? destinationIps.map((address) => formatNetworkEndpoint(address, destinationPort))
    : [formatNetworkEndpoint("", destinationPort)];
  const destinationNames = uniqueText([
    eventValue(group, "destination_hostname", "DestinationHostname"),
    ...asList(group.dns_queries),
    ...destinationAddresses,
  ]);
  const source = formatNetworkEndpoint(
    eventValue(group, "source_ip", "SourceIp", "SourceAddress"),
    eventValue(group, "source_port", "SourcePort"),
  );
  const process = eventValue(group, "process", "Image", "Application");
  const processId = eventValue(group, "process_id", "ProcessId", "ProcessID");
  const processGuid = eventValue(group, "process_guid", "ProcessGuid");
  const processInstanceId = eventValue(group, "process_instance_id");
  const protocol = eventValue(group, "protocol", "Protocol");
  const direction = eventValue(group, "network_direction", "Direction");
  const c2Candidate = isC2Candidate(group);
  const c2Score = normalizedC2Score(group.c2_score);
  const c2ScoreLevel = displayValue(group.c2_score_level).trim();
  const normalizedLevel = c2ScoreLevel.toLowerCase();
  const severity = c2Candidate
    ? (["critical", "high"].includes(normalizedLevel)
        ? "high"
        : normalizedLevel === "low"
          ? "low"
          : "medium")
    : "info";
  const c2ScorePill = c2Score === null
    ? ""
    : `<span class="pill">C2 후보 점수 ${escapeHtml(formatC2Score(c2Score))}/100${c2ScoreLevel ? ` · ${escapeHtml(c2ScoreLevel)}` : ""}</span>`;
  const destinationLabel = destinationNames[0] || "목적지 미상";
  const connectionCount = Number(group.connection_count || 0);
  const countLabel = Number.isFinite(connectionCount)
    ? connectionCount.toLocaleString()
    : "-";
  return `<section class="finding ${severity}">
    <h3>${escapeHtml(process || "프로세스 미상")} → ${escapeHtml(destinationLabel)}</h3>
    <div class="meta">
      <span class="pill">${c2Candidate ? "C2 통신 후보 (휴리스틱)" : "관측 통신"}</span>
      ${c2ScorePill}
      <span class="pill">${escapeHtml(countLabel)}회</span>
      <span class="pill">${escapeHtml(group.first_seen || "-")} ~ ${escapeHtml(group.last_seen || "-")}</span>
    </div>
    <table class="evidence-table">
      <thead><tr><th>출발지</th><th>목적지 / DNS</th><th>프로토콜 / 방향</th><th>프로세스 / PID·GUID</th></tr></thead>
      <tbody><tr>
        <td>${escapeHtml(source || "-")}</td>
        <td>${renderMultilineCell(destinationNames)}</td>
        <td>${renderMultilineCell([protocol, direction])}</td>
        <td>${renderMultilineCell([
          process,
          processId ? `PID ${processId}` : "",
          processGuid ? `GUID ${processGuid}` : "",
          processInstanceId ? `프로세스 인스턴스 ${processInstanceId}` : "",
        ])}</td>
      </tr></tbody>
    </table>
    ${renderValueList("이상 징후", group.anomaly_signals)}
    ${renderValueList("C2 후보 점수 근거", formatC2ScoreComponents(group.c2_score_components))}
    ${renderValueList("프로세스·DNS 상관 근거", group.correlation_reasons)}
  </section>`;
}

function renderProcessFanoutCandidate(candidate) {
  const process = eventValue(candidate, "process", "Image", "Application");
  const processId = eventValue(candidate, "process_id", "ProcessId", "ProcessID");
  const processGuid = eventValue(candidate, "process_guid", "ProcessGuid");
  const processInstanceId = eventValue(candidate, "process_instance_id");
  const c2Score = normalizedC2Score(candidate.c2_score);
  const c2ScoreLevel = displayValue(candidate.c2_score_level).trim();
  const destinationCount = finiteCount(candidate.fanout_destination_count);
  const portCount = finiteCount(candidate.fanout_port_count);
  const connectionCount = finiteCount(candidate.connection_count);
  const destinations = uniqueText([
    ...asList(candidate.candidate_destinations),
    ...asList(candidate.destination_ips),
    eventValue(candidate, "destination_hostname", "DestinationHostname"),
    eventValue(candidate, "destination_ip", "DestinationIp", "DestAddress"),
  ]);
  const ports = uniqueText([
    ...asList(candidate.candidate_ports),
    eventValue(candidate, "destination_port", "DestinationPort", "DestPort"),
  ]);
  const scoreLabel = c2Score === null
    ? "점수 미지정"
    : `C2 후보 점수 ${formatC2Score(c2Score)}/100${c2ScoreLevel ? ` · ${c2ScoreLevel}` : ""}`;
  return `<section class="finding ${c2ScoreLevel.toLowerCase() === "high" ? "high" : "medium"}">
    <h3>${escapeHtml(process || "프로세스 미상")}의 다수 목적지 통신</h3>
    <div class="meta">
      <span class="pill">프로세스 fan-out C2 후보 (휴리스틱)</span>
      <span class="pill">${escapeHtml(scoreLabel)}</span>
      ${connectionCount === null ? "" : `<span class="pill">연결 ${escapeHtml(formatC2Score(connectionCount))}회</span>`}
      <span class="pill">${escapeHtml(candidate.first_seen || "-")} ~ ${escapeHtml(candidate.last_seen || "-")}</span>
    </div>
    <table class="evidence-table">
      <thead><tr><th>호스트</th><th>프로세스 / PID·GUID</th><th>목적지</th><th>포트</th></tr></thead>
      <tbody><tr>
        <td>${escapeHtml(candidate.host || "-")}</td>
        <td>${renderMultilineCell([
          process,
          processId ? `PID ${processId}` : "",
          processGuid ? `GUID ${processGuid}` : "",
          processInstanceId ? `프로세스 인스턴스 ${processInstanceId}` : "",
        ])}</td>
        <td>${renderMultilineCell([
          destinationCount === null ? "" : `고유 목적지 ${formatC2Score(destinationCount)}개`,
          ...destinations,
        ])}</td>
        <td>${renderMultilineCell([
          portCount === null ? "" : `고유 포트 ${formatC2Score(portCount)}개`,
          ...ports,
        ])}</td>
      </tr></tbody>
    </table>
    ${renderValueList("이상 징후", candidate.anomaly_signals)}
    ${renderValueList("C2 후보 점수 근거", formatC2ScoreComponents(candidate.c2_score_components))}
    ${renderValueList("프로세스·DNS 상관 근거", candidate.correlation_reasons)}
  </section>`;
}

function renderPrintAnalysisAppendix(analysis, llm) {
  const safeAnalysis = analysis && typeof analysis === "object" && !Array.isArray(analysis)
    ? analysis
    : {};
  const findings = asList(safeAnalysis.findings).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const suspiciousEvents = asList(safeAnalysis.suspicious_events).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const scenarios = asList(
    asList(safeAnalysis.scenario_candidates).length
      ? safeAnalysis.scenario_candidates
      : safeAnalysis.attack_scenarios,
  ).filter((item) => item && typeof item === "object" && !Array.isArray(item));
  const intrusionHtml = suspiciousEvents.length
    ? suspiciousEvents.map(renderSuspiciousEvent).join("")
    : findings.length
      ? findings.map(renderFinding).join("")
      : "<p>현재 로컬 규칙 기준으로 탐지된 침해행위 후보가 없습니다.</p>";
  const scenarioHtml = scenarios.length
    ? scenarios.map(renderScenarioCandidate).join("")
    : "<p>연결 근거를 충족한 공격 시나리오 후보가 없습니다.</p>";
  const limitations = collectPrintEvidenceLimitations(safeAnalysis, llm);
  const limitationHtml = limitations.length
    ? `<ul>${limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "<p>CAT가 별도로 기록한 증거 제한 사항이 없습니다. 다만 EVTX/XML에 기록되지 않은 행위까지 부재한 것으로 단정할 수는 없습니다.</p>";
  return `<section class="print-only print-analysis-appendix" aria-label="CAT 요약 및 침해행위 분석 부록">
    <h1>CAT 분석 데이터 부록</h1>
    <p>LM 보고서와 함께 분석관이 교차 검토할 수 있도록 CAT가 계산한 요약과 로컬 탐지 근거를 수록합니다.</p>
    <h2>CAT 요약 내용</h2>
    ${renderSummaryContents(safeAnalysis, false)}
    ${renderIntrusionChain(safeAnalysis.intrusion_chain)}
    <h2>침해행위 및 탐지 결과</h2>
    ${renderDetectionMeta(safeAnalysis.detection_meta, safeAnalysis.suspicious_event_scope)}
    <div class="finding-list">${intrusionHtml}</div>
    <h2>공격 시나리오 후보</h2>
    <div class="finding-list">${scenarioHtml}</div>
    <h2>증거 및 분석 한계</h2>
    ${limitationHtml}
  </section>`;
}

function collectPrintEvidenceLimitations(analysis, llm) {
  const parser = analysis.parser && typeof analysis.parser === "object"
    ? analysis.parser
    : {};
  const scope = analysis.scope && typeof analysis.scope === "object"
    ? analysis.scope
    : {};
  const network = analysis.network_activity && typeof analysis.network_activity === "object"
    ? analysis.network_activity
    : {};
  const eventScope = analysis.suspicious_event_scope && typeof analysis.suspicious_event_scope === "object"
    ? analysis.suspicious_event_scope
    : {};
  const adaptiveRange = analysis.adaptive_time_range && typeof analysis.adaptive_time_range === "object"
    ? analysis.adaptive_time_range
    : {};
  const intrusionChain = analysis.intrusion_chain && typeof analysis.intrusion_chain === "object"
    ? analysis.intrusion_chain
    : {};
  const values = [
    ...asList(analysis.evidence_limitations).map(formatEvidenceLimitation),
    ...asList(analysis.report_evidence_scope?.limitations).map(formatEvidenceLimitation),
    ...asList(intrusionChain.limitations).map(formatEvidenceLimitation),
    ...asList(intrusionChain.related_event_scope?.limitations).map(formatEvidenceLimitation),
    ...asList(parser.errors),
    ...asList(llm?.hierarchical_validation_warnings),
    ...asList(llm?.validation_warnings),
    scope.note,
    eventScope.note,
    network.limitation,
    adaptiveRange.expansion_error,
    llm?.hierarchical_pipeline_error,
    llm?.input_limitation,
    analysis.history_limitation,
  ];
  if (parser.truncated === true || scope.truncated === true) {
    values.push("입력 파싱 또는 분석 제한으로 일부 이벤트가 분석에서 제외되었을 수 있습니다.");
  }
  if (parser.record_limit_reached === true || scope.record_limit_reached === true) {
    values.push("일반 이벤트 상세 보관 상한에 도달하여 대표 레코드만 유지되었을 수 있습니다.");
  }
  if (parser.network_scan_complete === false || scope.network_scan_complete === false) {
    values.push("C2 및 네트워크 상관용 입력 스캔이 파일 끝까지 완료되지 않았습니다.");
  }
  if (llm?.input_truncated === true) {
    values.push("로컬 분석 결과 중 우선순위가 높은 근거 일부만 LM 입력에 포함되었습니다.");
  }
  if (intrusionChain.truncated === true || intrusionChain.chain_truncated === true) {
    values.push("최초 침해 프로세스와 후속 흐름은 분석 상한에 맞춘 대표 체인이며 전체 행위가 아닐 수 있습니다.");
  }
  if (intrusionChain.source?.source_scan_complete === false) {
    values.push("최초 침해 프로세스 상관을 위한 입력 스캔이 파일 끝까지 완료되지 않았습니다.");
  }
  const hierarchicalFailures = finiteCount(llm?.hierarchical_chunks_failed) ?? 0;
  const hierarchicalOmitted = finiteCount(llm?.hierarchical_evidence_omitted) ?? 0;
  const hierarchicalRepetitionsOmitted = finiteCount(llm?.hierarchical_repetition_omitted) ?? 0;
  if (hierarchicalFailures) {
    const recovered = finiteCount(llm?.hierarchical_chunks_recovered) ?? 0;
    values.push(`계층형 LM 시간 청크 ${hierarchicalFailures}개에서 응답을 얻지 못했습니다. 그중 ${recovered}개는 해당 구간의 로컬 근거 요약으로 보완했습니다.`);
  }
  if (llm?.report_fallback_used === true) {
    values.push("최종 LM 보고서 대신 로컬 분석 보고서와 보존된 청크 요약을 사용했습니다.");
  }
  if (hierarchicalOmitted) {
    values.push(`계층형 분석 입력 상한으로 선별 근거 ${hierarchicalOmitted}건이 시간 청크 입력에서 제외되었습니다.`);
  }
  if (hierarchicalRepetitionsOmitted) {
    values.push(`동일·반복 계층형 근거 ${hierarchicalRepetitionsOmitted}건은 핵심 패턴만 남기도록 축약되었습니다.`);
  }
  if (llm?.hierarchical_source_limit_reached === true) {
    values.push("계층형 분석의 원천 증거 수집 상한에 도달하여 후반부 후보가 제외되었을 수 있습니다.");
  }
  if (analysis.history_limitation || analysis.history_snapshot_truncated === true) {
    values.push("브라우저 분석 이력에서 복원된 대표 증거일 수 있으므로 원본 로그로 재검증해야 합니다.");
  }
  return uniqueText(values);
}

function formatEvidenceLimitation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return displayValue(value);
  const title = displayValue(value.title || value.type || value.code);
  const detail = displayValue(value.description || value.detail || value.message);
  return title && detail ? `${title}: ${detail}` : title || detail || displayValue(value);
}

function renderPrintNetworkAppendix(analysis) {
  const safeAnalysis = analysis && typeof analysis === "object" && !Array.isArray(analysis)
    ? analysis
    : {};
  const activity = safeAnalysis.network_activity &&
    typeof safeAnalysis.network_activity === "object" &&
    !Array.isArray(safeAnalysis.network_activity)
      ? safeAnalysis.network_activity
      : {};
  const findings = asList(safeAnalysis.findings).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item) &&
      NETWORK_FINDING_RULE_IDS.has(String(item.rule_id || "")),
  );
  const connections = asList(activity.connections).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item) &&
      isC2Candidate(item),
  );
  const fanoutCandidates = asList(activity.process_fanout_candidates).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const hasNetworkActivity = [
    "source_network_record_count",
    "connection_event_count",
    "dns_query_event_count",
    "c2_candidate_count",
    "limitation",
  ].some((key) => Object.prototype.hasOwnProperty.call(activity, key));
  if (!hasNetworkActivity && !findings.length && !connections.length && !fanoutCandidates.length) {
    return "";
  }

  const findingHtml = findings.length
    ? `<h3>로컬 규칙 네트워크 finding</h3><div class="finding-list">${findings.map(renderFinding).join("")}</div>`
    : "";
  const connectionHtml = connections.length
    ? `<h3>C2 목적지 그룹</h3><div class="finding-list">${connections.map(renderNetworkConnectionGroup).join("")}</div>`
    : "";
  const fanoutHtml = fanoutCandidates.length
    ? `<h3>프로세스 fan-out 후보</h3><div class="finding-list">${fanoutCandidates.map(renderProcessFanoutCandidate).join("")}</div>`
    : "";
  const limitation = activity.limitation
    ? `<p><strong>분석 범위와 한계:</strong> ${escapeHtml(activity.limitation)}</p>`
    : "";
  const candidateSummary = hasNetworkActivity
    ? renderC2CandidateSummary(activity, asList(activity.connections), fanoutCandidates)
    : "";
  return `<section class="print-only print-network-appendix" aria-label="CAT 로컬 C2 및 네트워크 탐지 근거">
    <h2>CAT 로컬 C2/네트워크 탐지 근거</h2>
    <p>이 부록은 LM 보고서 원문과 별개인 CAT 로컬 규칙 결과입니다. 휴리스틱 후보이며 실제 명령제어 통신 판정이 아닙니다.</p>
    ${candidateSummary}
    ${limitation}
    ${findingHtml}${connectionHtml}${fanoutHtml}
  </section>`;
}

function normalizedC2Score(value) {
  if (value === undefined || value === null || value === "") return null;
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  return Math.max(0, Math.min(100, score));
}

function formatC2Score(value) {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatC2ScoreComponents(components) {
  if (!components || typeof components !== "object") return [];
  if (Array.isArray(components)) return components;
  return Object.entries(components)
    .filter(([, points]) => Number.isFinite(Number(points)) && Number(points) > 0)
    .map(([name, points]) => {
      const label = C2_SCORE_COMPONENT_LABELS[name] || name.replaceAll("_", " ");
      return `${label}: +${formatC2Score(Number(points))}점`;
    });
}

function renderSuspiciousEvent(item) {
  const matchedRules = asList(item.matched_rules).filter(
    (rule) => rule && typeof rule === "object",
  );
  const ruleIds = uniqueText([
    ...asList(item.rule_ids),
    ...matchedRules.map((rule) => rule.rule_id),
  ]);
  const reasons = uniqueText(
    [...asList(item.reasons), ...matchedRules.map((rule) => rule.reason)].map(
      formatReason,
    ),
  );
  const eventRef = item.event_ref || item.event_uid || "-";
  const severity = item.severity || matchedRules[0]?.severity || "info";
  const confidence = item.confidence || matchedRules[0]?.confidence || "-";

  return `<section class="finding ${escapeHtml(severity)}">
    <h3>${escapeHtml(item.title || `이벤트 ${eventRef}`)}</h3>
    <div class="meta">
      <span class="pill">${escapeHtml(severity)}</span>
      <span class="pill">신뢰도 ${escapeHtml(confidence)}</span>
      <span class="pill">${escapeHtml(eventRef)}</span>
      <span class="pill">${escapeHtml(item.time || "-")}</span>
    </div>
    <p><strong>탐지 규칙:</strong> ${ruleIds.length ? ruleIds.map(escapeHtml).join(", ") : "-"}</p>
    ${renderValueList("의심 근거", reasons)}
    <table class="evidence-table">
      <thead><tr><th>Event ID</th><th>호스트 / 계정</th><th>출발지</th><th>목적지 / DNS / 통신</th><th>명령 / 프로세스 / PID·GUID</th></tr></thead>
      <tbody>${renderEvidenceRow(item, false)}</tbody>
    </table>
    <p><strong>원본 위치:</strong> ${escapeHtml(item.provider || "-")} / ${escapeHtml(item.channel || "-")} / ${escapeHtml(item.source_file || "-")} / record ${escapeHtml(item.record_id || "-")}</p>
    ${renderEventFields(item.fields)}
    ${renderDecodedPowershell(item.decoded_powershell)}
  </section>`;
}

function renderScenarioCandidate(scenario) {
  const stages = Array.isArray(scenario.stages)
    ? scenario.stages.filter((item) => item && typeof item === "object")
    : Array.isArray(scenario.steps)
      ? scenario.steps.filter((item) => item && typeof item === "object")
      : [];
  const eventRefs = uniqueText([
    ...asList(scenario.event_refs),
    ...asList(scenario.event_uids),
  ]);
  const severity = scenario.severity || "info";
  const stageRows = [...stages]
    .sort((left, right) => Number(left.order || 0) - Number(right.order || 0))
    .map((stage) => {
      const refs = uniqueText([
        ...asList(stage.event_ref),
        ...asList(stage.event_uids),
      ]);
      return `<tr>
        <td>${escapeHtml(stage.order || "-")}</td>
        <td>${escapeHtml(stage.phase || "-")}</td>
        <td>${escapeHtml(stage.description || stage.label || "-")}</td>
        <td>${refs.length ? refs.map(escapeHtml).join(", ") : "-"}</td>
      </tr>`;
    })
    .join("");
  const factValues = asList(scenario.link_reasons).length
    ? scenario.link_reasons
    : scenario.observed_facts;
  const facts = asList(factValues).map(formatScenarioFact);
  const alternatives = asList(scenario.alternative_explanations).length
    ? scenario.alternative_explanations
    : scenario.not_proven;

  return `<section class="finding ${escapeHtml(severity)}">
    <h3>${escapeHtml(scenario.title || scenario.scenario_id || "공격 시나리오 후보")}</h3>
    <div class="meta">
      <span class="pill">${escapeHtml(scenario.scenario_id || "-")}</span>
      <span class="pill">신뢰도 ${escapeHtml(scenario.confidence || "-")}</span>
      ${scenario.severity ? `<span class="pill">${escapeHtml(scenario.severity)}</span>` : ""}
      ${scenario.status ? `<span class="pill">${escapeHtml(scenario.status)}</span>` : ""}
      ${scenario.correlation_rule_id ? `<span class="pill">${escapeHtml(scenario.correlation_rule_id)}</span>` : ""}
    </div>
    <p><strong>연결 이벤트:</strong> ${eventRefs.length ? eventRefs.map(escapeHtml).join(", ") : "-"}</p>
    <p><strong>가설:</strong> ${escapeHtml(scenario.hypothesis || "-")}</p>
    ${stageRows ? `<h4>공격 단계</h4>
      <table class="evidence-table">
        <thead><tr><th>순서</th><th>단계</th><th>설명</th><th>이벤트 참조</th></tr></thead>
        <tbody>${stageRows}</tbody>
      </table>` : ""}
    ${renderValueList("연결 근거", facts)}
    ${renderValueList("대안 설명 / 아직 입증되지 않은 사항", alternatives)}
    ${renderValueList("추가 증거 필요 사항", scenario.evidence_gaps)}
    ${renderValueList("권장 다음 단계", scenario.recommended_next_steps)}
    ${renderScenarioEntities(scenario.entities)}
  </section>`;
}

function renderDetectionMeta(meta, eventScope) {
  const safeMeta = meta && typeof meta === "object" ? meta : {};
  const safeScope = eventScope && typeof eventScope === "object" ? eventScope : {};
  const eventTotal = safeMeta.suspicious_events_total;
  const eventIncluded = safeMeta.suspicious_events_included;
  const scenarioTotal =
    safeMeta.scenario_candidates_total ?? safeMeta.attack_scenarios_total;
  const scenarioIncluded =
    safeMeta.scenario_candidates_included ?? safeMeta.attack_scenarios_included;
  const parts = [];
  if (eventTotal !== undefined || eventIncluded !== undefined) {
    parts.push(`의심 이벤트 ${eventIncluded ?? "-"} / ${eventTotal ?? "-"}`);
  } else if (safeScope.included_count !== undefined) {
    const findingCount =
      safeScope.finding_event_count !== undefined
        ? ` / finding 근거 집계 ${safeScope.finding_event_count}건`
        : "";
    parts.push(`고유 의심 이벤트 ${safeScope.included_count}건${findingCount}`);
  }
  if (scenarioTotal !== undefined || scenarioIncluded !== undefined) {
    parts.push(`공격 시나리오 후보 ${scenarioIncluded ?? "-"} / ${scenarioTotal ?? "-"}`);
  }
  const truncated =
    safeMeta.suspicious_events_truncated === true ||
    safeMeta.scenario_candidates_truncated === true ||
    safeMeta.attack_scenarios_truncated === true ||
    safeScope.evidence_truncated === true;
  const scopeNote = safeScope.note
    ? `<p><strong>범위 참고:</strong> ${escapeHtml(safeScope.note)}</p>`
    : "";
  const summary = parts.length
    ? `<p><strong>표시 범위:</strong> ${parts.map(escapeHtml).join(", ")}${truncated ? " (대표 근거만 포함될 수 있음)" : ""}</p>`
    : "";
  return `${summary}${scopeNote}`;
}

function renderScenarioEntities(entities) {
  if (!entities || typeof entities !== "object" || Array.isArray(entities)) return "";
  const rows = Object.entries(entities)
    .filter(([, values]) => asList(values).length)
    .map(
      ([name, values]) =>
        `<tr><td>${escapeHtml(name)}</td><td>${uniqueText(asList(values)).map(escapeHtml).join(", ")}</td></tr>`,
    )
    .join("");
  return rows
    ? `<h4>관련 엔티티</h4><table class="evidence-table"><tbody>${rows}</tbody></table>`
    : "";
}

function renderEventFields(fields) {
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) return "";
  const entries = Object.entries(fields);
  if (!entries.length) return "";
  const rows = entries
    .map(
      ([name, value]) =>
        `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(displayValue(value))}</td></tr>`,
    )
    .join("");
  return `<details>
    <summary>추가 이벤트 필드 ${entries.length}개</summary>
    <table class="evidence-table"><tbody>${rows}</tbody></table>
  </details>`;
}

function renderValueList(title, values) {
  const items = uniqueText(asList(values));
  if (!items.length) return "";
  return `<h4>${escapeHtml(title)}</h4><ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function asList(value) {
  if (Array.isArray(value)) return value;
  return value === undefined || value === null || value === "" ? [] : [value];
}

function uniqueText(values) {
  return [...new Set(values.map(displayValue).filter(Boolean))];
}

function formatReason(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return displayValue(value);
  }
  const heading = value.title || value.rule_id || "";
  const detail = value.description || value.reason || "";
  if (heading && detail && heading !== detail) return `${heading}: ${detail}`;
  return displayValue(heading || detail || value);
}

function formatScenarioFact(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return displayValue(value);
  }
  const text = value.text || value.description || value.reason || "";
  const refs = uniqueText([
    ...asList(value.event_ref),
    ...asList(value.event_refs),
    ...asList(value.event_uids),
  ]);
  if (text && refs.length) return `${text} (${refs.join(", ")})`;
  return displayValue(text || value);
}

function displayValue(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function renderFinding(finding) {
  const evidenceRows = asList(finding.evidence)
    .filter((item) => item && typeof item === "object" && !Array.isArray(item))
    .map((item) => renderEvidenceRow(item, true))
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
      <thead><tr><th>시간</th><th>ID</th><th>호스트 / 계정</th><th>출발지</th><th>목적지 / DNS / 통신</th><th>명령 / 프로세스 / PID·GUID</th></tr></thead>
      <tbody>${evidenceRows}</tbody>
    </table>
    ${asList(finding.evidence).map((item) => renderDecodedPowershell(item?.decoded_powershell)).join("")}
  </section>`;
}

function renderEvidenceRow(item, includeTime) {
  const sourceIp = eventValue(item, "source_ip", "SourceIp", "SourceAddress");
  const sourcePort = eventValue(item, "source_port", "SourcePort");
  const destinationIp = eventValue(
    item,
    "destination_ip",
    "DestinationIp",
    "DestAddress",
  );
  const destinationPort = eventValue(
    item,
    "destination_port",
    "DestinationPort",
    "DestPort",
  );
  const destinationNames = uniqueText([
    eventValue(item, "destination_hostname", "DestinationHostname"),
    eventValue(item, "destination_domain", "domain"),
    eventValue(item, "query_name", "QueryName"),
  ]);
  const protocol = eventValue(item, "protocol", "Protocol");
  const direction = eventValue(item, "network_direction", "Direction");
  const initiated = eventValue(item, "initiated", "Initiated");
  const process = eventValue(item, "command_line", "process", "Image", "Application");
  const processId = eventValue(
    item,
    "process_id",
    "ProcessId",
    "ProcessID",
    "NewProcessId",
  );
  const processGuid = eventValue(item, "process_guid", "ProcessGuid");
  const source = formatNetworkEndpoint(sourceIp, sourcePort);
  const destination = uniqueText([
    formatNetworkEndpoint(destinationIp, destinationPort),
    ...destinationNames,
    protocol ? `protocol ${protocol}` : "",
    direction ? `direction ${direction}` : "",
    initiated ? `initiated ${initiated}` : "",
  ]);
  const processDetails = uniqueText([
    process,
    processId ? `PID ${processId}` : "",
    processGuid ? `GUID ${processGuid}` : "",
  ]);
  const prefixCells = [];
  if (includeTime) prefixCells.push(item.time || "-");
  prefixCells.push(item.event_id || "-");
  const escapedPrefixCells = prefixCells
    .map((value) => `<td>${escapeHtml(value)}</td>`)
    .join("");
  const hostAccountCell = renderMultilineCell([item.host, item.account]);
  const destinationCell = destination.length
    ? destination.map(escapeHtml).join("<br>")
    : "-";
  const processCell = processDetails.length
    ? processDetails.map(escapeHtml).join("<br>")
    : "-";
  return `<tr>${escapedPrefixCells}<td>${hostAccountCell}</td><td>${escapeHtml(source || "-")}</td><td>${destinationCell}</td><td>${processCell}</td></tr>`;
}

function renderMultilineCell(values) {
  const items = uniqueText(values);
  return items.length ? items.map(escapeHtml).join("<br>") : "-";
}

function eventValue(item, ...names) {
  if (!item || typeof item !== "object" || Array.isArray(item)) return "";
  const sources = [item];
  if (item.fields && typeof item.fields === "object" && !Array.isArray(item.fields)) {
    sources.push(item.fields);
  }
  const normalizedNames = names.map(normalizeEventFieldName).filter(Boolean);
  for (const source of sources) {
    for (const name of names) {
      if (Object.prototype.hasOwnProperty.call(source, name)) {
        const value = displayValue(source[name]);
        if (value) return value;
      }
    }
    for (const [key, rawValue] of Object.entries(source)) {
      const normalizedKey = normalizeEventFieldName(key);
      if (!normalizedNames.some((name) => normalizedKey === name || normalizedKey.endsWith(name))) {
        continue;
      }
      const value = displayValue(rawValue);
      if (value) return value;
    }
  }
  return "";
}

function normalizeEventFieldName(value) {
  return String(value || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function formatNetworkEndpoint(address, port) {
  const safeAddress = displayValue(address);
  const safePort = displayValue(port);
  if (!safeAddress) return safePort ? `port ${safePort}` : "";
  if (!safePort) return safeAddress;
  return safeAddress.includes(":")
    ? `[${safeAddress}]:${safePort}`
    : `${safeAddress}:${safePort}`;
}

function renderSummary(analysis) {
  summaryView.innerHTML = renderSummaryContents(analysis);
}

function renderSummaryContents(analysis, includeParserWarning = true) {
  const summary = analysis.summary || {};
  const scope = analysis.scope || {};
  const parserWarning = includeParserWarning ? renderParserWarning(analysis) : "";
  return `${parserWarning}<div class="summary-grid">
    ${renderIntrusionChainSummary(analysis.intrusion_chain)}
    ${renderScope(scope)}
    ${renderAdaptiveTimeRange(analysis.adaptive_time_range)}
    ${renderNetworkActivity(analysis.network_activity)}
    ${renderCounter("이벤트 ID", summary.top_event_ids)}
    ${renderCounter("호스트", summary.top_hosts)}
    ${renderCounter("계정", summary.top_accounts)}
    ${renderCounter("원본 IP", summary.top_source_ips)}
    ${renderCounter("목적지 IP", summary.top_destination_ips)}
    ${renderCounter("목적지 호스트 / DNS", summary.top_destination_domains)}
    ${renderCounter("프로바이더", summary.top_providers)}
  </div>`;
}

function renderIntrusionChainSummary(chain) {
  if (!chain || typeof chain !== "object" || Array.isArray(chain)) return "";
  const origin = chain.origin_process && typeof chain.origin_process === "object"
    ? chain.origin_process
    : null;
  const rows = [
    ["식별 상태", chain.status || "근거 부족"],
    ["연결 신뢰도", chain.confidence || "unknown"],
    ["시작 프로세스 후보", origin?.process || "식별되지 않음"],
    ["관측된 의심 실행", chain.observed_trigger_process?.process],
    ["최초 유발 프로세스 후보", chain.initiating_process_candidate?.process],
    ["시작 시각", origin?.start_time || "확인 불가"],
    ["PID", origin?.process_id],
    ["ProcessGuid", origin?.process_guid],
    ["후속 프로세스", countLabel(asList(chain.processes).length)],
    ["연관 행위 근거", countLabel(asList(chain.steps).length)],
    ["우선 검토 로그", countLabel(asList(chain.related_events).length)],
    ["대표 체인 여부", chain.truncated === true ? "상한에 맞춘 대표 체인" : "기록된 범위 내 전체 체인"],
  ]
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`)
    .join("");
  return `<section class="summary-block origin-focus">
    <h3>침해 시발점 프로세스 · 최우선 조사 대상</h3>
    <table><tbody>${rows}</tbody></table>
  </section>`;
}

function renderAdaptiveTimeRange(adaptiveRange) {
  if (!adaptiveRange || typeof adaptiveRange !== "object" || Array.isArray(adaptiveRange)) {
    return "";
  }
  const enabled = adaptiveRange.enabled === true;
  const applied = adaptiveRange.applied === true;
  const reasons = uniqueText(asList(adaptiveRange.reasons));
  const requestedRange = [
    adaptiveRange.requested_start_utc || "시작 미지정",
    adaptiveRange.requested_end_utc || "종료 미지정",
  ].join(" ~ ");
  const effectiveRange = [
    adaptiveRange.effective_start_utc || "시작 미지정",
    adaptiveRange.effective_end_utc || "종료 미지정",
  ].join(" ~ ");
  const appliedRange = applied ? effectiveRange : requestedRange;
  const stopReasons = {
    disabled: "자동 분석 사용 안 함",
    no_supported_expansion: "추가 확장을 뒷받침하는 근거 없음",
    no_earlier_uploaded_logs: "업로드한 로그에 더 이른 기록이 없음",
    max_lookback: "이전 시간대 탐색 한도 도달",
    max_rounds: "추가 분석 횟수 한도 도달",
    time_budget: "추가 분석 시간 한도 도달",
    incident_focus_unavailable: "기존 침해 후보 연결 근거 부족으로 마지막 결과 유지",
    parser_or_retention_limit: "파싱 또는 로그 보존 한도로 분석 중지",
    expansion_error: "추가 분석 오류로 마지막 결과 유지",
  };
  const rows = [
    ["자동 확장", enabled ? "사용" : "사용 안 함"],
    ["확장 적용", applied ? "적용됨" : "적용되지 않음"],
    ["요청 범위", requestedRange],
    ["평가된 확장 범위", effectiveRange],
    ["실제 적용 범위", appliedRange],
    ["추가 분석 완료", adaptiveRange.rounds_completed != null ? `${Number(adaptiveRange.rounds_completed).toLocaleString()}회` : null],
    ["추가 분석 종료 이유", adaptiveRange.stop_reason ? stopReasons[adaptiveRange.stop_reason] || "추가 분석 완료" : null],
    ["추가 확인이 필요한 근거", Array.isArray(adaptiveRange.missing_evidence) ? countLabel(adaptiveRange.missing_evidence.length) : null],
    ["시작 전 가용 이벤트", countLabel(adaptiveRange.available_events_before_requested_range)],
    ["종료 후 가용 이벤트", countLabel(adaptiveRange.available_events_after_requested_range)],
  ]
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`)
    .join("");
  const reasonHtml = reasons.length
    ? `<h4>확장 근거</h4><ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>`
    : "";
  const errorHtml = adaptiveRange.expansion_error
    ? `<p><strong>확장 경고:</strong> ${escapeHtml(adaptiveRange.expansion_error)}</p>`
    : "";
  const rounds = asList(adaptiveRange.rounds).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const roundHtml = rounds.length ? `<details><summary>추가 분석 구간 확인</summary>
    <table><thead><tr><th>차수·결과</th><th>검토 범위 (UTC)</th><th>검토 이유</th></tr></thead><tbody>
    ${rounds.map((item) => `<tr>
      <td>${escapeHtml(item.round ?? "-")}차 · ${item.applied === true ? "적용" : "미적용"}</td>
      <td>${renderMultilineCell([item.start_utc || "시작 미지정", item.end_utc || "종료 미지정"])}</td>
      <td>${renderMultilineCell([...asList(item.reasons), item.error])}</td>
    </tr>`).join("")}
    </tbody></table></details>` : "";
  return `<section class="summary-block">
    <h3>자율 분석 시간 범위</h3>
    <table><tbody>${rows}</tbody></table>
    ${reasonHtml}${roundHtml}${errorHtml}
    ${adaptiveRange.coverage_note ? `<p class="scope-note">${escapeHtml(adaptiveRange.coverage_note)}</p>` : ""}
  </section>`;
}

function renderNetworkActivity(activity) {
  if (!activity || typeof activity !== "object" || Array.isArray(activity)) return "";
  const connectionCandidates = asList(activity.connections).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item) &&
      isC2Candidate(item),
  );
  const fanoutCandidates = asList(activity.process_fanout_candidates).filter(
    (item) => item && typeof item === "object" && !Array.isArray(item),
  );
  const reportedConnectionCandidateCount = finiteCount(activity.suspicious_group_count);
  const reportedFanoutCandidateCount = finiteCount(activity.process_fanout_candidate_count);
  const connectionCandidateCount = reportedConnectionCandidateCount ??
    connectionCandidates.length;
  const fanoutCandidateCount = reportedFanoutCandidateCount ??
    fanoutCandidates.length;
  const aggregateCandidateCount =
    reportedConnectionCandidateCount !== null && reportedFanoutCandidateCount !== null
      ? connectionCandidateCount + fanoutCandidateCount
      : finiteCount(activity.c2_candidate_count) ??
        connectionCandidateCount + fanoutCandidateCount;
  const connectionLowerBound = activity.group_state_limit_reached === true ||
    activity.correlation_index_limit_reached === true;
  const fanoutLowerBound = activity.fanout_state_limit_reached === true;
  const rows = [
    ["C2 상관 대상 이벤트", countLabel(activity.source_network_record_count)],
    ["네트워크 연결 이벤트", countLabel(activity.connection_event_count)],
    ["DNS 질의 이벤트", countLabel(activity.dns_query_event_count)],
    ["외부 목적지 연결", countLabel(activity.external_connection_count)],
    ["고유 외부 목적지", boundedCountLabel(
      activity.unique_external_destination_count,
      activity.unique_external_destination_count_is_lower_bound === true,
    )],
    ["통신 그룹", boundedCountLabel(
      activity.group_count,
      activity.group_state_limit_reached === true,
    )],
    ["C2 통신 후보 합계", boundedCountLabel(
      aggregateCandidateCount,
      connectionLowerBound || fanoutLowerBound,
    )],
    ["C2 목적지 후보 그룹", boundedCountLabel(
      connectionCandidateCount,
      connectionLowerBound,
    )],
    ["프로세스 fan-out 후보", boundedCountLabel(
      fanoutCandidateCount,
      fanoutLowerBound,
    )],
    [
      "C2 관련 입력 스캔",
      activity.full_input_scan === true
        ? "입력 끝까지 완료"
        : activity.full_input_scan === false
          ? "불완전"
          : undefined,
    ],
    [
      "일반 이벤트 보관 상한",
      activity.general_record_limit_reached === true
        ? "도달 (C2 스캔은 별도 수행)"
        : activity.general_record_limit_reached === false
          ? "미도달"
          : undefined,
    ],
  ]
    .filter(([, value]) => value !== undefined && value !== null)
    .map(
      ([label, value]) =>
        `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`,
    )
    .join("");
  if (!rows) return "";
  const limitation = activity.limitation
    ? `<p><strong>해석 한계:</strong> ${escapeHtml(activity.limitation)}</p>`
    : "";
  return `<section class="summary-block">
    <h3>네트워크 통신 범위</h3>
    <table><tbody>${rows}</tbody></table>
    ${limitation}
  </section>`;
}

function countLabel(value) {
  if (value === undefined || value === null) return undefined;
  const count = Number(value);
  return Number.isFinite(count) ? `${count.toLocaleString()}건` : displayValue(value);
}

function boundedCountLabel(value, isLowerBound = false) {
  const label = countLabel(value);
  if (label === undefined) return undefined;
  return isLowerBound ? `${label} 이상 (하한)` : label;
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
        ${scope.network_records_scanned !== undefined ? `<tr><td>C2 상관 대상</td><td>${escapeHtml(countLabel(scope.network_records_scanned))}</td></tr>` : ""}
        ${scope.network_scan_complete !== undefined ? `<tr><td>C2 관련 입력 스캔</td><td>${scope.network_scan_complete === true ? "입력 끝까지 완료" : "불완전"}</td></tr>` : ""}
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
  let fence = null;
  let codeLines = [];
  for (const line of lines) {
    const fenceMatch = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence) {
      if (fenceMatch && fenceMatch[1][0] === fence[0]
          && fenceMatch[1].length >= fence.length && !fenceMatch[2].trim()) {
        html.push(`<pre><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
        fence = null;
        codeLines = [];
      } else {
        codeLines.push(line);
      }
      continue;
    }
    if (fenceMatch) {
      if (inList) { html.push("</ul>"); inList = false; }
      fence = fenceMatch[1];
      continue;
    }
    if (line.startsWith("#### ")) {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
      html.push(`<h4>${inlineMarkdown(line.slice(5))}</h4>`);
    } else if (line.startsWith("### ")) {
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
  if (fence) html.push(`<pre><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
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
      message = "EVTX/XML 스트리밍 파싱 및 시간 범위 필터링 중";
      percent = Math.min(70, 25 + elapsed * 1.5);
    }
    if (elapsed > 20) {
      if (agentBackend?.value === "codex_dev") {
        message = "Codex 에이전트 보고서 생성 중";
      } else if (agentBackend?.value === "rule") {
        message = "규칙 기반 보고서 생성 중";
      } else {
        message = "LM Studio 보고서 생성 중";
      }
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

initializeCatSelector();
initializeCatCursor();
renderAnalysisHistory();
loadHealth();
