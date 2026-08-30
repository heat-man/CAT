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
const lmUrl = document.querySelector("#lmUrl");
const lmModel = document.querySelector("#lmModel");
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
    configureAgentBackends(data);
    if (data.lm_studio_url && lmUrl) {
      lmUrl.value = data.allow_custom_lm_url === true
        ? readPreference("cat.lm_url") || data.lm_studio_url
        : data.lm_studio_url;
    }
    if (lmUrl) {
      lmUrl.readOnly = data.allow_custom_lm_url !== true;
      lmUrl.title = lmUrl.readOnly
        ? "운영 모드에서는 서버 환경변수 LM_STUDIO_URL 값을 사용합니다."
        : "base URL, /v1 또는 전체 chat/completions 주소를 입력할 수 있습니다.";
    }
    if (data.default_model && lmModel) {
      lmModel.value = readPreference("cat.lm_model") || data.default_model;
    }
    updateAgentFields();
  } catch {
    healthStatus.textContent = "서버 연결 실패";
  }
}

function configureAgentBackends(data) {
  if (!agentBackend) return;
  const supported = new Set(["lmstudio", "rule"]);
  if (data.codex_dev_enabled === true) {
    supported.add("codex_dev");
  }
  const labels = {
    lmstudio: "LM Studio Qwen",
    codex_dev: "Codex 개발 검증",
    rule: "규칙 기반 보고서",
  };

  for (const option of [...agentBackend.options]) {
    if (!supported.has(option.value)) {
      option.remove();
    }
  }
  for (const backend of ["lmstudio", "codex_dev", "rule"]) {
    if (supported.has(backend) && !agentBackend.querySelector(`option[value="${backend}"]`)) {
      const option = document.createElement("option");
      option.value = backend;
      option.textContent = labels[backend];
      agentBackend.append(option);
    }
  }
  if (supported.has(data.default_agent_backend)) {
    agentBackend.value = data.default_agent_backend;
  }
}

function updateAgentFields() {
  const isLmStudio = agentBackend?.value === "lmstudio";
  if (lmUrl) lmUrl.disabled = !isLmStudio;
  if (lmModel) lmModel.disabled = !isLmStudio;
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

    lastReport = data.report_markdown;
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
    activateTab("report");
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
});

fileInput.addEventListener("change", updateFileSummary);
agentBackend?.addEventListener("change", updateAgentFields);
lmUrl?.addEventListener("change", () => writePreference("cat.lm_url", lmUrl.value.trim()));
lmModel?.addEventListener("change", () => writePreference("cat.lm_model", lmModel.value.trim()));

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
    status = llm?.used
      ? `<p><strong>에이전트:</strong> LM Studio Qwen 사용됨 (${escapeHtml(llm.model)})${llm.validation_mode === "relaxed" ? " / 완화 검증" : ""}</p>${
          warnings.length
            ? `<div class="llm-warning"><strong>응답 보정 안내:</strong><ul>${warnings.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>`
            : ""
        }`
      : `<p><strong>에이전트:</strong> LM Studio Qwen 미사용${llm?.error ? ` - ${escapeHtml(llm.error)}` : ""}</p>`;
  }
  reportView.innerHTML = `${renderParserWarning(analysis)}${status}${markdownToHtml(String(markdown || ""))}`;
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
  const details = errors.length
    ? `<ul>${errors.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "";
  return `<div class="parser-warning"><strong>입력 파싱 경고:</strong> 일부 파일 또는 레코드만 분석되었을 수 있습니다.${details}</div>`;
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
    <section aria-labelledby="suspiciousEventsTitle">
      <h2 id="suspiciousEventsTitle">의심 이벤트</h2>
      <div class="finding-list">${suspiciousHtml}</div>
    </section>
    <section aria-labelledby="scenarioCandidatesTitle">
      <h2 id="scenarioCandidatesTitle">공격 시나리오 후보</h2>
      <div class="finding-list">${scenarioHtml}</div>
    </section>`;
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
      <thead><tr><th>Event ID</th><th>호스트</th><th>계정</th><th>원본 IP</th><th>명령/프로세스</th></tr></thead>
      <tbody><tr>
        <td>${escapeHtml(item.event_id || "-")}</td>
        <td>${escapeHtml(item.host || "-")}</td>
        <td>${escapeHtml(item.account || "-")}</td>
        <td>${escapeHtml(item.source_ip || "-")}</td>
        <td>${escapeHtml(item.command_line || item.process || "-")}</td>
      </tr></tbody>
    </table>
    <p><strong>원본 위치:</strong> ${escapeHtml(item.provider || "-")} / ${escapeHtml(item.channel || "-")} / ${escapeHtml(item.source_file || "-")} / record ${escapeHtml(item.record_id || "-")}</p>
    ${renderEventFields(item.fields)}
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
  summaryView.innerHTML = `${renderParserWarning(analysis)}<div class="summary-grid">
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

loadHealth();
