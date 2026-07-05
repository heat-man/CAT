from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable

from .models import EventRecord, ParseResult
from .timeutil import isoformat_utc

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SUSPICIOUS_COMMAND_KEYWORDS = {
    "encoded powershell": ["encodedcommand", " -enc ", "frombase64string"],
    "download or remote payload": ["downloadstring", "invoke-webrequest", "iwr ", "curl ", "wget ", "bitsadmin"],
    "living-off-the-land execution": ["certutil", "mshta", "regsvr32", "rundll32", "wmic process call create"],
    "credential access": ["mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs.dll", "nanodump"],
    "defense evasion": ["wevtutil cl", "clear-eventlog", "vssadmin delete shadows", "bcdedit /set"],
    "persistence": ["schtasks", "sc create", "new-service", "reg add", "runonce", "\\currentversion\\run"],
    "discovery": ["whoami", "net user", "net group", "net localgroup", "nltest", "dsquery", "adfind", "sharphound"],
}

POWERSHELL_KEYWORDS = [
    "encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex",
    "invoke-webrequest",
    "new-object net.webclient",
    "bypass",
    "amsiutils",
    "mimikatz",
    "powercat",
    "empire",
    "cobalt",
]


def analyze_events(parse_result: ParseResult, start_utc: datetime | None, end_utc: datetime | None) -> dict[str, Any]:
    records = sorted(
        parse_result.records,
        key=lambda event: event.time_created or datetime.min.replace(tzinfo=start_utc.tzinfo if start_utc else None),
    )
    findings: list[dict[str, Any]] = []

    findings.extend(_single_rule_findings(records))
    findings.extend(_failed_logon_bursts(records))
    findings.extend(_kerberos_ntlm_failure_bursts(records))
    findings.extend(_remote_logon_findings(records))
    findings.extend(_explicit_credential_findings(records))
    findings.extend(_privileged_logon_findings(records))
    findings.extend(_suspicious_process_findings(records))
    findings.extend(_powershell_findings(records))

    findings = sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item["severity"], 0),
            item.get("first_seen") or "",
            item["title"],
        ),
    )

    return {
        "scope": {
            "start_utc": isoformat_utc(start_utc),
            "end_utc": isoformat_utc(end_utc),
            "records_loaded": len(records),
            "records_in_range": parse_result.total_in_range,
            "records_seen": parse_result.total_seen,
            "truncated": parse_result.truncated,
        },
        "parser": parse_result.to_dict(),
        "summary": _summary(records),
        "findings": findings,
        "timeline": _timeline(records, findings),
        "sample_events": [_evidence(event) for event in records[:50]],
    }


def _summary(records: list[EventRecord]) -> dict[str, Any]:
    event_ids = Counter(str(event.event_id or "unknown") for event in records)
    providers = Counter(event.provider or "unknown" for event in records)
    channels = Counter(event.channel or "unknown" for event in records)
    computers = Counter(event.computer or "unknown" for event in records)
    accounts = Counter(_account(event) for event in records if _account(event))
    source_ips = Counter(_source_ip(event) for event in records if _valid_ip_field(_source_ip(event)))

    first_seen = min((event.time_created for event in records if event.time_created), default=None)
    last_seen = max((event.time_created for event in records if event.time_created), default=None)

    return {
        "first_seen": isoformat_utc(first_seen),
        "last_seen": isoformat_utc(last_seen),
        "top_event_ids": _counter_list(event_ids, 20),
        "top_providers": _counter_list(providers, 12),
        "top_channels": _counter_list(channels, 12),
        "top_hosts": _counter_list(computers, 20),
        "top_accounts": _counter_list(accounts, 20),
        "top_source_ips": _counter_list(source_ips, 20),
    }


def _single_rule_findings(records: list[EventRecord]) -> list[dict[str, Any]]:
    rules = [
        (
            "log_cleared",
            "감사 로그 삭제 또는 이벤트 로그 정리",
            "critical",
            "이벤트 로그 삭제는 침해 흔적 은폐와 직접 관련될 수 있습니다.",
            _is_event_log_clear_event,
            [
                "해당 시점 직전/직후의 원격 접속, 프로세스 생성, 계정 변경 이벤트를 확인하세요.",
                "로그 보존 정책과 중앙 로그 수집지의 동일 시간대 원본을 대조하세요.",
            ],
        ),
        (
            "service_installed",
            "신규 서비스 설치",
            "high",
            "서비스 설치 이벤트는 지속성 확보, 원격 실행 도구, 백도어 배포와 관련될 수 있습니다.",
            lambda e: _event_id(e) in {"4697", "7045"},
            [
                "서비스 실행 파일 경로와 서명, 생성 시간을 확인하세요.",
                "동일 호스트의 4688/Sysmon 1 프로세스 생성 이벤트와 부모 프로세스를 대조하세요.",
            ],
        ),
        (
            "scheduled_task_changed",
            "예약 작업 생성 또는 변경",
            "high",
            "예약 작업은 지속성 확보와 정기 실행에 자주 사용됩니다.",
            lambda e: _event_id(e) in {"4698", "4702", "106", "140", "141"},
            [
                "작업 이름, 실행 계정, 실행 명령, 트리거를 확인하세요.",
                "작업 등록 직전의 원격 로그온 또는 명령 실행 이벤트를 추적하세요.",
            ],
        ),
        (
            "account_created",
            "사용자 계정 생성",
            "high",
            "침해 중 신규 로컬/도메인 계정 생성은 지속 접근권 확보 신호일 수 있습니다.",
            lambda e: _event_id(e) in {"4720"},
            [
                "생성 주체 계정과 생성된 계정의 정당성을 확인하세요.",
                "생성 직후 그룹 추가, 로그인 성공, 서비스/작업 등록 여부를 확인하세요.",
            ],
        ),
        (
            "account_enabled_or_password_reset",
            "계정 활성화 또는 암호 재설정",
            "medium",
            "비활성 계정 활성화나 암호 재설정은 계정 탈취 또는 권한 유지와 연결될 수 있습니다.",
            lambda e: _event_id(e) in {"4722", "4723", "4724", "4738"},
            [
                "변경 요청자와 대상 계정의 업무상 정당성을 확인하세요.",
                "변경 이후 첫 로그인 위치와 로그인 유형을 확인하세요.",
            ],
        ),
        (
            "privileged_group_change",
            "권한 그룹 멤버십 변경",
            "critical",
            "관리자 또는 고권한 그룹 멤버십 변경은 권한 상승의 핵심 증거가 될 수 있습니다.",
            lambda e: _event_id(e) in {"4728", "4732", "4756"},
            [
                "추가된 계정, 대상 그룹, 수행 주체를 확인하세요.",
                "변경 이후 해당 계정의 4624, 4672, 4688 이벤트를 추적하세요.",
            ],
        ),
        (
            "defender_detection_or_tamper",
            "Defender 탐지 또는 보안 설정 변경",
            "high",
            "악성코드 탐지, 치료 실패, 보안 제품 설정 변경은 침해 조사 우선순위를 높입니다.",
            _is_defender_security_event,
            [
                "탐지명, 파일 경로, 조치 결과, 격리 여부를 확인하세요.",
                "보안 설정 변경 주체와 변경 직전 프로세스 실행 내역을 확인하세요.",
            ],
        ),
        (
            "wmi_activity",
            "WMI 기반 실행 또는 영구 이벤트 활동",
            "medium",
            "WMI 이벤트는 원격 실행, 측면 이동, 지속성 확보에 사용될 수 있습니다.",
            _is_wmi_activity_event,
            [
                "WMI consumer/filter/binding 정보와 명령 내용을 확인하세요.",
                "원격 원본 호스트와 실행 계정을 다른 보안 로그와 연결하세요.",
            ],
        ),
    ]

    findings: list[dict[str, Any]] = []
    for rule_id, title, severity, description, predicate, steps in rules:
        matched = [event for event in records if predicate(event)]
        if matched:
            findings.append(_finding(rule_id, title, severity, matched, description, "high", steps))
    return findings


def _failed_logon_bursts(records: list[EventRecord]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[EventRecord]] = defaultdict(list)
    for event in records:
        if _event_id(event) != "4625":
            continue
        key = (_account(event) or "unknown", _source_ip(event) or "unknown", event.computer or "unknown")
        groups[key].append(event)

    findings: list[dict[str, Any]] = []
    for (account, source_ip, host), events in sorted(groups.items(), key=lambda item: len(item[1]), reverse=True)[:10]:
        if len(events) < 5:
            continue
        severity = "high" if len(events) >= 20 else "medium"
        findings.append(
            _finding(
                "failed_logon_burst",
                f"로그온 실패 반복: {account} / {source_ip} -> {host}",
                severity,
                events,
                "동일 계정/원본/대상 조합에서 반복 실패가 발생했습니다. 비밀번호 추측, 계정 탈취 시도, 잘못된 서비스 자격증명 가능성을 확인해야 합니다.",
                "medium",
                [
                    "실패 사유(SubStatus/Status)와 정상 업무 시스템 여부를 확인하세요.",
                    "성공 로그인(4624)이 같은 원본에서 뒤따랐는지 확인하세요.",
                ],
            )
        )
    return findings


def _kerberos_ntlm_failure_bursts(records: list[EventRecord]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)
    for event in records:
        if _event_id(event) not in {"4771", "4776"}:
            continue
        groups[(_account(event) or "unknown", _source_ip(event) or event.computer or "unknown")].append(event)

    findings: list[dict[str, Any]] = []
    for (account, origin), events in sorted(groups.items(), key=lambda item: len(item[1]), reverse=True)[:8]:
        if len(events) < 10:
            continue
        findings.append(
            _finding(
                "auth_failure_burst",
                f"Kerberos/NTLM 인증 실패 반복: {account} / {origin}",
                "medium",
                events,
                "Kerberos 또는 NTLM 인증 실패가 반복되었습니다. 계정 잠금 전조, 스프레이, 잘못된 저장 자격증명 가능성이 있습니다.",
                "medium",
                [
                    "도메인 컨트롤러 기준 동일 원본의 다른 계정 실패 여부를 확인하세요.",
                    "성공 인증 이벤트와 VPN/프록시 접속 기록을 대조하세요.",
                ],
            )
        )
    return findings


def _remote_logon_findings(records: list[EventRecord]) -> list[dict[str, Any]]:
    rdp_events = [
        event
        for event in records
        if _event_id(event) == "4624" and _field(event, "LogonType") == "10" and _valid_ip_field(_source_ip(event))
    ]
    network_events = [
        event
        for event in records
        if _event_id(event) == "4624" and _field(event, "LogonType") == "3" and _valid_ip_field(_source_ip(event))
    ]
    findings: list[dict[str, Any]] = []
    if rdp_events:
        findings.append(
            _finding(
                "rdp_logon",
                "RDP 원격 대화형 로그온",
                "medium",
                rdp_events,
                "원격 대화형 로그온이 관찰되었습니다. 침해 조사에서는 초기 접근 또는 측면 이동 경로일 수 있습니다.",
                "medium",
                [
                    "원본 IP, 계정, 대상 호스트가 정상 관리 경로인지 확인하세요.",
                    "로그온 직후 프로세스 생성, 파일 생성, 서비스 설치 이벤트를 확인하세요.",
                ],
            )
        )
    if len(network_events) >= 10:
        findings.append(
            _finding(
                "network_logon_volume",
                "네트워크 로그온 다수 발생",
                "low",
                network_events,
                "네트워크 로그온이 다수 관찰되었습니다. 파일 공유, 원격 서비스 접근, 측면 이동 후보를 좁히는 단서입니다.",
                "low",
                [
                    "상위 원본 IP와 대상 호스트 쌍을 기준으로 정상 업무 트래픽인지 확인하세요.",
                    "동일 원본에서 4648, 4688, 7045, 4698 이벤트가 이어지는지 확인하세요.",
                ],
            )
        )
    return findings


def _explicit_credential_findings(records: list[EventRecord]) -> list[dict[str, Any]]:
    events = [event for event in records if _event_id(event) == "4648"]
    if not events:
        return []
    return [
        _finding(
            "explicit_credentials",
            "명시적 자격증명을 사용한 로그온 시도",
            "medium",
            events,
            "4648 이벤트는 다른 계정의 자격증명을 명시적으로 사용한 실행 또는 접속을 의미합니다. 관리자 도구 사용일 수도 있지만 측면 이동 조사에 중요합니다.",
            "medium",
            [
                "Subject 계정, Target 계정, 대상 서버, 실행 프로세스를 함께 확인하세요.",
                "같은 시각 대상 호스트의 4624 LogonType 3/10 이벤트를 대조하세요.",
            ],
        )
    ]


def _privileged_logon_findings(records: list[EventRecord]) -> list[dict[str, Any]]:
    events = [
        event
        for event in records
        if _event_id(event) == "4672" and (_account(event) or "").lower() not in {"system", "local service", "network service"}
    ]
    if len(events) < 3:
        return []
    return [
        _finding(
            "privileged_logon",
            "특수 권한이 할당된 로그온",
            "low",
            events,
            "관리 권한 계정 로그온이 관찰되었습니다. 단독으로 침해 증거는 아니지만, 원격 로그온 및 프로세스 실행과 결합해 확인해야 합니다.",
            "low",
            [
                "해당 계정의 로그인 위치와 시간대가 정상 운영 패턴인지 확인하세요.",
                "동일 Logon ID 또는 가까운 시간대의 4688/7045/4698 이벤트를 연결하세요.",
            ],
        )
    ]


def _suspicious_process_findings(records: list[EventRecord]) -> list[dict[str, Any]]:
    matched_by_category: dict[str, list[EventRecord]] = defaultdict(list)
    for event in records:
        if _event_id(event) not in {"1", "4688"}:
            continue
        text = f" {_event_text(event).lower()} "
        for category, keywords in SUSPICIOUS_COMMAND_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                matched_by_category[category].append(event)

    findings: list[dict[str, Any]] = []
    for category, events in matched_by_category.items():
        severity = "high" if category in {"credential access", "defense evasion", "persistence"} else "medium"
        findings.append(
            _finding(
                f"suspicious_process_{category.replace(' ', '_')}",
                f"의심 프로세스 실행: {category}",
                severity,
                events,
                "프로세스 생성 이벤트에서 공격자가 자주 사용하는 명령 또는 LOLBin 사용 흔적이 발견되었습니다.",
                "medium",
                [
                    "명령줄 전체, 부모 프로세스, 실행 사용자, 파일 해시/서명을 확인하세요.",
                    "동일 호스트에서 직후 네트워크 연결, 파일 생성, 계정 변경이 있었는지 확인하세요.",
                ],
            )
        )
    return findings


def _powershell_findings(records: list[EventRecord]) -> list[dict[str, Any]]:
    events: list[EventRecord] = []
    for event in records:
        provider = (event.provider or "").lower()
        if _event_id(event) not in {"4103", "4104"} and "powershell" not in provider:
            continue
        text = _event_text(event).lower()
        if any(keyword in text for keyword in POWERSHELL_KEYWORDS):
            events.append(event)
    if not events:
        return []
    return [
        _finding(
            "suspicious_powershell",
            "의심 PowerShell 스크립트 또는 명령",
            "high",
            events,
            "PowerShell 로그에서 난독화, 다운로드 실행, 실행 정책 우회, 보안 우회 또는 공격 도구 키워드가 발견되었습니다.",
            "medium",
            [
                "ScriptBlockText 원문과 실행 계정, 호스트, 부모 프로세스를 확인하세요.",
                "동일 세션의 네트워크 연결, 파일 쓰기, AMSI/Defender 이벤트를 대조하세요.",
            ],
        )
    ]


def _timeline(records: list[EventRecord], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    finding_event_keys = set()
    for finding in findings:
        for evidence in finding.get("evidence", []):
            key = (
                evidence.get("time"),
                evidence.get("event_id"),
                evidence.get("host"),
                evidence.get("record_id"),
            )
            finding_event_keys.add(key)
            entries.append(
                {
                    "time": evidence.get("time"),
                    "type": "finding",
                    "severity": finding["severity"],
                    "title": finding["title"],
                    "event_id": evidence.get("event_id"),
                    "host": evidence.get("host"),
                    "account": evidence.get("account"),
                    "source_ip": evidence.get("source_ip"),
                }
            )

    if len(entries) < 50:
        for event in records:
            evidence = _evidence(event)
            key = (evidence.get("time"), evidence.get("event_id"), evidence.get("host"), evidence.get("record_id"))
            if key in finding_event_keys:
                continue
            entries.append(
                {
                    "time": evidence.get("time"),
                    "type": "event",
                    "severity": "info",
                    "title": f"Event ID {event.event_id}",
                    "event_id": event.event_id,
                    "host": event.computer,
                    "account": evidence.get("account"),
                    "source_ip": evidence.get("source_ip"),
                }
            )
            if len(entries) >= 50:
                break

    return sorted(entries, key=lambda item: item.get("time") or "")[:100]


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    events: list[EventRecord],
    description: str,
    confidence: str,
    steps: list[str],
) -> dict[str, Any]:
    ordered = sorted(events, key=lambda event: event.time_created or datetime.min)
    first_seen = min((event.time_created for event in ordered if event.time_created), default=None)
    last_seen = max((event.time_created for event in ordered if event.time_created), default=None)
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "event_count": len(events),
        "first_seen": isoformat_utc(first_seen),
        "last_seen": isoformat_utc(last_seen),
        "description": description,
        "entities": _entities(ordered),
        "evidence": [_evidence(event) for event in ordered[:12]],
        "analysis_guidance": _analysis_guidance(rule_id),
        "recommended_next_steps": steps,
    }


def _entities(events: Iterable[EventRecord]) -> dict[str, list[str]]:
    accounts = Counter()
    hosts = Counter()
    source_ips = Counter()
    processes = Counter()
    services = Counter()
    tasks = Counter()
    for event in events:
        if account := _account(event):
            accounts[account] += 1
        if event.computer:
            hosts[event.computer] += 1
        if _valid_ip_field(_source_ip(event)):
            source_ips[_source_ip(event)] += 1
        if process := _process(event):
            processes[process] += 1
        if service := _field(event, "ServiceName"):
            services[service] += 1
        if task := _field(event, "TaskName"):
            tasks[task] += 1
    return {
        "accounts": [item for item, _ in accounts.most_common(10)],
        "hosts": [item for item, _ in hosts.most_common(10)],
        "source_ips": [item for item, _ in source_ips.most_common(10)],
        "processes": [item for item, _ in processes.most_common(10)],
        "services": [item for item, _ in services.most_common(10)],
        "tasks": [item for item, _ in tasks.most_common(10)],
    }


def _evidence(event: EventRecord) -> dict[str, Any]:
    selected_fields = {
        key: value
        for key, value in {**event.event_data, **event.user_data}.items()
        if key
        in {
            "TargetUserName",
            "TargetDomainName",
            "SubjectUserName",
            "SubjectDomainName",
            "IpAddress",
            "IpPort",
            "WorkstationName",
            "LogonType",
            "Status",
            "SubStatus",
            "ProcessName",
            "ProcessId",
            "ClientProcessId",
            "NewProcessName",
            "NewProcessId",
            "CommandLine",
            "ParentProcessName",
            "ParentProcessId",
            "ServiceName",
            "ServiceFileName",
            "TaskName",
            "ObjectName",
            "ObjectValueName",
            "Operation",
            "NamespaceName",
            "Query",
            "Consumer",
            "Filter",
            "Binding",
            "PossibleCause",
            "TargetServerName",
            "TargetInfo",
            "SubjectLogonId",
            "TargetLogonId",
            "LogonProcessName",
            "AuthenticationPackageName",
            "ThreatName",
            "Threat Name",
            "ThreatID",
            "Threat ID",
            "Path",
            "Action",
            "ActionName",
            "Action Name",
            "OldValue",
            "Old Value",
            "NewValue",
            "New Value",
            "Setting",
            "ScriptBlockText",
        }
    }
    return {
        "time": isoformat_utc(event.time_created),
        "source_file": event.source_file,
        "event_id": event.event_id,
        "provider": event.provider,
        "channel": event.channel,
        "host": event.computer,
        "record_id": event.record_id,
        "account": _account(event),
        "source_ip": _source_ip(event),
        "process": _process(event),
        "command_line": _truncate(_command_line(event), 600),
        "fields": {key: _truncate(value, 600) for key, value in selected_fields.items()},
    }


def _event_id(event: EventRecord) -> str:
    return str(event.event_id or "")


def _provider(event: EventRecord) -> str:
    return (event.provider or "").lower()


def _channel(event: EventRecord) -> str:
    return (event.channel or "").lower()


def _is_event_log_clear_event(event: EventRecord) -> bool:
    event_id = _event_id(event)
    provider = _provider(event)
    channel = _channel(event)
    text = _event_text(event).lower()
    if "wevtutil cl" in text or "clear-eventlog" in text:
        return True
    if event_id == "1102" and ("security-auditing" in provider or channel == "security"):
        return True
    return event_id == "104" and "eventlog" in provider and (channel == "system" or "eventlog" in channel)


def _is_defender_security_event(event: EventRecord) -> bool:
    if _event_id(event) not in {"1116", "1117", "1118", "1119", "5007", "5013", "5015"}:
        return False
    provider = _provider(event)
    channel = _channel(event)
    return "defender" in provider or "windows defender" in channel


def _is_wmi_activity_event(event: EventRecord) -> bool:
    text = _event_text(event).lower()
    if "wmic process call create" in text:
        return True
    if _event_id(event) not in {"5857", "5858", "5859", "5860", "5861"}:
        return False
    provider = _provider(event)
    channel = _channel(event)
    return "wmi-activity" in provider or "wmi-activity" in channel


def _analysis_guidance(rule_id: str) -> dict[str, Any]:
    if rule_id == "log_cleared":
        return {
            "cause_focus": "Security 1102, Microsoft-Windows-Eventlog/System 104, 또는 로그 삭제 명령 실행 주체를 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 이벤트 로그 정리 또는 삭제 가능성입니다.",
            "not_proven": "이 항목만으로 외부 네트워크 연결, 파일 내용 변조, 데이터 유출은 확인되지 않습니다.",
            "correlation_targets": ["4688/Sysmon 1 프로세스 생성", "4624/4648 로그온", "중앙 로그 record gap", "로그 파일 생성/수정 시각"],
        }
    if rule_id == "defender_detection_or_tamper":
        return {
            "cause_focus": "Defender 탐지명, 변경 전후 설정, 변경 주체 계정/프로세스를 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 악성코드 탐지, 치료/격리 결과, 또는 보안 설정 변경 가능성입니다.",
            "not_proven": "탐지명, 파일 경로, 조치 결과가 없으면 악성 파일 실행이나 치료 성공 여부를 단정할 수 없습니다.",
            "correlation_targets": ["Defender 1116/1117/5007/5013/5015/5017", "격리 목록", "변경 직전 4688/Sysmon 1", "Defender support logs"],
        }
    if rule_id == "wmi_activity":
        return {
            "cause_focus": "ClientProcessId, NamespaceName, Query, Consumer/Filter/Binding, 실행 계정을 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 WMI 조회, provider 활동, 원격 실행, 또는 영구 이벤트 구독 가능성입니다.",
            "not_proven": "명령줄, 원본 IP, consumer/filter/binding이 없으면 원격 실행 또는 지속성 확보로 단정할 수 없습니다.",
            "correlation_targets": ["WMI 5857-5861 상세 필드", "root/subscription", "4688/Sysmon 1", "4624 LogonType 3/10"],
        }
    if rule_id == "explicit_credentials":
        return {
            "cause_focus": "4648의 Subject 계정, Target 계정, TargetServerName, 실행 프로세스를 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 다른 자격증명을 명시적으로 사용한 로컬 실행 또는 원격 접속 시도입니다.",
            "not_proven": "대상 서버와 4624 성공 로그온이 연결되지 않으면 측면 이동 또는 외부 네트워크 연결은 확인되지 않습니다.",
            "correlation_targets": ["대상 호스트 4624", "원본 호스트 4688", "TargetServerName", "Logon ID"],
        }
    if rule_id == "service_installed":
        return {
            "cause_focus": "서비스명, 서비스 실행 파일, 설치 주체 계정, 부모 프로세스를 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 신규 서비스 등록이며 지속성 또는 원격 실행 도구 배포 가능성이 있습니다.",
            "not_proven": "서비스 바이너리 경로와 해시가 확인되지 않으면 악성 파일 설치나 데이터 변조는 단정할 수 없습니다.",
            "correlation_targets": ["7045/4697", "4688/Sysmon 1", "파일 해시/서명", "서비스 시작 이벤트"],
        }
    if rule_id == "scheduled_task_changed":
        return {
            "cause_focus": "작업 이름, 실행 명령, 실행 계정, 트리거를 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 예약 작업 생성 또는 변경이며 지속성/재실행 가능성이 있습니다.",
            "not_proven": "작업 명령과 실행 결과가 없으면 악성 실행 또는 데이터 변조는 확인되지 않습니다.",
            "correlation_targets": ["4698/4702", "TaskScheduler 106/140/141", "4688", "작업 XML"],
        }
    if rule_id.startswith("suspicious_process_") or rule_id == "suspicious_powershell":
        return {
            "cause_focus": "명령줄, 부모 프로세스, 실행 계정, 실행 파일 해시를 원인 후보로 추적합니다.",
            "observed_behavior": "관측 행위는 의심 명령 실행입니다. 명령 내용에 따라 다운로드, 자격증명 접근, 방어 회피, 지속성 행위를 분류합니다.",
            "not_proven": "네트워크 목적지, 파일 쓰기, 레지스트리 변경 로그가 없으면 실제 연결이나 데이터 변조는 확인되지 않습니다.",
            "correlation_targets": ["Sysmon 3/11/13", "PowerShell 4103/4104", "Defender/EDR", "프록시/방화벽 로그"],
        }
    return {
        "cause_focus": "계정, 호스트, 프로세스, 원본 IP, 명령줄 필드를 기준으로 발생 원인을 추적합니다.",
        "observed_behavior": "관측 행위는 finding 유형과 근거 이벤트 필드 범위 안에서만 설명합니다.",
        "not_proven": "근거 이벤트에 없는 네트워크 연결, 파일/레지스트리 변조, 데이터 유출은 확인되지 않은 행위로 남깁니다.",
        "correlation_targets": ["4624/4625/4648", "4688/Sysmon", "PowerShell", "방화벽/프록시/EDR"],
    }


def _field(event: EventRecord, *names: str) -> str | None:
    sources = (event.event_data, event.user_data)
    for name in names:
        for source in sources:
            if name in source and source[name] not in {"", "-"}:
                return source[name]
        lower_name = name.lower()
        for source in sources:
            for key, value in source.items():
                if key.lower().endswith(lower_name) and value not in {"", "-"}:
                    return value
    return None


def _account(event: EventRecord) -> str | None:
    user = _field(
        event,
        "TargetUserName",
        "SubjectUserName",
        "AccountName",
        "UserName",
        "User",
        "SecurityUserID",
    )
    domain = _field(event, "TargetDomainName", "SubjectDomainName", "DomainName")
    if user and domain and domain not in {"-", "."} and "\\" not in user:
        return f"{domain}\\{user}"
    return user


def _source_ip(event: EventRecord) -> str | None:
    return _field(event, "IpAddress", "SourceNetworkAddress", "ClientAddress", "SourceAddress")


def _process(event: EventRecord) -> str | None:
    return _field(event, "NewProcessName", "ProcessName", "Image", "Application")


def _command_line(event: EventRecord) -> str | None:
    return _field(event, "CommandLine", "ProcessCommandLine", "ScriptBlockText")


def _event_text(event: EventRecord) -> str:
    parts = [
        event.provider or "",
        event.channel or "",
        event.computer or "",
        *event.event_data.values(),
        *event.user_data.values(),
    ]
    return " ".join(str(part) for part in parts if part)


def _valid_ip_field(value: str | None) -> bool:
    if not value:
        return False
    return value not in {"-", "::1", "127.0.0.1", "0.0.0.0"}


def _counter_list(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."
