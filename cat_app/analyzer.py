from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import math
from pathlib import PureWindowsPath
import statistics
from typing import Any, Iterable

from .models import EventRecord, ParseResult
from .timeutil import isoformat_utc

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
SCENARIO_CORRELATION_WINDOW_SECONDS = 60 * 60
AUTHENTICATION_BURST_WINDOW_SECONDS = 10 * 60
FINDING_EVIDENCE_LIMIT = 96
NETWORK_CORRELATION_WINDOW_SECONDS = 10 * 60
DNS_CORRELATION_WINDOW_SECONDS = 5 * 60
NETWORK_ACTIVITY_GROUP_LIMIT = 64
NETWORK_FINDING_LIMIT = 24
NETWORK_CORRELATION_CANDIDATE_LIMIT = 32
NETWORK_CORRELATED_DNS_LIMIT = 4
NETWORK_FINDING_EVIDENCE_LIMIT = 32

COMMON_DESTINATION_PORTS = {
    22,
    25,
    53,
    80,
    88,
    110,
    123,
    143,
    389,
    443,
    445,
    464,
    465,
    587,
    636,
    853,
    993,
    995,
    3268,
    3269,
    3389,
}
HIGH_RISK_DESTINATION_PORTS = {
    1337,
    4444,
    5555,
    6666,
    6667,
    6668,
    6669,
    9001,
    9050,
    31337,
}
COMMON_NETWORK_CLIENTS = {
    "brave.exe",
    "chrome.exe",
    "firefox.exe",
    "iexplore.exe",
    "msedge.exe",
    "onedrive.exe",
    "opera.exe",
    "outlook.exe",
    "teams.exe",
}
KNOWN_TUNNEL_CLIENTS = {
    "chisel.exe",
    "frpc.exe",
    "ligolo-agent.exe",
    "ngrok.exe",
    "ncat.exe",
    "nc.exe",
    "plink.exe",
    "socat.exe",
}
SERVER_PROCESSES_WITH_SENSITIVE_LOOPBACK = {
    "httpd.exe",
    "nginx.exe",
    "php-cgi.exe",
    "tomcat.exe",
    "w3wp.exe",
}
SENSITIVE_TUNNEL_PORTS = {135, 139, 445, 3389, 5985, 5986}

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
        key=lambda event: _event_time_sort_key(event.time_created),
    )
    findings: list[dict[str, Any]] = []
    network_findings, network_activity = _network_analysis(records)

    findings.extend(_single_rule_findings(records))
    findings.extend(_failed_logon_bursts(records))
    findings.extend(_kerberos_ntlm_failure_bursts(records))
    findings.extend(_remote_logon_findings(records))
    findings.extend(_explicit_credential_findings(records))
    findings.extend(_privileged_logon_findings(records))
    findings.extend(_suspicious_process_findings(records))
    findings.extend(_powershell_findings(records))
    findings.extend(network_findings)

    findings = sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item["severity"], 0),
            item.get("first_seen") or "",
            item["title"],
        ),
    )

    suspicious_events = _suspicious_events(findings)
    scenario_candidates = _scenario_candidates(suspicious_events)

    return {
        "analysis_schema_version": 2,
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
        "network_activity": network_activity,
        "findings": findings,
        "suspicious_events": suspicious_events,
        "suspicious_event_scope": {
            "included_count": len(suspicious_events),
            "finding_event_count": sum(int(finding.get("event_count") or 0) for finding in findings),
            "per_finding_evidence_limit": FINDING_EVIDENCE_LIMIT,
            "evidence_truncated": any(
                int(finding.get("event_count") or 0) > len(finding.get("evidence") or [])
                for finding in findings
            ),
            "note": (
                "동일 원본 이벤트가 여러 규칙에 탐지되면 하나로 통합합니다. "
                f"대량 탐지는 finding별 최대 {FINDING_EVIDENCE_LIMIT}개의 "
                "시간 균형 대표 근거만 포함될 수 있습니다."
            ),
        },
        "scenario_candidates": scenario_candidates,
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
    destination_ips = Counter(
        _destination_ip(event)
        for event in records
        if _valid_ip_field(_destination_ip(event))
    )
    destination_domains = Counter(
        domain
        for event in records
        if (
            domain := _normalized_domain(
                _field(event, "DestinationHostname", "QueryName")
            )
        )
    )

    timed_records = [event for event in records if event.time_created is not None]
    first_seen = timed_records[0].time_created if timed_records else None
    last_seen = timed_records[-1].time_created if timed_records else None

    return {
        "first_seen": isoformat_utc(first_seen),
        "last_seen": isoformat_utc(last_seen),
        "top_event_ids": _counter_list(event_ids, 20),
        "top_providers": _counter_list(providers, 12),
        "top_channels": _counter_list(channels, 12),
        "top_hosts": _counter_list(computers, 20),
        "top_accounts": _counter_list(accounts, 20),
        "top_source_ips": _counter_list(source_ips, 20),
        "top_destination_ips": _counter_list(destination_ips, 20),
        "top_destination_domains": _counter_list(destination_domains, 20),
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
            _is_service_install_event,
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
            _is_scheduled_task_event,
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
            lambda e: _event_id(e) == "4720" and _is_security_event(e),
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
            lambda e: _event_id(e) in {"4722", "4723", "4724", "4738"} and _is_security_event(e),
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
            lambda e: _event_id(e) in {"4728", "4732", "4756"} and _is_security_event(e),
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
        if _event_id(event) != "4625" or not _is_security_event(event):
            continue
        key = (_account(event) or "unknown", _source_ip(event) or "unknown", event.computer or "unknown")
        groups[key].append(event)

    bursts = []
    for key, events in groups.items():
        burst = _largest_event_window(
            events,
            AUTHENTICATION_BURST_WINDOW_SECONDS,
        )
        if len(burst) >= 5:
            bursts.append((key, burst))

    findings: list[dict[str, Any]] = []
    for (account, source_ip, host), events in sorted(
        bursts,
        key=lambda item: len(item[1]),
        reverse=True,
    )[:10]:
        severity = "high" if len(events) >= 20 else "medium"
        findings.append(
            _finding(
                "failed_logon_burst",
                f"로그온 실패 반복: {account} / {source_ip} -> {host}",
                severity,
                events,
                "동일 계정/원본/대상 조합에서 10분 이내 반복 실패가 발생했습니다. 비밀번호 추측, 계정 탈취 시도, 잘못된 서비스 자격증명 가능성을 확인해야 합니다.",
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
        if _event_id(event) not in {"4771", "4776"} or not _is_security_event(event):
            continue
        groups[(_account(event) or "unknown", _source_ip(event) or event.computer or "unknown")].append(event)

    bursts = []
    for key, events in groups.items():
        burst = _largest_event_window(
            events,
            AUTHENTICATION_BURST_WINDOW_SECONDS,
        )
        if len(burst) >= 10:
            bursts.append((key, burst))

    findings: list[dict[str, Any]] = []
    for (account, origin), events in sorted(
        bursts,
        key=lambda item: len(item[1]),
        reverse=True,
    )[:8]:
        findings.append(
            _finding(
                "auth_failure_burst",
                f"Kerberos/NTLM 인증 실패 반복: {account} / {origin}",
                "medium",
                events,
                "Kerberos 또는 NTLM 인증 실패가 10분 이내 반복되었습니다. 계정 잠금 전조, 스프레이, 잘못된 저장 자격증명 가능성이 있습니다.",
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
        if _event_id(event) == "4624"
        and _is_security_event(event)
        and _field(event, "LogonType") == "10"
        and _valid_ip_field(_source_ip(event))
    ]
    network_events = [
        event
        for event in records
        if _event_id(event) == "4624"
        and _is_security_event(event)
        and _field(event, "LogonType") == "3"
        and _valid_ip_field(_source_ip(event))
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
    events = [event for event in records if _event_id(event) == "4648" and _is_security_event(event)]
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
        if _event_id(event) == "4672"
        and _is_security_event(event)
        and (_account(event) or "").lower() not in {"system", "local service", "network service"}
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
        if not _is_process_creation_event(event):
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
        if not _is_powershell_event(event):
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


def _network_analysis(
    records: list[EventRecord],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Correlate process, DNS, and connection evidence without threat intel.

    A public destination alone is deliberately not treated as malicious.  A
    finding requires a stronger, locally verifiable signal such as a known
    high-risk port, execution from a user-writable path, a suspicious command,
    or sufficiently regular/repeated communication.  All connections are still
    summarized in ``network_activity`` so an investigator can inspect activity
    that did not cross the anomaly threshold.
    """
    process_events = [event for event in records if _is_process_creation_event(event)]
    dns_events = [event for event in records if _is_dns_query_event(event)]
    connection_events = [event for event in records if _is_network_connection_event(event)]

    processes_by_guid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    processes_by_pid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    dns_by_guid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    dns_by_pid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    for sequence, event in enumerate(process_events):
        host = _normalized_host(event.computer)
        if guid := _normalized_process_guid(_field(event, "ProcessGuid")):
            _append_timed_event(processes_by_guid, (host, guid), event, sequence)
        if pid := _normalized_process_id(
            _field(event, "ProcessId", "NewProcessId")
        ):
            _append_timed_event(processes_by_pid, (host, pid), event, sequence)
    for sequence, event in enumerate(dns_events):
        host = _normalized_host(event.computer)
        if guid := _normalized_process_guid(_field(event, "ProcessGuid")):
            _append_timed_event(dns_by_guid, (host, guid), event, sequence)
        if pid := _normalized_process_id(_field(event, "ProcessId")):
            _append_timed_event(dns_by_pid, (host, pid), event, sequence)
    _sort_timed_event_index(processes_by_guid)
    _sort_timed_event_index(processes_by_pid)
    _sort_timed_event_index(dns_by_guid)
    _sort_timed_event_index(dns_by_pid)

    observations: list[dict[str, Any]] = []
    for event in connection_events:
        observation = _network_observation(event)
        if observation is None:
            continue
        process_event, process_link = _correlated_process_event(
            event,
            processes_by_guid,
            processes_by_pid,
        )
        correlated_dns, dns_link = _correlated_dns_events(
            event,
            dns_by_guid,
            dns_by_pid,
        )
        observation["process_event"] = process_event
        observation["dns_events"] = correlated_dns
        observation["correlation_reasons"] = [
            reason for reason in (process_link, dns_link) if reason
        ]
        observations.append(observation)

    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        groups[_network_group_key(observation)].append(observation)

    group_summaries: list[dict[str, Any]] = []
    finding_candidates: list[tuple[int, dict[str, Any], list[EventRecord]]] = []
    for grouped_observations in groups.values():
        for session in _network_sessions(grouped_observations):
            summary, related_events = _summarize_network_group(session)
            group_summaries.append(summary)
            if not summary["suspicious"]:
                continue
            score = int(summary.pop("_score"))
            finding_candidates.append((score, summary, related_events))
    for summary in group_summaries:
        summary.pop("_score", None)

    finding_candidates.sort(
        key=lambda item: (
            -item[0],
            item[1].get("first_seen") or "",
            item[1].get("destination_ip") or item[1].get("destination_hostname") or "",
        )
    )
    findings: list[dict[str, Any]] = []
    for _, summary, related_events in finding_candidates[:NETWORK_FINDING_LIMIT]:
        rule_id = "suspicious_network_connection"
        title_prefix = "의심 네트워크 통신"
        if summary["beacon_signal"]:
            rule_id = "possible_network_beacon"
            title_prefix = "반복·주기적 외부 통신 후보"
        elif summary["suspicious_domain_signal"]:
            rule_id = "suspicious_dns_network_activity"
            title_prefix = "의심 DNS와 연결된 네트워크 통신"
        destination = (
            summary.get("destination_hostname")
            or summary.get("destination_ip")
            or "목적지 미상"
        )
        if summary.get("destination_port"):
            destination = f"{destination}:{summary['destination_port']}"
        process = summary.get("process") or "프로세스 미상"
        signals = ", ".join(summary["anomaly_signals"])
        severity = _network_finding_severity(summary)
        finding = _finding(
            rule_id,
            f"{title_prefix}: {process} -> {destination}",
            severity,
            related_events,
            (
                f"프로세스와 목적지 통신에서 {signals} 근거가 관찰되었습니다. "
                "이는 침해 확정 판정이 아니며 승인된 관리·개발 도구 또는 정상 응용프로그램 "
                "통신 가능성을 프로세스 서명, 자산 역할, 프록시/방화벽 로그로 확인해야 합니다."
            ),
            "medium",
            [
                "ProcessGuid와 프로세스 생성 이벤트를 기준으로 부모 프로세스, 명령줄, 파일 해시와 서명을 확인하세요.",
                "DNS, 프록시, 방화벽 로그에서 목적지의 최초·최종 통신 시각과 전송량을 교차 검증하세요.",
                "동일 목적지에 대한 정상 소프트웨어 기준선과 주기성을 비교하고 필요하면 호스트를 격리하세요.",
            ],
            evidence_limit=NETWORK_FINDING_EVIDENCE_LIMIT,
        )
        finding["network_context"] = {
            key: value
            for key, value in summary.items()
            if key not in {"suspicious"}
        }
        findings.append(finding)

    sorted_groups = sorted(
        group_summaries,
        key=lambda item: (
            not item["suspicious"],
            -int(item["connection_count"]),
            item.get("first_seen") or "",
        ),
    )
    external_connections = sum(
        1 for observation in observations if observation["external_destination"]
    )
    unique_external_destinations = {
        str(observation.get("destination_ip") or observation.get("destination_hostname"))
        for observation in observations
        if observation["external_destination"]
        and (observation.get("destination_ip") or observation.get("destination_hostname"))
    }
    dns_counter = Counter(
        query
        for event in dns_events
        if (query := _normalized_domain(_field(event, "QueryName")))
    )
    included_groups = sorted_groups[:NETWORK_ACTIVITY_GROUP_LIMIT]
    group_limit_reached = len(sorted_groups) > len(included_groups)
    finding_limit_reached = len(finding_candidates) > len(findings)
    activity = {
        "connection_event_count": len(connection_events),
        "normalized_connection_count": len(observations),
        "dns_query_event_count": len(dns_events),
        "external_connection_count": external_connections,
        "unique_external_destination_count": len(unique_external_destinations),
        "group_count": len(sorted_groups),
        "included_group_count": len(included_groups),
        "suspicious_group_count": len(finding_candidates),
        "included_finding_count": len(findings),
        "truncated": group_limit_reached or finding_limit_reached,
        "limitation": (
            f"네트워크 통신 {len(sorted_groups)}개 그룹 중 대표 {len(included_groups)}개와 "
            f"의심 그룹 {len(finding_candidates)}개 중 최대 {NETWORK_FINDING_LIMIT}개 finding만 포함했습니다."
            if group_limit_reached or finding_limit_reached
            else "공개 위협 인텔리전스 없이 로컬 이벤트의 목적지·포트·경로·반복성만 평가했습니다. 정상 기준선과 교차 검증해야 합니다."
        ),
        "top_dns_queries": _counter_list(dns_counter, 30),
        "connections": included_groups,
    }
    return findings, activity


def _network_observation(event: EventRecord) -> dict[str, Any] | None:
    destination_ip = _destination_ip(event)
    destination_hostname = _field(event, "DestinationHostname")
    destination_port = _normalized_port(_destination_port(event))
    source_ip = _source_ip(event)
    source_port = _normalized_port(_source_port(event))
    process = _process(event)
    process_guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    process_id = _normalized_process_id(_field(event, "ProcessId", "ProcessID"))
    protocol = _normalized_protocol(_field(event, "Protocol"))
    initiated = _normalized_boolean(_field(event, "Initiated"))
    direction = _network_direction(event, initiated)
    if not any((destination_ip, destination_hostname, destination_port, process)):
        return None
    return {
        "event": event,
        "time": event.time_created,
        "host": event.computer,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "destination_hostname": destination_hostname,
        "protocol": protocol,
        "initiated": initiated,
        "network_direction": direction,
        "process": process,
        "process_guid": process_guid,
        "process_id": process_id,
        "external_destination": _is_external_destination(
            destination_ip,
            destination_hostname,
        ),
    }


def _network_group_key(observation: dict[str, Any]) -> tuple[str, ...]:
    process_identity = (
        observation.get("process_guid")
        or "|".join(
            (
                str(observation.get("process") or "").casefold(),
                str(observation.get("process_id") or ""),
            )
        )
    )
    return (
        _normalized_host(observation.get("host")),
        str(process_identity),
        str(observation.get("destination_ip") or "").casefold(),
        str(observation.get("destination_hostname") or "").casefold(),
        str(observation.get("destination_port") or ""),
        str(observation.get("protocol") or "").casefold(),
        str(observation.get("network_direction") or "").casefold(),
    )


def _network_sessions(
    observations: list[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    """Split PID-only groups at long gaps to avoid PID-reuse correlations."""
    ordered = sorted(
        observations,
        key=lambda item: _event_time_sort_key(item.get("time")),
    )
    if not ordered or any(item.get("process_guid") for item in ordered):
        return [ordered] if ordered else []
    sessions: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    previous_time: datetime | None = None
    for observation in ordered:
        current_time = observation.get("time")
        if (
            current
            and previous_time is not None
            and current_time is not None
            and (_as_utc(current_time) - _as_utc(previous_time)).total_seconds()
            > SCENARIO_CORRELATION_WINDOW_SECONDS
        ):
            sessions.append(current)
            current = []
        current.append(observation)
        if current_time is not None:
            previous_time = current_time
    if current:
        sessions.append(current)
    return sessions


def _summarize_network_group(
    observations: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[EventRecord]]:
    observations = sorted(
        observations,
        key=lambda item: _event_time_sort_key(item["time"]),
    )
    first = observations[0]
    timed = [item["time"] for item in observations if item["time"] is not None]
    dns_events = _deduplicate_events(
        event
        for item in observations
        for event in item.get("dns_events") or []
    )
    process_events = _deduplicate_events(
        item["process_event"]
        for item in observations
        if item.get("process_event") is not None
    )
    connection_events = _deduplicate_events(item["event"] for item in observations)
    related_events = _deduplicate_events(
        [*process_events, *dns_events, *connection_events]
    )
    process = first.get("process")
    if not process and process_events:
        process = _process(process_events[0])
    command_suspicious = any(
        _event_has_suspicious_command(event) for event in process_events
    )
    writable_path = _is_user_writable_process_path(process)
    process_name = _windows_basename(process)
    destination_port = first.get("destination_port")
    high_risk_port = destination_port in HIGH_RISK_DESTINATION_PORTS
    nonstandard_port = bool(
        destination_port and destination_port not in COMMON_DESTINATION_PORTS
    )
    common_client = process_name in COMMON_NETWORK_CLIENTS
    known_tunnel_client = process_name in KNOWN_TUNNEL_CLIENTS
    sensitive_loopback = bool(
        _is_loopback_ip(first.get("destination_ip"))
        and destination_port in SENSITIVE_TUNNEL_PORTS
        and process_name in SERVER_PROCESSES_WITH_SENSITIVE_LOOPBACK
        and first.get("network_direction") != "inbound"
    )
    possible_beacon, beacon_detail = _possible_beacon(timed)
    dns_queries = sorted(
        {
            query
            for event in dns_events
            if (query := _normalized_domain(_field(event, "QueryName")))
        }
    )
    suspicious_domain_pattern = any(
        _suspicious_domain_pattern(query) for query in dns_queries
    )
    external_destination = any(
        item["external_destination"] for item in observations
    )

    signals: list[str] = []
    score = 0
    if external_destination:
        signals.append("외부/비로컬 목적지")
        score += 1
    if high_risk_port:
        signals.append(f"고위험 목적지 포트 {destination_port}")
        score += 5
    if nonstandard_port:
        signals.append(f"비표준 목적지 포트 {destination_port}")
        score += 1
    if writable_path and not (common_client and not high_risk_port):
        signals.append("사용자 쓰기 가능 경로의 프로세스")
        score += 3
    if command_suspicious:
        signals.append("연결된 프로세스 생성 이벤트의 의심 명령줄")
        score += 4
    if known_tunnel_client:
        signals.append(f"알려진 터널링 도구 프로세스 {process_name}")
        score += 5
    if sensitive_loopback:
        signals.append(
            f"서버 프로세스의 민감 서비스 loopback 통신 {destination_port}"
        )
        score += 5
    if dns_queries:
        signals.append("ProcessGuid/PID와 시간으로 연결된 DNS 질의")
        score += 1
    if suspicious_domain_pattern:
        signals.append("긴 고엔트로피 DNS 레이블")
        score += 3
    if possible_beacon:
        signals.append(beacon_detail)
        score += 5

    strong_process_signal = command_suspicious or (
        writable_path and not (common_client and not high_risk_port)
    )
    suspicious_domain_signal = bool(
        suspicious_domain_pattern
        and external_destination
        and (strong_process_signal or nonstandard_port or len(observations) >= 3)
    )
    beacon_signal = bool(
        possible_beacon
        and external_destination
        and first.get("network_direction") != "inbound"
    )
    suspicious = bool(
        high_risk_port
        or known_tunnel_client
        or sensitive_loopback
        or beacon_signal
        or suspicious_domain_signal
        or (external_destination and strong_process_signal)
        or (external_destination and nonstandard_port and strong_process_signal)
    )
    correlation_reasons = []
    for observation in observations:
        for reason in observation.get("correlation_reasons") or []:
            if reason not in correlation_reasons:
                correlation_reasons.append(reason)
    summary = {
        "first_seen": isoformat_utc(timed[0]) if timed else None,
        "last_seen": isoformat_utc(timed[-1]) if timed else None,
        "host": first.get("host"),
        "source_ip": first.get("source_ip"),
        "source_port": first.get("source_port"),
        "destination_ip": first.get("destination_ip"),
        "destination_port": destination_port,
        "destination_hostname": first.get("destination_hostname"),
        "protocol": first.get("protocol"),
        "initiated": first.get("initiated"),
        "network_direction": first.get("network_direction"),
        "process": process,
        "process_guid": first.get("process_guid"),
        "process_id": first.get("process_id"),
        "connection_count": len(observations),
        "external_destination": external_destination,
        "dns_queries": dns_queries[:12],
        "correlation_reasons": correlation_reasons,
        "anomaly_signals": signals,
        "possible_beacon": possible_beacon,
        "beacon_signal": beacon_signal,
        "suspicious_domain_pattern": suspicious_domain_pattern,
        "suspicious_domain_signal": suspicious_domain_signal,
        "known_tunnel_client": known_tunnel_client,
        "sensitive_loopback": sensitive_loopback,
        "suspicious": suspicious,
        "_score": score,
    }
    return summary, related_events


def _correlated_process_event(
    event: EventRecord,
    by_guid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    by_pid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
) -> tuple[EventRecord | None, str | None]:
    host = _normalized_host(event.computer)
    guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    if guid:
        candidates = by_guid.get((host, guid), [])
        if candidate := _most_recent_preceding_event(event, candidates, None):
            return candidate, "동일 ProcessGuid로 프로세스 생성 이벤트 연결"

    pid = _normalized_process_id(_field(event, "ProcessId", "ProcessID"))
    if not pid:
        return None, None
    candidates = by_pid.get((host, pid), [])
    candidate = _most_recent_preceding_event(
        event,
        candidates,
        NETWORK_CORRELATION_WINDOW_SECONDS,
    )
    if candidate is None:
        return None, None
    connection_image = str(_process(event) or "").casefold()
    process_image = str(_process(candidate) or "").casefold()
    image_relation = "프로세스 경로"
    if connection_image and process_image and connection_image != process_image:
        connection_name = _windows_basename(connection_image)
        process_name = _windows_basename(process_image)
        if not connection_name or connection_name != process_name:
            return None, None
        # Security 5156 commonly records an NT device path while 4688 records
        # a drive-letter path.  Host + PID + a short time window + the same
        # executable basename is useful supporting evidence, but the wording
        # keeps this weaker than an exact path or ProcessGuid match.
        image_relation = "프로세스 파일명(경로 표기 상이)"
    return (
        candidate,
        f"동일 호스트·PID·{image_relation}와 10분 시간창으로 프로세스 생성 이벤트 연결",
    )


def _correlated_dns_events(
    event: EventRecord,
    by_guid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    by_pid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
) -> tuple[list[EventRecord], str | None]:
    host = _normalized_host(event.computer)
    guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    pid = _normalized_process_id(_field(event, "ProcessId", "ProcessID"))
    candidates: list[EventRecord] = []
    link_kind: str | None = None
    if guid:
        candidates = _events_near_target(
            event,
            by_guid.get((host, guid), []),
            DNS_CORRELATION_WINDOW_SECONDS,
        )
        if candidates:
            link_kind = "동일 ProcessGuid"
    if not candidates and pid:
        candidates = _events_near_target(
            event,
            by_pid.get((host, pid), []),
            DNS_CORRELATION_WINDOW_SECONDS,
        )
        if candidates:
            link_kind = "동일 호스트·PID"
    if not candidates:
        return [], None

    destination_hostname = _normalized_domain(_field(event, "DestinationHostname"))
    linked: list[tuple[float, EventRecord]] = []
    for candidate in candidates:
        delta = _event_time_delta_seconds(event, candidate)
        if delta is None or delta > DNS_CORRELATION_WINDOW_SECONDS:
            continue
        query = _normalized_domain(_field(candidate, "QueryName"))
        if destination_hostname and query and not _domains_equivalent(
            destination_hostname,
            query,
        ):
            continue
        linked.append((delta, candidate))
    if not linked:
        return [], None
    linked.sort(key=lambda item: item[0])
    domain_note = " 및 동일 도메인" if destination_hostname else ""
    return (
        [item[1] for item in linked[:NETWORK_CORRELATED_DNS_LIMIT]],
        f"{link_kind}{domain_note}, 5분 시간창으로 DNS 질의 연결",
    )


def _most_recent_preceding_event(
    target: EventRecord,
    candidates: list[tuple[float, int, EventRecord]],
    max_delta_seconds: int | None,
) -> EventRecord | None:
    if target.time_created is None or not candidates:
        return None
    target_timestamp = _as_utc(target.time_created).timestamp()
    position = bisect_right(candidates, (target_timestamp, 10**30)) - 1
    if position < 0:
        return None
    candidate_timestamp, _, candidate = candidates[position]
    if (
        max_delta_seconds is not None
        and target_timestamp - candidate_timestamp > max_delta_seconds
    ):
        return None
    return candidate


def _events_near_target(
    target: EventRecord,
    candidates: list[tuple[float, int, EventRecord]],
    max_delta_seconds: int,
) -> list[EventRecord]:
    if target.time_created is None or not candidates:
        return []
    target_timestamp = _as_utc(target.time_created).timestamp()
    left = bisect_left(candidates, (target_timestamp - max_delta_seconds, -1))
    right = bisect_right(candidates, (target_timestamp + max_delta_seconds, 10**30))
    position = bisect_left(candidates, (target_timestamp, -1), left, right)
    half_limit = NETWORK_CORRELATION_CANDIDATE_LIMIT // 2
    nearby_left = max(left, position - half_limit)
    nearby_right = min(
        right,
        nearby_left + NETWORK_CORRELATION_CANDIDATE_LIMIT,
    )
    nearby_left = max(left, nearby_right - NETWORK_CORRELATION_CANDIDATE_LIMIT)
    nearby = candidates[nearby_left:nearby_right]
    return [item[2] for item in nearby]


def _append_timed_event(
    index: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    key: tuple[str, str],
    event: EventRecord,
    sequence: int,
) -> None:
    if event.time_created is None:
        return
    index[key].append((_as_utc(event.time_created).timestamp(), sequence, event))


def _sort_timed_event_index(
    index: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
) -> None:
    for events in index.values():
        events.sort(key=lambda item: (item[0], item[1]))


def _possible_beacon(times: list[datetime]) -> tuple[bool, str]:
    if len(times) < 6:
        return False, ""
    normalized = sorted(_as_utc(value) for value in times)
    intervals = [
        (right - left).total_seconds()
        for left, right in zip(normalized, normalized[1:])
        if (right - left).total_seconds() > 0
    ]
    if len(intervals) < 5:
        return False, ""
    median_interval = statistics.median(intervals)
    if not 5 <= median_interval <= 60 * 60:
        return False, ""
    tolerance = max(2.0, median_interval * 0.20)
    regular_count = sum(
        abs(interval - median_interval) <= tolerance for interval in intervals
    )
    regular_ratio = regular_count / len(intervals)
    if regular_ratio < 0.75:
        return False, ""
    return (
        True,
        f"반복·주기 통신 후보 {len(times)}회(중앙 간격 {median_interval:.1f}초, 규칙성 {regular_ratio:.0%})",
    )


def _network_finding_severity(summary: dict[str, Any]) -> str:
    signals = set(summary.get("anomaly_signals") or [])
    strong_count = sum(
        1
        for prefix in (
            "고위험 목적지 포트",
            "사용자 쓰기 가능 경로",
            "연결된 프로세스 생성 이벤트",
            "알려진 터널링 도구",
            "서버 프로세스의 민감 서비스 loopback",
            "반복·주기 통신 후보",
            "긴 고엔트로피",
        )
        if any(str(signal).startswith(prefix) for signal in signals)
    )
    return "high" if strong_count >= 2 else "medium"


def _event_has_suspicious_command(event: EventRecord) -> bool:
    text = f" {_event_text(event).casefold()} "
    return any(
        keyword in text
        for keywords in SUSPICIOUS_COMMAND_KEYWORDS.values()
        for keyword in keywords
    ) or any(keyword in text for keyword in POWERSHELL_KEYWORDS)


def _is_user_writable_process_path(value: Any) -> bool:
    if not value:
        return False
    path = str(value).strip().replace("/", "\\").casefold()
    return any(
        marker in path
        for marker in (
            "\\appdata\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\users\\public\\",
            "\\windows\\temp\\",
            "\\programdata\\",
            "\\$recycle.bin\\",
        )
    ) or path.startswith(("temp\\", "tmp\\"))


def _windows_basename(value: Any) -> str:
    if not value:
        return ""
    return PureWindowsPath(str(value)).name.casefold()


def _suspicious_domain_pattern(value: str) -> bool:
    # Conservative DGA-like heuristic: require a long, mixed alphanumeric,
    # high-entropy first label.  It is only promoted as a hypothesis.
    label = value.split(".", 1)[0].casefold()
    if len(label) < 28 or not label.isalnum():
        return False
    digit_count = sum(character.isdigit() for character in label)
    letter_count = sum(character.isalpha() for character in label)
    if digit_count < 4 or letter_count < 12:
        return False
    counts = Counter(label)
    entropy = -sum(
        (count / len(label)) * math.log2(count / len(label))
        for count in counts.values()
    )
    return entropy >= 3.8


def _deduplicate_events(events: Iterable[EventRecord]) -> list[EventRecord]:
    seen: set[tuple[str, ...]] = set()
    result = []
    for event in events:
        key = (
            event.source_file,
            str(event.record_id or ""),
            str(event.event_id or ""),
            isoformat_utc(event.time_created) or "",
            event.computer or "",
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(event)
    return result


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
                    "source_port": evidence.get("source_port"),
                    "destination_ip": evidence.get("destination_ip"),
                    "destination_port": evidence.get("destination_port"),
                    "destination_hostname": evidence.get("destination_hostname"),
                    "protocol": evidence.get("protocol"),
                    "initiated": evidence.get("initiated"),
                    "process": evidence.get("process"),
                    "process_id": evidence.get("process_id"),
                    "process_guid": evidence.get("process_guid"),
                    "query_name": evidence.get("query_name"),
                    "network_direction": evidence.get("network_direction"),
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
                    "source_port": evidence.get("source_port"),
                    "destination_ip": evidence.get("destination_ip"),
                    "destination_port": evidence.get("destination_port"),
                    "destination_hostname": evidence.get("destination_hostname"),
                    "protocol": evidence.get("protocol"),
                    "initiated": evidence.get("initiated"),
                    "process": evidence.get("process"),
                    "process_id": evidence.get("process_id"),
                    "process_guid": evidence.get("process_guid"),
                    "query_name": evidence.get("query_name"),
                    "network_direction": evidence.get("network_direction"),
                }
            )
            if len(entries) >= 50:
                break

    return sorted(entries, key=lambda item: item.get("time") or "")[:100]


def _suspicious_events(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    aggregated: dict[tuple[str, ...], dict[str, Any]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "unknown")
        title = str(finding.get("title") or rule_id)
        description = str(finding.get("description") or title)
        severity = str(finding.get("severity") or "info")
        confidence = str(finding.get("confidence") or "unknown")
        for evidence in finding.get("evidence") or []:
            if not isinstance(evidence, dict):
                continue
            key = _evidence_identity(evidence)
            item = aggregated.get(key)
            if item is None:
                item = {
                    "time": evidence.get("time"),
                    "source_file": evidence.get("source_file"),
                    "record_id": evidence.get("record_id"),
                    "event_id": evidence.get("event_id"),
                    "provider": evidence.get("provider"),
                    "channel": evidence.get("channel"),
                    "host": evidence.get("host"),
                    "account": evidence.get("account"),
                    "source_ip": evidence.get("source_ip"),
                    "source_port": evidence.get("source_port"),
                    "destination_ip": evidence.get("destination_ip"),
                    "destination_port": evidence.get("destination_port"),
                    "destination_hostname": evidence.get("destination_hostname"),
                    "protocol": evidence.get("protocol"),
                    "initiated": evidence.get("initiated"),
                    "process": evidence.get("process"),
                    "process_id": evidence.get("process_id"),
                    "process_guid": evidence.get("process_guid"),
                    "query_name": evidence.get("query_name"),
                    "network_direction": evidence.get("network_direction"),
                    "command_line": evidence.get("command_line"),
                    "fields": dict(evidence.get("fields") or {}),
                    "severity": severity,
                    "confidence": confidence,
                    "rule_ids": [],
                    "reasons": [],
                }
                aggregated[key] = item
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(str(item["severity"]), 0):
                item["severity"] = severity
            if CONFIDENCE_RANK.get(confidence, 0) > CONFIDENCE_RANK.get(str(item["confidence"]), 0):
                item["confidence"] = confidence
            if rule_id not in item["rule_ids"]:
                item["rule_ids"].append(rule_id)
            reason = {"rule_id": rule_id, "title": title, "description": description}
            if reason not in item["reasons"]:
                item["reasons"].append(reason)

    ordered = sorted(
        aggregated.values(),
        key=lambda item: (
            item.get("time") is None,
            item.get("time") or "",
            item.get("source_file") or "",
            _record_sort_key(item.get("record_id")),
            item.get("event_id") or "",
        ),
    )
    for index, item in enumerate(ordered, start=1):
        item["event_ref"] = f"EVT-{index:04d}"
    return ordered


def _evidence_identity(evidence: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(evidence.get(key) or "")
        for key in (
            "source_file",
            "record_id",
            "time",
            "event_id",
            "provider",
            "channel",
            "host",
            "account",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "destination_hostname",
            "protocol",
            "initiated",
            "process",
            "process_id",
            "process_guid",
            "query_name",
            "network_direction",
            "command_line",
        )
    )


def _record_sort_key(value: Any) -> tuple[int, int | str]:
    text = str(value or "")
    try:
        return (0, int(text))
    except ValueError:
        return (1, text)


def _scenario_candidates(suspicious_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not suspicious_events:
        return []

    parents = list(range(len(suspicious_events)))
    edge_reasons: dict[tuple[int, int], list[str]] = {}

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(suspicious_events)):
        for right in range(left + 1, len(suspicious_events)):
            reasons = _event_link_reasons(suspicious_events[left], suspicious_events[right])
            if not reasons:
                continue
            edge_reasons[(left, right)] = reasons
            union(left, right)

    groups: dict[int, list[int]] = defaultdict(list)
    for index in range(len(suspicious_events)):
        groups[find(index)].append(index)

    candidates = []
    ordered_groups = sorted(
        groups.values(),
        key=lambda indexes: (
            suspicious_events[indexes[0]].get("time") is None,
            suspicious_events[indexes[0]].get("time") or "",
            suspicious_events[indexes[0]].get("event_ref") or "",
        ),
    )
    for indexes in ordered_groups:
        if len(indexes) < 2:
            continue
        events = [suspicious_events[index] for index in indexes]
        events.sort(key=lambda item: (item.get("time") is None, item.get("time") or "", item["event_ref"]))
        reasons = []
        index_set = set(indexes)
        for (left, right), values in edge_reasons.items():
            if left in index_set and right in index_set:
                for value in values:
                    if value not in reasons:
                        reasons.append(value)
        stages = [
            {
                "order": order,
                "phase": _scenario_phase(event.get("rule_ids") or []),
                "event_ref": event["event_ref"],
                "description": _scenario_stage_description(event),
            }
            for order, event in enumerate(events, start=1)
        ]
        confidence = _scenario_confidence(events, reasons)
        phases = []
        for stage in stages:
            if stage["phase"] not in phases:
                phases.append(stage["phase"])
        unique_rules = {
            str(rule_id)
            for event in events
            for rule_id in event.get("rule_ids") or []
            if rule_id
        }
        # Repeated instances of one detector are useful suspicious events, but
        # they do not by themselves establish a multi-stage attack scenario.
        if len(unique_rules) < 2 or len(phases) < 2:
            continue
        candidate = {
            "scenario_id": f"SCN-{len(candidates) + 1:03d}",
            "title": _scenario_title(events, phases),
            "confidence": confidence,
            "event_refs": [event["event_ref"] for event in events],
            "stages": stages,
            "link_reasons": reasons,
            "hypothesis": _scenario_hypothesis(events, phases, confidence),
            "alternative_explanations": _scenario_alternatives(events),
            "evidence_gaps": _scenario_evidence_gaps(events),
        }
        candidates.append(candidate)
    return candidates


def _event_link_reasons(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    left_time = _parse_analysis_time(left.get("time"))
    right_time = _parse_analysis_time(right.get("time"))
    if left_time is None or right_time is None:
        return []
    delta_seconds = abs((right_time - left_time).total_seconds())
    if delta_seconds > SCENARIO_CORRELATION_WINDOW_SECONDS:
        return []

    same_host = bool(left.get("host") and left.get("host") == right.get("host"))
    cross_host_reason = (
        None if same_host else _explicit_cross_host_relation(left, right)
    )
    if not same_host and not cross_host_reason:
        # A reused account or process path on different machines is not enough.
        # Cross-host movement requires an explicit source/target hostname field.
        return []

    shared_entity_reasons = []
    minutes = max(1, int(delta_seconds // 60))
    left_account = str(left.get("account") or "")
    right_account = str(right.get("account") or "")
    if (
        _meaningful_account(left_account)
        and left_account.casefold() == right_account.casefold()
    ):
        shared_entity_reasons.append(f"동일 계정 {left['account']} 사용")
    if (
        _valid_ip_field(str(left.get("source_ip") or ""))
        and left.get("source_ip") == right.get("source_ip")
    ):
        shared_entity_reasons.append(f"동일 원본 IP {left['source_ip']} 관측")

    left_fields = left.get("fields") or {}
    right_fields = right.get("fields") or {}
    if same_host:
        left_logon_ids = {
            _normalized_logon_id(left_fields.get(key))
            for key in ("SubjectLogonId", "TargetLogonId")
            if _meaningful_logon_id(left_fields.get(key))
        }
        right_logon_ids = {
            _normalized_logon_id(right_fields.get(key))
            for key in ("SubjectLogonId", "TargetLogonId")
            if _meaningful_logon_id(right_fields.get(key))
        }
        shared_logon_ids = sorted(left_logon_ids & right_logon_ids)
        if shared_logon_ids:
            shared_entity_reasons.append(
                f"동일 Logon ID {', '.join(shared_logon_ids[:2])} 공유"
            )

        left_processes = {
            str(value).casefold()
            for value in (
                left.get("process"),
                left_fields.get("ParentProcessName"),
                left_fields.get("NewProcessName"),
            )
            if value
        }
        right_processes = {
            str(value).casefold()
            for value in (
                right.get("process"),
                right_fields.get("ParentProcessName"),
                right_fields.get("NewProcessName"),
            )
            if value
        }
        shared_processes = left_processes & right_processes
        if shared_processes:
            shared_entity_reasons.append("동일 또는 부모/자식 프로세스 경로 공유")
        left_process_guid = _normalized_process_guid(
            left.get("process_guid") or left_fields.get("ProcessGuid")
        )
        right_process_guid = _normalized_process_guid(
            right.get("process_guid") or right_fields.get("ProcessGuid")
        )
        if left_process_guid and left_process_guid == right_process_guid:
            shared_entity_reasons.append("동일 ProcessGuid 공유")

        left_destination = (
            left.get("destination_ip")
            or left.get("destination_hostname")
            or left.get("query_name")
        )
        right_destination = (
            right.get("destination_ip")
            or right.get("destination_hostname")
            or right.get("query_name")
        )
        if (
            left_destination
            and right_destination
            and str(left_destination).casefold() == str(right_destination).casefold()
        ):
            shared_entity_reasons.append(
                f"동일 네트워크 목적지 {left_destination} 공유"
            )

    transition_reason = _rule_transition_reason(
        left.get("rule_ids") or [],
        right.get("rule_ids") or [],
    )
    if (
        not shared_entity_reasons
        and not transition_reason
        and not cross_host_reason
    ):
        return []

    reasons = []
    if same_host:
        reasons.append(f"동일 호스트 {left['host']}에서 {minutes}분 이내 발생")
    elif cross_host_reason:
        reasons.append(cross_host_reason)
        reasons.append(f"서로 다른 호스트에서 {minutes}분 이내 발생")
    reasons.extend(shared_entity_reasons)
    if transition_reason:
        reasons.append(transition_reason)
    return reasons


def _explicit_cross_host_relation(
    left: dict[str, Any],
    right: dict[str, Any],
) -> str | None:
    left_host = str(left.get("host") or "")
    right_host = str(right.get("host") or "")
    left_fields = left.get("fields") or {}
    right_fields = right.get("fields") or {}
    if not isinstance(left_fields, dict) or not isinstance(right_fields, dict):
        return None

    for key in ("TargetServerName", "TargetInfo"):
        if _host_reference_matches(left_fields.get(key), right_host):
            return (
                f"{left_host} 이벤트의 {key}가 대상 호스트 "
                f"{right_host}를 명시함"
            )
        if _host_reference_matches(right_fields.get(key), left_host):
            return (
                f"{right_host} 이벤트의 {key}가 대상 호스트 "
                f"{left_host}를 명시함"
            )
    if _host_reference_matches(left_fields.get("WorkstationName"), right_host):
        return (
            f"{left_host} 이벤트의 WorkstationName이 원본 호스트 "
            f"{right_host}를 명시함"
        )
    if _host_reference_matches(right_fields.get("WorkstationName"), left_host):
        return (
            f"{right_host} 이벤트의 WorkstationName이 원본 호스트 "
            f"{left_host}를 명시함"
        )
    return None


def _host_reference_matches(value: Any, host: str) -> bool:
    if not value or not host:
        return False

    def normalized_candidates(raw: Any) -> set[str]:
        text = str(raw).strip().lstrip("\\").casefold()
        if not text or text in {"-", "localhost"}:
            return set()
        candidates = {text, text.split(".", 1)[0]}
        if "/" in text:
            suffix = text.rsplit("/", 1)[-1].lstrip("\\")
            candidates.update({suffix, suffix.split(".", 1)[0]})
        return {item for item in candidates if item}

    return bool(normalized_candidates(value) & normalized_candidates(host))


def _rule_transition_reason(left_rules: list[str], right_rules: list[str]) -> str | None:
    left = set(left_rules)
    right = set(right_rules)
    execution_rules = {
        "suspicious_powershell",
        "wmi_activity",
        "suspicious_network_connection",
        "possible_network_beacon",
        "suspicious_dns_network_activity",
    }
    defense_rules = {"log_cleared", "defender_detection_or_tamper"}
    persistence_rules = {
        "service_installed",
        "scheduled_task_changed",
        "account_created",
        "account_enabled_or_password_reset",
    }
    remote_rules = {"rdp_logon", "network_logon_volume", "explicit_credentials"}
    authentication_rules = {"failed_logon_burst", "auth_failure_burst"}
    privilege_rules = {"privileged_group_change", "privileged_logon"}

    left_execution = any(
        rule.startswith("suspicious_process_") or rule in execution_rules
        for rule in left
    )
    right_execution = any(
        rule.startswith("suspicious_process_") or rule in execution_rules
        for rule in right
    )
    left_defense = bool(left & defense_rules)
    right_defense = bool(right & defense_rules)
    left_persistence = bool(left & persistence_rules)
    right_persistence = bool(right & persistence_rules)
    left_remote = bool(left & remote_rules)
    right_remote = bool(right & remote_rules)
    left_authentication = bool(left & authentication_rules)
    right_authentication = bool(right & authentication_rules)
    left_privilege = bool(left & privilege_rules)
    right_privilege = bool(right & privilege_rules)

    if left_execution and right_defense:
        return "의심 실행 후 로그 삭제 또는 Defender 탐지·설정 변경 징후가 이어짐"
    if left_defense and right_execution:
        return "로그 삭제 또는 Defender 탐지·설정 변경 후 의심 실행 징후가 이어짐"
    if left_execution and right_persistence:
        return "의심 실행 후 지속성 변경 징후가 이어짐"
    if left_persistence and right_execution:
        return "지속성 변경 후 의심 실행 징후가 이어짐"
    if left_remote and (right_execution or right_persistence):
        return "원격 접근 또는 명시적 자격 증명 사용 후 실행·지속성 징후가 이어짐"
    if (left_execution or left_persistence) and right_remote:
        return "실행·지속성 징후 후 원격 접근 또는 명시적 자격 증명 사용이 이어짐"
    if left_authentication and right_remote:
        return "인증 실패 반복 후 원격 로그인 징후가 이어짐"
    if left_remote and right_authentication:
        return "원격 로그인 징후 후 인증 실패 반복이 이어짐"
    if "account_created" in left and right_privilege:
        return "계정 생성 후 권한 부여·고권한 사용 징후가 이어짐"
    if left_privilege and "account_created" in right:
        return "권한 부여·고권한 사용 후 계정 생성 징후가 이어짐"
    return None


def _parse_analysis_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _meaningful_account(value: Any) -> bool:
    if not value:
        return False
    account = str(value).rsplit("\\", 1)[-1].strip().lower()
    return account not in {
        "system",
        "localsystem",
        "local system",
        "localservice",
        "local service",
        "networkservice",
        "network service",
        "anonymous logon",
        "-",
    }


def _normalized_logon_id(value: Any) -> str:
    return str(value or "").strip().lower()


def _meaningful_logon_id(value: Any) -> bool:
    logon_id = _normalized_logon_id(value)
    return bool(logon_id) and logon_id not in {
        "-",
        "0",
        "0x0",
        "0x3e4",
        "0x3e5",
        "0x3e6",
        "0x3e7",
    }


def _scenario_phase(rule_ids: list[str]) -> str:
    phase_by_rule = {
        "log_cleared": "방어 회피",
        "defender_detection_or_tamper": "악성 활동/방어 회피 확인",
        "service_installed": "지속성 또는 실행",
        "scheduled_task_changed": "지속성",
        "account_created": "지속성",
        "account_enabled_or_password_reset": "계정 접근 유지",
        "privileged_group_change": "권한 상승",
        "failed_logon_burst": "자격 증명 공격 후보",
        "auth_failure_burst": "자격 증명 공격 후보",
        "rdp_logon": "원격 접근 또는 측면 이동",
        "network_logon_volume": "원격 접근 또는 측면 이동",
        "explicit_credentials": "자격 증명 사용 또는 측면 이동",
        "privileged_logon": "고권한 세션 활동",
        "wmi_activity": "실행·측면 이동·지속성 후보",
        "suspicious_powershell": "실행",
        "suspicious_network_connection": "명령제어 또는 비정상 통신 후보",
        "possible_network_beacon": "명령제어 반복 통신 후보",
        "suspicious_dns_network_activity": "의심 DNS/네트워크 통신 후보",
    }
    for rule_id in rule_ids:
        if rule_id in phase_by_rule:
            return phase_by_rule[rule_id]
        if rule_id.startswith("suspicious_process_"):
            category = rule_id.removeprefix("suspicious_process_")
            return {
                "credential_access": "자격 증명 접근",
                "defense_evasion": "방어 회피",
                "persistence": "지속성",
                "discovery": "환경 탐색",
                "download_or_remote_payload": "페이로드 획득 또는 실행 후보",
            }.get(category, "의심 명령 실행")
    return "의심 활동"


def _scenario_stage_description(event: dict[str, Any]) -> str:
    reason_titles = [str(reason.get("title")) for reason in event.get("reasons") or [] if reason.get("title")]
    title = ", ".join(reason_titles[:2]) or "규칙 기반 의심 이벤트"
    details = [f"Event ID {event.get('event_id') or 'unknown'}", f"host={event.get('host') or '-'}"]
    if event.get("account"):
        details.append(f"account={event['account']}")
    if event.get("source_ip"):
        details.append(f"src={event['source_ip']}")
    destination = event.get("destination_ip") or event.get("destination_hostname")
    if destination:
        if event.get("destination_port"):
            destination = f"{destination}:{event['destination_port']}"
        details.append(f"dst={destination}")
    if event.get("query_name"):
        details.append(f"dns={event['query_name']}")
    return f"{title}: {', '.join(details)}"


def _scenario_confidence(events: list[dict[str, Any]], link_reasons: list[str]) -> str:
    unique_rules = {rule for event in events for rule in event.get("rule_ids") or []}
    direct_reasons = [
        reason
        for reason in link_reasons
        if "Logon ID" in reason or "프로세스" in reason
    ]
    has_account = any("동일 계정" in reason for reason in link_reasons)
    has_source_ip = any("동일 원본 IP" in reason for reason in link_reasons)
    if len(events) >= 3 and len(unique_rules) >= 3 and (direct_reasons or (has_account and has_source_ip)):
        return "high"
    if len(events) >= 2 and len(unique_rules) >= 2 and link_reasons:
        return "medium"
    return "low"


def _scenario_title(events: list[dict[str, Any]], phases: list[str]) -> str:
    hosts = sorted({str(event["host"]) for event in events if event.get("host")})
    target = ", ".join(hosts[:2]) if hosts else "호스트 미상"
    if len(phases) == 1:
        return f"{target}의 {phases[0]} 활동 가설"
    return f"{target}의 {' → '.join(phases[:4])} 연계 가설"


def _scenario_hypothesis(events: list[dict[str, Any]], phases: list[str], confidence: str) -> str:
    refs = ", ".join(str(event["event_ref"]) for event in events)
    flow = " → ".join(phases) if phases else "의심 활동"
    return (
        f"{refs}의 인접 이벤트가 60분 이내의 공통 엔티티 또는 명시적 행위 전이를 통해 연결되어 "
        f"{flow} 흐름일 가능성이 있습니다. "
        f"현재 신뢰도는 {confidence}이며, 이는 관측 이벤트에 근거한 가설이지 침해 확정 판정이 아닙니다."
    )


def _scenario_alternatives(events: list[dict[str, Any]]) -> list[str]:
    hosts = {
        str(event.get("host"))
        for event in events
        if event.get("host")
    }
    alternatives = [
        "승인된 관리자 작업, 소프트웨어 배포 또는 장애 대응 활동일 수 있습니다.",
    ]
    if len(hosts) > 1:
        alternatives.append(
            "명시적 원본/대상 호스트 필드는 연결되지만, 승인된 원격 관리·배포 활동이 "
            "서로 다른 호스트에서 관측된 것일 수 있습니다."
        )
    else:
        alternatives.append(
            "공통 호스트에서 시간상 인접했지만 서로 무관한 정상 이벤트가 우연히 함께 "
            "관측됐을 수 있습니다."
        )
    if any("failed_logon_burst" in (event.get("rule_ids") or []) for event in events):
        alternatives.append("저장된 자격증명 오류 또는 서비스 계정 암호 불일치로 인증 실패가 반복됐을 수 있습니다.")
    return alternatives


def _scenario_evidence_gaps(events: list[dict[str, Any]]) -> list[str]:
    gaps = []
    if any(not event.get("source_ip") for event in events):
        gaps.append("일부 단계의 원본 IP 또는 네트워크 목적지가 확인되지 않았습니다.")
    if any(not event.get("process") and not event.get("command_line") for event in events):
        gaps.append("일부 단계의 프로세스, 부모 프로세스 또는 전체 명령줄이 확인되지 않았습니다.")
    if any(not event.get("time") for event in events):
        gaps.append("시각이 없는 이벤트는 다른 단계와 시간 상관분석하지 못했습니다.")
    gaps.extend(
        [
            "EDR의 프로세스 계보, 파일 해시·서명 및 파일 생성 기록을 추가 확인해야 합니다.",
            "방화벽·프록시·DNS·VPN 로그로 외부 통신과 원격 접근 여부를 교차 검증해야 합니다.",
        ]
    )
    return gaps


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    events: list[EventRecord],
    description: str,
    confidence: str,
    steps: list[str],
    evidence_limit: int = FINDING_EVIDENCE_LIMIT,
) -> dict[str, Any]:
    ordered = sorted(
        events,
        key=lambda event: (
            event.time_created is None,
            isoformat_utc(event.time_created) or "",
            event.source_file,
            _record_sort_key(event.record_id),
        ),
    )
    timed_events = [event for event in ordered if event.time_created is not None]
    first_seen = timed_events[0].time_created if timed_events else None
    last_seen = timed_events[-1].time_created if timed_events else None
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "event_count": len(events),
        "evidence_limit": evidence_limit,
        "first_seen": isoformat_utc(first_seen),
        "last_seen": isoformat_utc(last_seen),
        "description": description,
        "entities": _entities(ordered),
        "evidence": [
            _evidence(event)
            for event in _representative_events(ordered, evidence_limit)
        ],
        "analysis_guidance": _analysis_guidance(rule_id),
        "recommended_next_steps": steps,
    }


def _representative_events(
    events: list[EventRecord],
    limit: int = FINDING_EVIDENCE_LIMIT,
) -> list[EventRecord]:
    """Keep time-balanced evidence, including both ends of a large match set."""
    if limit <= 0:
        return []
    if len(events) <= limit:
        return list(events)
    if limit == 1:
        return [events[0]]
    indexes = {
        round(position * (len(events) - 1) / (limit - 1))
        for position in range(limit)
    }
    return [events[index] for index in sorted(indexes)]


def _largest_event_window(
    events: list[EventRecord],
    window_seconds: int,
) -> list[EventRecord]:
    """Return the largest chronological event set contained in one time window."""
    if window_seconds < 0:
        return []

    timed_events = []
    for event in events:
        if event.time_created is None:
            continue
        event_time = event.time_created
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        else:
            event_time = event_time.astimezone(timezone.utc)
        timed_events.append((event_time, event))

    timed_events.sort(
        key=lambda item: (
            item[0],
            item[1].source_file,
            _record_sort_key(item[1].record_id),
        )
    )
    best_start = 0
    best_end = 0
    window_start = 0
    for window_end, (end_time, _) in enumerate(timed_events):
        while (
            window_start <= window_end
            and (end_time - timed_events[window_start][0]).total_seconds()
            > window_seconds
        ):
            window_start += 1
        if window_end - window_start > best_end - best_start:
            best_start = window_start
            best_end = window_end

    if not timed_events:
        return []
    return [event for _, event in timed_events[best_start : best_end + 1]]


def _event_time_sort_key(value: datetime | None) -> tuple[bool, str]:
    return (value is None, isoformat_utc(value) or "")


def _entities(events: Iterable[EventRecord]) -> dict[str, list[str]]:
    accounts = Counter()
    hosts = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    destination_domains = Counter()
    destination_ports = Counter()
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
        if _valid_ip_field(_destination_ip(event)):
            destination_ips[_destination_ip(event)] += 1
        if destination_domain := _normalized_domain(
            _field(event, "DestinationHostname", "QueryName")
        ):
            destination_domains[destination_domain] += 1
        if destination_port := _normalized_port(_destination_port(event)):
            destination_ports[str(destination_port)] += 1
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
        "destination_ips": [item for item, _ in destination_ips.most_common(10)],
        "destination_domains": [item for item, _ in destination_domains.most_common(10)],
        "destination_ports": [item for item, _ in destination_ports.most_common(10)],
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
            "SourceIp",
            "SourceHostname",
            "SourcePort",
            "SourcePortName",
            "DestinationIp",
            "DestinationHostname",
            "DestinationPort",
            "DestinationPortName",
            "SourceAddress",
            "DestAddress",
            "DestPort",
            "Protocol",
            "Initiated",
            "Direction",
            "QueryName",
            "QueryStatus",
            "QueryResults",
            "ProcessGuid",
            "User",
            "WorkstationName",
            "LogonType",
            "Status",
            "SubStatus",
            "ProcessName",
            "ProcessId",
            "ProcessID",
            "ClientProcessId",
            "Image",
            "OriginalFileName",
            "Hashes",
            "IntegrityLevel",
            "NewProcessName",
            "NewProcessId",
            "Application",
            "CommandLine",
            "ParentImage",
            "ParentProcessGuid",
            "ParentCommandLine",
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
        "source_port": _normalized_port(_source_port(event)),
        "destination_ip": _destination_ip(event),
        "destination_port": _normalized_port(_destination_port(event)),
        "destination_hostname": _field(event, "DestinationHostname"),
        "protocol": _normalized_protocol(_field(event, "Protocol")),
        "initiated": _normalized_boolean(_field(event, "Initiated")),
        "process": _process(event),
        "process_id": _normalized_process_id(
            _field(event, "ProcessId", "ProcessID", "NewProcessId")
        ),
        "process_guid": _normalized_process_guid(_field(event, "ProcessGuid")),
        "query_name": _field(event, "QueryName"),
        "network_direction": _network_direction(
            event,
            _normalized_boolean(_field(event, "Initiated")),
        ),
        "command_line": _truncate(_command_line(event), 600),
        "fields": {key: _truncate(value, 600) for key, value in selected_fields.items()},
    }


def _event_id(event: EventRecord) -> str:
    return str(event.event_id or "")


def _provider(event: EventRecord) -> str:
    return (event.provider or "").strip().casefold()


def _channel(event: EventRecord) -> str:
    return (event.channel or "").strip().casefold()


def _is_security_event(event: EventRecord) -> bool:
    return (
        _provider(event) == "microsoft-windows-security-auditing"
        and _channel(event) == "security"
    )


def _is_service_install_event(event: EventRecord) -> bool:
    if _event_id(event) == "4697":
        return _is_security_event(event)
    if _event_id(event) != "7045":
        return False
    return (
        _provider(event) == "service control manager"
        and _channel(event) == "system"
    )


def _is_scheduled_task_event(event: EventRecord) -> bool:
    if _event_id(event) in {"4698", "4702"}:
        return _is_security_event(event)
    if _event_id(event) not in {"106", "140", "141"}:
        return False
    return (
        _provider(event) == "microsoft-windows-taskscheduler"
        and _channel(event) == "microsoft-windows-taskscheduler/operational"
    )


def _is_process_creation_event(event: EventRecord) -> bool:
    if _event_id(event) == "4688":
        return _is_security_event(event)
    if _event_id(event) != "1":
        return False
    return (
        _provider(event) == "microsoft-windows-sysmon"
        and _channel(event) == "microsoft-windows-sysmon/operational"
    )


def _is_network_connection_event(event: EventRecord) -> bool:
    if _event_id(event) == "3":
        return (
            _provider(event) == "microsoft-windows-sysmon"
            and _channel(event) == "microsoft-windows-sysmon/operational"
        )
    return _event_id(event) == "5156" and _is_security_event(event)


def _is_dns_query_event(event: EventRecord) -> bool:
    return (
        _event_id(event) == "22"
        and _provider(event) == "microsoft-windows-sysmon"
        and _channel(event) == "microsoft-windows-sysmon/operational"
    )


def _is_powershell_event(event: EventRecord) -> bool:
    if _event_id(event) not in {"4103", "4104"}:
        return False
    return (
        _provider(event) == "microsoft-windows-powershell"
        and _channel(event) == "microsoft-windows-powershell/operational"
    )


def _is_event_log_clear_event(event: EventRecord) -> bool:
    event_id = _event_id(event)
    provider = _provider(event)
    channel = _channel(event)
    text = _event_text(event).lower()
    if (
        ("wevtutil cl" in text or "clear-eventlog" in text)
        and _is_process_creation_event(event)
    ):
        return True
    if event_id == "1102" and _is_security_event(event):
        return True
    return (
        event_id == "104"
        and provider == "microsoft-windows-eventlog"
        and channel == "system"
    )


def _is_defender_security_event(event: EventRecord) -> bool:
    if _event_id(event) not in {"1116", "1117", "1118", "1119", "5007", "5013", "5015"}:
        return False
    provider = _provider(event)
    channel = _channel(event)
    return (
        provider == "microsoft-windows-windows defender"
        and channel == "microsoft-windows-windows defender/operational"
    )


def _is_wmi_activity_event(event: EventRecord) -> bool:
    text = _event_text(event).lower()
    if "wmic process call create" in text and _is_process_creation_event(event):
        return True
    if _event_id(event) not in {"5857", "5858", "5859", "5860", "5861"}:
        return False
    provider = _provider(event)
    channel = _channel(event)
    return (
        provider == "microsoft-windows-wmi-activity"
        and channel == "microsoft-windows-wmi-activity/operational"
    )


def _analysis_guidance(rule_id: str) -> dict[str, Any]:
    if rule_id in {
        "suspicious_network_connection",
        "possible_network_beacon",
        "suspicious_dns_network_activity",
    }:
        return {
            "cause_focus": "ProcessGuid를 우선으로 Sysmon 1/3/22를 연결하고 Image, CommandLine, DestinationIp/Port/Hostname, QueryName을 원인 후보로 추적합니다.",
            "observed_behavior": "외부·비로컬 목적지, 고위험 포트, 사용자 쓰기 가능 경로, 터널링 도구, DNS 연결 또는 반복 주기성 중 하나 이상의 구체적 통신 신호가 관찰되었습니다.",
            "not_proven": "목적지 평판, 전송 내용과 바이트 수가 없으므로 C2, 데이터 유출 또는 악성 여부는 확정되지 않습니다. 승인된 원격 관리·개발·업데이트 통신일 수 있습니다.",
            "correlation_targets": ["Sysmon 1/3/22 ProcessGuid", "Security 5156", "프록시/방화벽/DNS", "파일 해시·서명 및 프로세스 계보"],
        }
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
    return _field(
        event,
        "IpAddress",
        "SourceIp",
        "SourceNetworkAddress",
        "ClientAddress",
        "SourceAddress",
    )


def _source_port(event: EventRecord) -> str | None:
    return _field(event, "IpPort", "SourcePort")


def _destination_ip(event: EventRecord) -> str | None:
    return _field(event, "DestinationIp", "DestAddress")


def _destination_port(event: EventRecord) -> str | None:
    return _field(event, "DestinationPort", "DestPort")


def _process(event: EventRecord) -> str | None:
    return _field(event, "NewProcessName", "ProcessName", "Image", "Application")


def _command_line(event: EventRecord) -> str | None:
    return _field(event, "CommandLine", "ProcessCommandLine", "ScriptBlockText")


def _normalized_host(value: Any) -> str:
    return str(value or "").strip().casefold()


def _normalized_process_guid(value: Any) -> str | None:
    text = str(value or "").strip().casefold()
    if not text or text == "-":
        return None
    compact = text.strip("{}").replace("-", "")
    if compact and set(compact) == {"0"}:
        return None
    return text


def _normalized_process_id(value: Any) -> str | None:
    text = str(value or "").strip().casefold()
    if not text or text == "-":
        return None
    try:
        number = int(text, 0)
    except ValueError:
        try:
            number = int(text, 10)
        except ValueError:
            return text
    if number < 0:
        return None
    return str(number)


def _normalized_port(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text or text == "-":
        return None
    try:
        port = int(text, 10)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _normalized_boolean(value: Any) -> bool | None:
    text = str(value or "").strip().casefold()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _normalized_protocol(value: Any) -> str | None:
    text = str(value or "").strip().casefold()
    return {
        "1": "icmp",
        "6": "tcp",
        "17": "udp",
        "58": "icmpv6",
    }.get(text, text or None)


def _network_direction(event: EventRecord, initiated: bool | None) -> str | None:
    if initiated is not None:
        return "outbound" if initiated else "inbound"
    value = str(_field(event, "Direction") or "").strip().casefold()
    if value in {"%%14593", "outbound", "out", "egress"}:
        return "outbound"
    if value in {"%%14592", "inbound", "in", "ingress"}:
        return "inbound"
    return value or None


def _normalized_domain(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def _domains_equivalent(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _is_external_destination(
    destination_ip: Any,
    destination_hostname: Any,
) -> bool:
    if destination_ip:
        try:
            address = ipaddress.ip_address(str(destination_ip).strip())
        except ValueError:
            pass
        else:
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                return False
            if isinstance(address, ipaddress.IPv4Address):
                internal_v4 = (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("100.64.0.0/10"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                )
                return not any(address in network for network in internal_v4)
            return not address.is_private
    hostname = _normalized_domain(destination_hostname)
    if not hostname or hostname in {"localhost", "-"}:
        return False
    return not hostname.endswith((".local", ".lan", ".internal"))


def _is_loopback_ip(value: Any) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(str(value).strip()).is_loopback
    except ValueError:
        return False


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _signed_event_time_delta_seconds(
    target: EventRecord,
    candidate: EventRecord,
) -> float | None:
    if target.time_created is None or candidate.time_created is None:
        return None
    return (_as_utc(target.time_created) - _as_utc(candidate.time_created)).total_seconds()


def _event_time_delta_seconds(
    left: EventRecord,
    right: EventRecord,
) -> float | None:
    delta = _signed_event_time_delta_seconds(left, right)
    return abs(delta) if delta is not None else None


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
