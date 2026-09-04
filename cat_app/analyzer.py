from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import math
from pathlib import PureWindowsPath
import re
import statistics
from typing import Any, Callable, Iterable, Iterator

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
NETWORK_GROUP_TIMING_SAMPLE_LIMIT = 4096
NETWORK_GROUP_EDGE_EVIDENCE_LIMIT = NETWORK_FINDING_EVIDENCE_LIMIT // 2
NETWORK_GROUP_STATE_LIMIT = 100_000
NETWORK_CORRELATION_INDEX_EVENT_LIMIT = 250_000
NETWORK_DNS_MATCH_INDEX_ENTRY_LIMIT = 250_000
NETWORK_DESTINATION_SET_LIMIT = 100_000
NETWORK_GROUP_DESTINATION_IP_LIMIT = 64
NETWORK_FANOUT_WINDOW_SECONDS = 10 * 60
NETWORK_FANOUT_DESTINATION_THRESHOLD = 12
NETWORK_FANOUT_PORT_THRESHOLD = 8
NETWORK_FANOUT_STANDALONE_DESTINATION_THRESHOLD = 20
NETWORK_FANOUT_PROCESS_LIMIT = 20_000
NETWORK_FANOUT_EVENT_LIMIT_PER_PROCESS = 2048
NETWORK_FANOUT_ACTIVITY_LIMIT = 24
INTRUSION_PROCESS_NODE_LIMIT = 50_000
INTRUSION_PRIORITY_PROCESS_NODE_LIMIT = 512
INTRUSION_CHAIN_PROCESS_LIMIT = 128
INTRUSION_CHAIN_STEP_LIMIT = 96
INTRUSION_FOLLOWON_GROUP_LIMIT = 128
INTRUSION_SUSPICIOUS_EVENT_LIMIT = 512
INTRUSION_ORIGIN_ALTERNATIVE_LIMIT = 5
INTRUSION_DESCENDANT_DEPTH_LIMIT = 8
INTRUSION_PID_LINK_WINDOW_SECONDS = 60 * 60

C2_SCORE_VERSION = 1
C2_SCORE_WEIGHTS = {
    "high_risk_port": 20,
    "user_writable_process": 15,
    "suspicious_command": 20,
    "suspicious_parent_or_lolbin": 15,
    "known_tunnel_client": 35,
    "sensitive_loopback_tunnel": 35,
    "high_entropy_dns": 20,
    "periodic_beacon": 30,
    "process_fanout": 20,
    "unusual_network_process": 5,
    "nonstandard_port": 5,
}

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
SCRIPT_OR_LOLBIN_NETWORK_CLIENTS = {
    "bitsadmin.exe",
    "certutil.exe",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
}
SUSPICIOUS_NETWORK_PARENT_PROCESSES = {
    "cscript.exe",
    "excel.exe",
    "mshta.exe",
    "outlook.exe",
    "powerpnt.exe",
    "powershell.exe",
    "pwsh.exe",
    "winword.exe",
    "wscript.exe",
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
    network_findings, network_activity = _network_analysis(
        parse_result.iter_network_records,
    )
    network_records_analyzed = int(
        parse_result.network_records_spooled
        if parse_result.has_network_record_spool
        else network_activity.get("source_network_record_count") or 0
    )
    network_activity["source_network_record_count"] = network_records_analyzed
    network_activity["input_network_record_count"] = parse_result.network_records_seen
    network_activity["network_spool_limit_reached"] = (
        parse_result.network_spool_limit_reached
    )
    network_activity["network_spool_bytes"] = parse_result.network_spool_bytes
    network_activity["full_input_scan"] = parse_result.network_scan_complete
    network_activity["general_record_limit_reached"] = parse_result.record_limit_reached

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
    intrusion_chain = _intrusion_chain(
        lambda: _iter_intrusion_source_records(parse_result, records),
        suspicious_events,
        retained_record_count=len(records),
        network_scan_complete=parse_result.network_scan_complete,
        network_spool_limit_reached=parse_result.network_spool_limit_reached,
        spool_scan_used=parse_result.has_network_record_spool,
    )

    return {
        "analysis_schema_version": 2,
        "scope": {
            "start_utc": isoformat_utc(start_utc),
            "end_utc": isoformat_utc(end_utc),
            "records_loaded": len(records),
            "records_in_range": parse_result.total_in_range,
            "records_seen": parse_result.total_seen,
            "truncated": parse_result.truncated,
            "record_limit_reached": parse_result.record_limit_reached,
            "retention_limit_reached": parse_result.retention_limit_reached,
            "network_records_seen": parse_result.network_records_seen,
            "network_records_scanned": network_records_analyzed,
            "network_spool_limit_reached": parse_result.network_spool_limit_reached,
            "network_spool_bytes": parse_result.network_spool_bytes,
            "network_scan_complete": parse_result.network_scan_complete,
        },
        "parser": parse_result.to_dict(),
        "summary": _summary(records),
        "network_activity": network_activity,
        "findings": findings,
        "suspicious_events": suspicious_events,
        "intrusion_chain": intrusion_chain,
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


@dataclass
class _NetworkGroupState:
    """Bounded samples plus exact counters for one normalized connection group."""

    connection_count: int = 0
    external_connection_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    observation_head: list[dict[str, Any]] = field(default_factory=list)
    observation_tail: deque[dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=NETWORK_GROUP_EDGE_EVIDENCE_LIMIT)
    )
    timing_head: list[datetime] = field(default_factory=list)
    timing_tail: deque[datetime] = field(
        default_factory=lambda: deque(maxlen=NETWORK_GROUP_TIMING_SAMPLE_LIMIT // 2)
    )
    destination_ips: list[str] = field(default_factory=list)
    _destination_ip_seen: set[str] = field(default_factory=set)
    destination_ip_limit_reached: bool = False

    def add(self, observation: dict[str, Any]) -> None:
        self.connection_count += 1
        if observation.get("external_destination"):
            self.external_connection_count += 1

        value = observation.get("time")
        if isinstance(value, datetime):
            utc_value = _as_utc(value)
            if self.first_seen is None or utc_value < _as_utc(self.first_seen):
                self.first_seen = value
            if self.last_seen is None or utc_value > _as_utc(self.last_seen):
                self.last_seen = value
            if len(self.timing_head) < NETWORK_GROUP_TIMING_SAMPLE_LIMIT // 2:
                self.timing_head.append(value)
            else:
                self.timing_tail.append(value)

        if len(self.observation_head) < NETWORK_GROUP_EDGE_EVIDENCE_LIMIT:
            self.observation_head.append(observation)
        else:
            self.observation_tail.append(observation)

        destination_ip = _normalized_ip(observation.get("destination_ip"))
        if destination_ip and destination_ip not in self._destination_ip_seen:
            if len(self.destination_ips) < NETWORK_GROUP_DESTINATION_IP_LIMIT:
                self._destination_ip_seen.add(destination_ip)
                self.destination_ips.append(destination_ip)
            else:
                self.destination_ip_limit_reached = True

    def observations(self) -> list[dict[str, Any]]:
        return [*self.observation_head, *self.observation_tail]

    def timing_sample(self) -> list[datetime]:
        return [*self.timing_head, *self.timing_tail]


def _network_analysis(
    record_source: Callable[[], Iterator[EventRecord]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Correlate process, DNS, and connection evidence without threat intel.

    A public destination alone is deliberately not treated as malicious.  A
    finding requires a stronger, locally verifiable signal such as a known
    high-risk port, execution from a user-writable path, a suspicious command,
    or sufficiently regular/repeated communication.  All connections are still
    summarized in ``network_activity`` so an investigator can inspect activity
    that did not cross the anomaly threshold.
    """
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
    dns_matches_by_guid: dict[
        tuple[str, str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    dns_matches_by_pid: dict[
        tuple[str, str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    terminations_by_guid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    terminations_by_pid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ] = defaultdict(list)
    dns_counter: Counter[str] = Counter()
    dns_event_count = 0
    source_network_record_count = 0
    correlation_index_event_count = 0
    correlation_index_limit_reached = False
    dns_match_index_entry_count = 0
    dns_match_index_limit_reached = False

    # First pass builds only the process-lifetime and DNS indexes required by
    # network correlation. The source is a rewindable disk-backed spool for
    # parsed uploads, so general record retention does not hide tail activity.
    for sequence, event in enumerate(record_source()):
        is_process = _is_process_creation_event(event)
        is_termination = _is_process_termination_event(event)
        is_dns = _is_dns_query_event(event)
        if (
            is_process
            or is_termination
            or is_dns
            or _is_network_connection_event(event)
        ):
            source_network_record_count += 1
        if not (is_process or is_termination or is_dns):
            continue
        if is_dns:
            dns_event_count += 1
            if query := _normalized_domain(_field(event, "QueryName")):
                dns_counter[query] += 1
        if correlation_index_event_count >= NETWORK_CORRELATION_INDEX_EVENT_LIMIT:
            correlation_index_limit_reached = True
            continue
        correlation_index_event_count += 1
        host = _normalized_host(event.computer)
        if is_process:
            if guid := _normalized_process_guid(_field(event, "ProcessGuid")):
                _append_timed_event(processes_by_guid, (host, guid), event, sequence)
            if pid := _process_id(event):
                _append_timed_event(processes_by_pid, (host, pid), event, sequence)
        elif is_termination:
            if guid := _normalized_process_guid(_field(event, "ProcessGuid")):
                _append_timed_event(
                    terminations_by_guid,
                    (host, guid),
                    event,
                    sequence,
                )
            if pid := _normalized_process_id(
                _field(event, "ProcessId", "ProcessID")
            ):
                _append_timed_event(
                    terminations_by_pid,
                    (host, pid),
                    event,
                    sequence,
                )
        else:
            guid = _normalized_process_guid(_field(event, "ProcessGuid"))
            pid = _normalized_process_id(_field(event, "ProcessId"))
            if guid:
                _append_timed_event(dns_by_guid, (host, guid), event, sequence)
            if pid:
                _append_timed_event(dns_by_pid, (host, pid), event, sequence)
            if event.time_created is not None:
                for match_token in _dns_match_tokens(event):
                    for index, identity in (
                        (dns_matches_by_guid, guid),
                        (dns_matches_by_pid, pid),
                    ):
                        if not identity:
                            continue
                        if (
                            dns_match_index_entry_count
                            >= NETWORK_DNS_MATCH_INDEX_ENTRY_LIMIT
                        ):
                            dns_match_index_limit_reached = True
                            continue
                        _append_timed_event(
                            index,
                            (host, identity, match_token),
                            event,
                            sequence,
                        )
                        dns_match_index_entry_count += 1
    _sort_timed_event_index(processes_by_guid)
    _sort_timed_event_index(processes_by_pid)
    _sort_timed_event_index(terminations_by_guid)
    _sort_timed_event_index(terminations_by_pid)
    _sort_timed_event_index(dns_by_guid)
    _sort_timed_event_index(dns_by_pid)
    _sort_timed_event_index(dns_matches_by_guid)
    _sort_timed_event_index(dns_matches_by_pid)

    groups: dict[tuple[str, ...], _NetworkGroupState] = {}
    fanout_windows: dict[tuple[str, str], dict[str, Any]] = {}
    fanout_candidates: dict[tuple[str, str], dict[str, Any]] = {}
    unique_external_destinations: set[str] = set()
    unique_destination_limit_reached = False
    connection_event_count = 0
    normalized_connection_count = 0
    external_connections = 0
    omitted_group_connections = 0
    group_state_limit_reached = False
    fanout_state_limit_reached = False
    dns_correlation_candidate_limit_reached = False

    for event in record_source():
        if not _is_network_connection_event(event):
            continue
        connection_event_count += 1
        observation = _network_observation(event)
        if observation is None:
            continue
        normalized_connection_count += 1
        process_event, process_link, process_instance_id, process_end = (
            _correlated_process_event(
                event,
                processes_by_guid,
                processes_by_pid,
                terminations_by_guid,
                terminations_by_pid,
            )
        )
        correlated_dns, dns_link, dns_candidates_truncated = _correlated_dns_events(
            event,
            dns_by_guid,
            dns_by_pid,
            dns_matches_by_guid,
            dns_matches_by_pid,
            process_start=process_event,
            process_end=process_end,
        )
        dns_correlation_candidate_limit_reached = bool(
            dns_correlation_candidate_limit_reached or dns_candidates_truncated
        )
        observation["process_event"] = process_event
        observation["process_end_event"] = process_end
        observation["process_instance_id"] = process_instance_id
        if process_event is not None:
            observation["process"] = observation.get("process") or _process(process_event)
            observation["process_guid"] = observation.get(
                "process_guid"
            ) or _normalized_process_guid(_field(process_event, "ProcessGuid"))
            observation["process_id"] = observation.get("process_id") or _process_id(
                process_event
            )
        if process_end is not None:
            observation["process_end_time"] = process_end.time_created
        observation["dns_events"] = correlated_dns
        if not observation.get("destination_hostname"):
            observation["destination_hostname"] = _dns_hostname_for_destination(
                observation.get("destination_ip"),
                correlated_dns,
            )
        observation["correlation_reasons"] = [
            reason for reason in (process_link, dns_link) if reason
        ]
        if observation["external_destination"]:
            external_connections += 1
            destination_identity = str(
                observation.get("destination_hostname")
                or observation.get("destination_ip")
                or ""
            ).casefold()
            if destination_identity:
                if len(unique_external_destinations) < NETWORK_DESTINATION_SET_LIMIT:
                    unique_external_destinations.add(destination_identity)
                elif destination_identity not in unique_external_destinations:
                    unique_destination_limit_reached = True

        fanout_key = _fanout_process_key(observation)
        if fanout_key is not None and _fanout_eligible(observation):
            if (
                fanout_key in fanout_windows
                or len(fanout_windows) < NETWORK_FANOUT_PROCESS_LIMIT
            ):
                _update_fanout_window(
                    fanout_windows,
                    fanout_candidates,
                    fanout_key,
                    observation,
                )
            else:
                fanout_state_limit_reached = True

        key = _network_group_key(observation)
        state = groups.get(key)
        if state is None:
            if len(groups) >= NETWORK_GROUP_STATE_LIMIT:
                group_state_limit_reached = True
                omitted_group_connections += 1
                continue
            state = _NetworkGroupState()
            groups[key] = state
        state.add(observation)

    group_summaries: list[dict[str, Any]] = []
    finding_candidates: list[
        tuple[int, str, dict[str, Any], list[EventRecord]]
    ] = []
    fanout_instances = set(fanout_candidates)
    timing_sample_truncated = False
    observation_sample_truncated = False
    destination_ip_sample_truncated = False
    for state in groups.values():
        sampled_observations = state.observations()
        group_observations_sampled = state.connection_count > len(
            sampled_observations
        )
        if group_observations_sampled:
            observation_sample_truncated = True
        sessions = _network_sessions(sampled_observations)
        if group_observations_sampled and not any(
            item.get("process_guid") or item.get("process_instance_id")
            for item in sampled_observations
        ):
            # Missing middle observations can manufacture a >1 hour gap
            # between bounded head/tail samples. Keep the exact count in one
            # explicitly sampled group instead of silently dropping it.
            sessions = [
                sorted(
                    sampled_observations,
                    key=lambda item: _event_time_sort_key(item.get("time")),
                )
            ]
        if state.connection_count > len(state.timing_sample()):
            timing_sample_truncated = True
        if state.destination_ip_limit_reached:
            destination_ip_sample_truncated = True
        for session in sessions:
            whole_state = len(sessions) == 1
            sample_first = session[0]
            process_key = _fanout_process_key(sample_first)
            summary, related_events = _summarize_network_group(
                session,
                connection_count=(state.connection_count if whole_state else len(session)),
                timed=(
                    state.timing_sample()
                    if whole_state
                    else [
                        item["time"]
                        for item in session
                        if isinstance(item.get("time"), datetime)
                    ]
                ),
                first_seen=state.first_seen if whole_state else None,
                last_seen=state.last_seen if whole_state else None,
                destination_ips=state.destination_ips if whole_state else None,
                destination_ip_limit_reached=(
                    state.destination_ip_limit_reached if whole_state else False
                ),
                external_destination=(
                    state.external_connection_count > 0 if whole_state else None
                ),
                process_fanout=process_key in fanout_instances,
            )
            group_summaries.append(summary)
            if not summary["suspicious"]:
                continue
            score = int(summary.get("_score") or 0)
            finding_candidates.append(
                (score, "connection", summary, related_events)
            )

    fanout_summaries: list[dict[str, Any]] = []
    for candidate in fanout_candidates.values():
        summary, related_events = _summarize_fanout_candidate(candidate)
        fanout_summaries.append(summary)
        finding_candidates.append(
            (int(summary.get("_score") or 0), "fanout", summary, related_events)
        )
    for summary in group_summaries:
        summary.pop("_score", None)

    finding_candidates.sort(
        key=lambda item: (
            -item[0],
            item[2].get("first_seen") or "",
            item[2].get("destination_ip") or item[2].get("destination_hostname") or "",
        )
    )
    findings: list[dict[str, Any]] = []
    for _, finding_kind, summary, related_events in finding_candidates[
        :NETWORK_FINDING_LIMIT
    ]:
        if finding_kind == "fanout":
            process = summary.get("process") or "프로세스 미상"
            destination_count = summary.get("fanout_destination_count") or 0
            port_count = summary.get("fanout_port_count") or 0
            finding = _finding(
                "possible_process_fanout",
                f"다수 외부 목적지 통신 후보: {process}",
                _network_finding_severity(summary),
                related_events,
                (
                    f"10분 이내 서로 다른 외부 목적지 {destination_count}개와 "
                    f"포트 {port_count}개에 대한 통신이 관찰되었습니다. 스캔·프록시·"
                    "업데이트 동작 또는 C2 인프라 탐색 가능성을 구분해야 하며, 이 결과만으로 "
                    "악성 C2를 확정할 수 없습니다."
                ),
                "medium",
                [
                    "표시된 프로세스 인스턴스의 생성 명령줄, 부모 프로세스, 해시와 서명을 확인하세요.",
                    "후보 목적지를 DNS·프록시·방화벽 로그와 대조하여 승인된 서비스인지 확인하세요.",
                    "같은 시간대의 포트 스캔, 자격증명 사용, 원격 실행 이벤트를 교차 검증하세요.",
                ],
                evidence_limit=NETWORK_FINDING_EVIDENCE_LIMIT,
                event_count=int(summary.get("connection_count") or 0),
            )
            finding["network_context"] = {
                key: value
                for key, value in summary.items()
                if key not in {"suspicious", "_score"}
            }
            findings.append(finding)
            continue
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
            event_count=int(summary.get("connection_count") or 0),
        )
        finding["network_context"] = {
            key: value
            for key, value in summary.items()
            if key not in {"suspicious", "_score"}
        }
        findings.append(finding)

    sorted_fanout_summaries = sorted(
        fanout_summaries,
        key=lambda item: (
            -int(item.get("c2_score") or 0),
            -int(item.get("fanout_destination_count") or 0),
            item.get("first_seen") or "",
        ),
    )
    included_fanout_summaries = sorted_fanout_summaries[
        :NETWORK_FANOUT_ACTIVITY_LIMIT
    ]
    for summary in sorted_fanout_summaries:
        summary.pop("_score", None)

    sorted_groups = sorted(
        group_summaries,
        key=lambda item: (
            not item.get("c2_candidate", item["suspicious"]),
            -int(item.get("c2_score") or 0),
            -int(item["connection_count"]),
            item.get("first_seen") or "",
        ),
    )
    included_groups = sorted_groups[:NETWORK_ACTIVITY_GROUP_LIMIT]
    group_limit_reached = len(sorted_groups) > len(included_groups)
    finding_limit_reached = len(finding_candidates) > len(findings)
    fanout_activity_limit_reached = len(sorted_fanout_summaries) > len(
        included_fanout_summaries
    )
    fanout_out_of_order_reset_count = sum(
        int(state.get("out_of_order_resets") or 0)
        for state in fanout_windows.values()
    )
    limitation_reasons: list[str] = []
    if group_limit_reached or finding_limit_reached:
        limitation_reasons.append(
            f"네트워크 통신 {len(sorted_groups)}개 그룹 중 대표 {len(included_groups)}개와 "
            f"탐지 후보 {len(finding_candidates)}개 중 최대 {NETWORK_FINDING_LIMIT}개 finding만 포함했습니다."
        )
    if fanout_activity_limit_reached:
        limitation_reasons.append(
            f"프로세스 fan-out 후보 {len(sorted_fanout_summaries)}개 중 "
            f"상위 {len(included_fanout_summaries)}개 상세만 표시했습니다."
        )
    if correlation_index_limit_reached:
        limitation_reasons.append(
            f"프로세스·DNS 상관 인덱스는 선착순 {NETWORK_CORRELATION_INDEX_EVENT_LIMIT}개 관련 이벤트로 제한되었습니다."
        )
    if dns_match_index_limit_reached:
        limitation_reasons.append(
            "DNS 목적지 일치 보조 인덱스가 상한에 도달하여 이후 DNS는 "
            "시간 근접 후보만으로 상관분석했습니다."
        )
    if dns_correlation_candidate_limit_reached:
        limitation_reasons.append(
            f"일부 연결의 DNS 시간창 후보가 {NETWORK_CORRELATION_CANDIDATE_LIMIT}개를 넘어 "
            "목적지 IP·도메인 일치 후보와 가장 가까운 대표 후보만 평가했습니다."
        )
    if group_state_limit_reached:
        limitation_reasons.append(
            f"통신 그룹 상태 상한 {NETWORK_GROUP_STATE_LIMIT}개를 넘어 {omitted_group_connections}개 연결의 그룹 상세를 생략했습니다."
        )
    if timing_sample_truncated:
        limitation_reasons.append(
            f"그룹별 주기성 계산은 최대 {NETWORK_GROUP_TIMING_SAMPLE_LIMIT}개 시간 표본을 사용했습니다."
        )
    if observation_sample_truncated:
        limitation_reasons.append(
            "대량 통신 그룹의 상세 근거는 앞뒤 최대 "
            f"{NETWORK_GROUP_EDGE_EVIDENCE_LIMIT * 2}개 연결 표본을 사용했습니다."
        )
    if destination_ip_sample_truncated or unique_destination_limit_reached:
        limitation_reasons.append("고유 목적지 수 또는 그룹별 목적지 IP 목록이 표시 상한에 도달했습니다.")
    if fanout_state_limit_reached:
        limitation_reasons.append(
            f"fan-out 상태는 최대 {NETWORK_FANOUT_PROCESS_LIMIT}개 프로세스 인스턴스에 대해 유지했습니다."
        )
    if fanout_out_of_order_reset_count:
        limitation_reasons.append(
            "파일 간 네트워크 이벤트 순서가 역전되어 fan-out 시간창을 "
            f"{fanout_out_of_order_reset_count}회 보수적으로 재시작했습니다."
        )
    if not limitation_reasons:
        limitation_reasons.append(
            "공개 위협 인텔리전스 없이 로컬 이벤트의 프로세스·DNS·목적지·포트·반복성만 평가했습니다. "
            "C2 점수는 휴리스틱 후보 우선순위이며 정상 기준선과 교차 검증해야 합니다."
        )
    activity = {
        "connection_event_count": connection_event_count,
        "source_network_record_count": source_network_record_count,
        "normalized_connection_count": normalized_connection_count,
        "dns_query_event_count": dns_event_count,
        "external_connection_count": external_connections,
        "unique_external_destination_count": len(unique_external_destinations),
        "unique_external_destination_count_is_lower_bound": unique_destination_limit_reached,
        "group_count": len(sorted_groups),
        "included_group_count": len(included_groups),
        "suspicious_group_count": sum(
            1 for _, kind, _, _ in finding_candidates if kind == "connection"
        ),
        "process_fanout_candidate_count": len(fanout_candidates),
        "c2_candidate_count": sum(
            1 for _, kind, _, _ in finding_candidates if kind == "connection"
        )
        + len(fanout_candidates),
        "included_process_fanout_candidate_count": len(
            included_fanout_summaries
        ),
        "included_finding_count": len(findings),
        "correlation_index_limit_reached": correlation_index_limit_reached,
        "dns_match_index_limit_reached": dns_match_index_limit_reached,
        "dns_correlation_candidate_limit_reached": dns_correlation_candidate_limit_reached,
        "group_state_limit_reached": group_state_limit_reached,
        "fanout_state_limit_reached": fanout_state_limit_reached,
        "fanout_out_of_order_reset_count": fanout_out_of_order_reset_count,
        "timing_sample_truncated": timing_sample_truncated,
        "observation_sample_truncated": observation_sample_truncated,
        "omitted_group_connection_count": omitted_group_connections,
        "c2_score_version": C2_SCORE_VERSION,
        "c2_score_is_heuristic": True,
        "truncated": bool(
            group_limit_reached
            or finding_limit_reached
            or fanout_activity_limit_reached
            or correlation_index_limit_reached
            or dns_match_index_limit_reached
            or dns_correlation_candidate_limit_reached
            or group_state_limit_reached
            or timing_sample_truncated
            or observation_sample_truncated
            or destination_ip_sample_truncated
            or unique_destination_limit_reached
            or fanout_state_limit_reached
            or fanout_out_of_order_reset_count > 0
        ),
        "limitation": " ".join(limitation_reasons),
        "top_dns_queries": _counter_list(dns_counter, 30),
        "connections": included_groups,
        "process_fanout_candidates": included_fanout_summaries,
    }
    return findings, activity


def _network_observation(event: EventRecord) -> dict[str, Any] | None:
    destination_ip = _normalized_ip(_destination_ip(event)) or _destination_ip(event)
    destination_hostname = _normalized_domain(
        _field(event, "DestinationHostname")
    ) or None
    destination_port = _normalized_port(_destination_port(event))
    source_ip = _normalized_ip(_source_ip(event)) or _source_ip(event)
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
        observation.get("process_instance_id")
        or observation.get("process_guid")
        or "|".join(
            (
                str(observation.get("process") or "").casefold(),
                str(observation.get("process_id") or ""),
            )
        )
    )
    destination_identity = (
        _normalized_domain(observation.get("destination_hostname"))
        or _normalized_ip(observation.get("destination_ip"))
        or str(observation.get("destination_ip") or "").strip().casefold()
    )
    return (
        _normalized_host(observation.get("host")),
        str(process_identity),
        destination_identity,
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
    if not ordered or any(
        item.get("process_guid") or item.get("process_instance_id")
        for item in ordered
    ):
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
    *,
    connection_count: int | None = None,
    timed: list[datetime] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    destination_ips: list[str] | None = None,
    destination_ip_limit_reached: bool = False,
    external_destination: bool | None = None,
    process_fanout: bool = False,
) -> tuple[dict[str, Any], list[EventRecord]]:
    observations = sorted(
        observations,
        key=lambda item: _event_time_sort_key(item["time"]),
    )
    first = observations[0]
    timed_values = sorted(
        timed
        if timed is not None
        else [item["time"] for item in observations if item["time"] is not None],
        key=_event_time_sort_key,
    )
    effective_connection_count = connection_count or len(observations)
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
    parent_process_names = {
        name
        for event in process_events
        if (
            name := _windows_basename(
                _field(event, "ParentImage", "ParentProcessName")
            )
        )
    }
    suspicious_parent_or_lolbin = bool(
        process_name in SCRIPT_OR_LOLBIN_NETWORK_CLIENTS
        or parent_process_names.intersection(SUSPICIOUS_NETWORK_PARENT_PROCESSES)
    )
    sensitive_loopback = bool(
        _is_loopback_ip(first.get("destination_ip"))
        and destination_port in SENSITIVE_TUNNEL_PORTS
        and process_name in SERVER_PROCESSES_WITH_SENSITIVE_LOOPBACK
        and first.get("network_direction") != "inbound"
    )
    possible_beacon, beacon_detail = _possible_beacon(timed_values)
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
    external_destination_value = (
        external_destination
        if external_destination is not None
        else any(item["external_destination"] for item in observations)
    )
    unusual_network_process = bool(
        external_destination_value
        and process_name
        and not common_client
        and process_name
        not in {"svchost.exe", "services.exe", "system", "system.exe"}
    )

    signals: list[str] = []
    score_components: dict[str, int] = {}
    if external_destination_value:
        signals.append("외부/비로컬 목적지")
    if high_risk_port:
        signals.append(f"고위험 목적지 포트 {destination_port}")
        score_components["high_risk_port"] = C2_SCORE_WEIGHTS["high_risk_port"]
    if nonstandard_port:
        signals.append(f"비표준 목적지 포트 {destination_port}")
        score_components["nonstandard_port"] = C2_SCORE_WEIGHTS["nonstandard_port"]
    effective_writable_path = writable_path and not (
        common_client and not high_risk_port
    )
    if effective_writable_path:
        signals.append("사용자 쓰기 가능 경로의 프로세스")
        score_components["user_writable_process"] = C2_SCORE_WEIGHTS[
            "user_writable_process"
        ]
    if command_suspicious:
        signals.append("연결된 프로세스 생성 이벤트의 의심 명령줄")
        score_components["suspicious_command"] = C2_SCORE_WEIGHTS[
            "suspicious_command"
        ]
    if suspicious_parent_or_lolbin:
        signals.append("스크립트/LOLBIN 네트워크 프로세스 또는 의심 부모 프로세스")
        score_components["suspicious_parent_or_lolbin"] = C2_SCORE_WEIGHTS[
            "suspicious_parent_or_lolbin"
        ]
    if known_tunnel_client:
        signals.append(f"알려진 터널링 도구 프로세스 {process_name}")
        score_components["known_tunnel_client"] = C2_SCORE_WEIGHTS[
            "known_tunnel_client"
        ]
    if sensitive_loopback:
        signals.append(
            f"서버 프로세스의 민감 서비스 loopback 통신 {destination_port}"
        )
        score_components["sensitive_loopback_tunnel"] = C2_SCORE_WEIGHTS[
            "sensitive_loopback_tunnel"
        ]
    if dns_queries:
        signals.append("ProcessGuid/PID와 시간으로 연결된 DNS 질의")
    if suspicious_domain_pattern:
        signals.append("긴 고엔트로피 DNS 레이블")
        score_components["high_entropy_dns"] = C2_SCORE_WEIGHTS[
            "high_entropy_dns"
        ]
    if possible_beacon:
        signals.append(beacon_detail)
        score_components["periodic_beacon"] = C2_SCORE_WEIGHTS[
            "periodic_beacon"
        ]
    if process_fanout:
        signals.append("동일 프로세스 인스턴스의 단시간 다수 목적지 통신")
        score_components["process_fanout"] = C2_SCORE_WEIGHTS["process_fanout"]
    if unusual_network_process:
        score_components["unusual_network_process"] = C2_SCORE_WEIGHTS[
            "unusual_network_process"
        ]

    strong_process_signal = command_suspicious or effective_writable_path
    suspicious_domain_signal = bool(
        suspicious_domain_pattern
        and external_destination_value
        and (
            strong_process_signal
            or nonstandard_port
            or effective_connection_count >= 3
        )
    )
    beacon_signal = bool(
        possible_beacon
        and external_destination_value
        and first.get("network_direction") != "inbound"
    )
    suspicious = bool(
        high_risk_port
        or known_tunnel_client
        or sensitive_loopback
        or beacon_signal
        or suspicious_domain_signal
        or (external_destination_value and strong_process_signal)
        or (
            external_destination_value
            and suspicious_parent_or_lolbin
            and (nonstandard_port or suspicious_domain_pattern)
        )
    )
    c2_score = min(100, sum(score_components.values()))
    correlation_reasons = []
    for observation in observations:
        for reason in observation.get("correlation_reasons") or []:
            if reason not in correlation_reasons:
                correlation_reasons.append(reason)
    normalized_destination_ips = list(destination_ips or [])
    first_destination_ip = _normalized_ip(first.get("destination_ip"))
    if first_destination_ip and first_destination_ip not in normalized_destination_ips:
        normalized_destination_ips.insert(0, first_destination_ip)
    process_start_times = [
        event.time_created
        for event in process_events
        if event.time_created is not None
    ]
    process_end_times = [
        item.get("process_end_time")
        for item in observations
        if isinstance(item.get("process_end_time"), datetime)
    ]
    summary = {
        "first_seen": isoformat_utc(
            first_seen or (timed_values[0] if timed_values else None)
        ),
        "last_seen": isoformat_utc(
            last_seen or (timed_values[-1] if timed_values else None)
        ),
        "host": first.get("host"),
        "source_ip": first.get("source_ip"),
        "source_port": first.get("source_port"),
        "destination_ip": first.get("destination_ip"),
        "destination_ips": normalized_destination_ips,
        "destination_ip_count_is_lower_bound": destination_ip_limit_reached,
        "destination_port": destination_port,
        "destination_hostname": first.get("destination_hostname"),
        "protocol": first.get("protocol"),
        "initiated": first.get("initiated"),
        "network_direction": first.get("network_direction"),
        "process": process,
        "process_guid": first.get("process_guid"),
        "process_id": first.get("process_id"),
        "process_instance_id": first.get("process_instance_id"),
        "process_start_time": isoformat_utc(
            min(process_start_times, key=_event_time_sort_key)
        )
        if process_start_times
        else None,
        "process_end_time": isoformat_utc(
            min(process_end_times, key=_event_time_sort_key)
        )
        if process_end_times
        else None,
        "connection_count": effective_connection_count,
        "sampled_connection_count": len(observations),
        "timing_sample_count": len(timed_values),
        "evidence_sampled": effective_connection_count > len(observations),
        "external_destination": external_destination_value,
        "dns_queries": dns_queries[:12],
        "correlation_reasons": correlation_reasons,
        "anomaly_signals": signals,
        "possible_beacon": possible_beacon,
        "beacon_signal": beacon_signal,
        "suspicious_domain_pattern": suspicious_domain_pattern,
        "suspicious_domain_signal": suspicious_domain_signal,
        "known_tunnel_client": known_tunnel_client,
        "sensitive_loopback": sensitive_loopback,
        "suspicious_parent_or_lolbin": suspicious_parent_or_lolbin,
        "process_fanout": process_fanout,
        "c2_candidate": suspicious,
        "c2_score": c2_score,
        "c2_score_level": _c2_score_level(c2_score),
        "c2_score_version": C2_SCORE_VERSION,
        "c2_score_components": score_components,
        "suspicious": suspicious,
        "_score": c2_score,
    }
    return summary, related_events


def _c2_score_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _fanout_process_key(
    observation: dict[str, Any],
) -> tuple[str, str] | None:
    identity = observation.get("process_instance_id") or observation.get(
        "process_guid"
    )
    if not identity:
        process = str(observation.get("process") or "").casefold()
        pid = str(observation.get("process_id") or "")
        if not process and not pid:
            return None
        identity = f"unresolved:{process}|{pid}"
    return _normalized_host(observation.get("host")), str(identity)


def _fanout_eligible(observation: dict[str, Any]) -> bool:
    return bool(
        observation.get("external_destination")
        and observation.get("network_direction") != "inbound"
        and (
            observation.get("destination_hostname")
            or observation.get("destination_ip")
        )
        and isinstance(observation.get("time"), datetime)
    )


def _fanout_process_risk(observation: dict[str, Any]) -> bool:
    process = observation.get("process")
    process_name = _windows_basename(process)
    process_event = observation.get("process_event")
    parent_name = (
        _windows_basename(
            _field(process_event, "ParentImage", "ParentProcessName")
        )
        if isinstance(process_event, EventRecord)
        else ""
    )
    return bool(
        process_name in KNOWN_TUNNEL_CLIENTS
        or process_name in SCRIPT_OR_LOLBIN_NETWORK_CLIENTS
        or parent_name in SUSPICIOUS_NETWORK_PARENT_PROCESSES
        or (
            _is_user_writable_process_path(process)
            and process_name not in COMMON_NETWORK_CLIENTS
        )
        or (
            isinstance(process_event, EventRecord)
            and _event_has_suspicious_command(process_event)
        )
    )


def _update_fanout_window(
    windows: dict[tuple[str, str], dict[str, Any]],
    candidates: dict[tuple[str, str], dict[str, Any]],
    key: tuple[str, str],
    observation: dict[str, Any],
) -> None:
    value = observation.get("time")
    if not isinstance(value, datetime):
        return
    timestamp = _as_utc(value).timestamp()
    state = windows.get(key)
    if state is None:
        state = {
            "queue": deque(),
            "destinations": Counter(),
            "ports": Counter(),
            "last_timestamp": None,
            "process_risk": False,
            "out_of_order_resets": 0,
        }
        windows[key] = state
    queue = state["queue"]
    destinations = state["destinations"]
    ports = state["ports"]
    last_timestamp = state.get("last_timestamp")
    if isinstance(last_timestamp, (int, float)) and timestamp < last_timestamp:
        # Cross-file input can arrive out of order. Resetting avoids inventing
        # an over-wide false fan-out window; endpoint grouping still proceeds.
        queue.clear()
        destinations.clear()
        ports.clear()
        state["out_of_order_resets"] += 1
    state["last_timestamp"] = timestamp
    cutoff = timestamp - NETWORK_FANOUT_WINDOW_SECONDS
    while queue and queue[0][0] < cutoff:
        _, old_destination, old_port, _ = queue.popleft()
        _decrement_counter(destinations, old_destination)
        _decrement_counter(ports, old_port)

    destination = str(
        observation.get("destination_hostname")
        or observation.get("destination_ip")
        or ""
    ).casefold()
    port = observation.get("destination_port")
    queue.append((timestamp, destination, port, observation))
    destinations[destination] += 1
    if port is not None:
        ports[port] += 1
    state["process_risk"] = bool(
        state.get("process_risk") or _fanout_process_risk(observation)
    )

    while len(queue) > NETWORK_FANOUT_EVENT_LIMIT_PER_PROCESS:
        _, old_destination, old_port, _ = queue.popleft()
        _decrement_counter(destinations, old_destination)
        _decrement_counter(ports, old_port)

    destination_count = len(destinations)
    port_count = len(ports)
    process_name = _windows_basename(observation.get("process"))
    triggered = bool(
        (
            destination_count >= NETWORK_FANOUT_STANDALONE_DESTINATION_THRESHOLD
            and process_name not in COMMON_NETWORK_CLIENTS
        )
        or (
            destination_count >= NETWORK_FANOUT_DESTINATION_THRESHOLD
            and (
                port_count >= NETWORK_FANOUT_PORT_THRESHOLD
                or state["process_risk"]
            )
        )
    )
    if not triggered:
        return
    current_rank = (destination_count, port_count, len(queue))
    previous = candidates.get(key)
    if previous is not None and current_rank <= previous["rank"]:
        return
    queue_values = list(queue)
    observations = [item[3] for item in queue_values]
    edge = NETWORK_GROUP_EDGE_EVIDENCE_LIMIT
    representative = (
        observations
        if len(observations) <= edge * 2
        else [*observations[:edge], *observations[-edge:]]
    )
    candidate_ips: list[str] = []
    seen_ips: set[str] = set()
    for item in observations:
        ip = _normalized_ip(item.get("destination_ip"))
        if ip and ip not in seen_ips and len(candidate_ips) < NETWORK_GROUP_DESTINATION_IP_LIMIT:
            seen_ips.add(ip)
            candidate_ips.append(ip)
    candidates[key] = {
        "rank": current_rank,
        "observations": representative,
        "window_connection_count": len(queue),
        "destination_count": destination_count,
        "port_count": port_count,
        "destinations": [name for name, _ in destinations.most_common(32)],
        "ports": [value for value, _ in ports.most_common(32)],
        "destination_ips": candidate_ips,
        "first_seen": queue_values[0][0],
        "last_seen": queue_values[-1][0],
        "process_risk": bool(state["process_risk"]),
    }


def _decrement_counter(counter: Counter[Any], key: Any) -> None:
    if key is None:
        return
    counter[key] -= 1
    if counter[key] <= 0:
        del counter[key]


def _summarize_fanout_candidate(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any], list[EventRecord]]:
    observations = list(candidate.get("observations") or [])
    first = observations[0]
    process_events = _deduplicate_events(
        item["process_event"]
        for item in observations
        if isinstance(item.get("process_event"), EventRecord)
    )
    dns_events = _deduplicate_events(
        event
        for item in observations
        for event in item.get("dns_events") or []
    )
    connection_events = _deduplicate_events(
        item["event"] for item in observations
    )
    related_events = _deduplicate_events(
        [*process_events, *dns_events, *connection_events]
    )
    process = first.get("process")
    process_name = _windows_basename(process)
    command_suspicious = any(
        _event_has_suspicious_command(event) for event in process_events
    )
    writable_path = _is_user_writable_process_path(process)
    known_tunnel_client = process_name in KNOWN_TUNNEL_CLIENTS
    parent_names = {
        _windows_basename(_field(event, "ParentImage", "ParentProcessName"))
        for event in process_events
    }
    suspicious_parent_or_lolbin = bool(
        process_name in SCRIPT_OR_LOLBIN_NETWORK_CLIENTS
        or parent_names.intersection(SUSPICIOUS_NETWORK_PARENT_PROCESSES)
    )
    score_components = {
        "process_fanout": C2_SCORE_WEIGHTS["process_fanout"],
    }
    signals = [
        (
            f"10분 내 다수 외부 목적지 fan-out "
            f"{candidate.get('destination_count', 0)}개/포트 {candidate.get('port_count', 0)}개"
        )
    ]
    if writable_path:
        signals.append("사용자 쓰기 가능 경로의 프로세스")
        score_components["user_writable_process"] = C2_SCORE_WEIGHTS[
            "user_writable_process"
        ]
    if command_suspicious:
        signals.append("연결된 프로세스 생성 이벤트의 의심 명령줄")
        score_components["suspicious_command"] = C2_SCORE_WEIGHTS[
            "suspicious_command"
        ]
    if suspicious_parent_or_lolbin:
        signals.append("스크립트/LOLBIN 네트워크 프로세스 또는 의심 부모 프로세스")
        score_components["suspicious_parent_or_lolbin"] = C2_SCORE_WEIGHTS[
            "suspicious_parent_or_lolbin"
        ]
    if known_tunnel_client:
        signals.append(f"알려진 터널링 도구 프로세스 {process_name}")
        score_components["known_tunnel_client"] = C2_SCORE_WEIGHTS[
            "known_tunnel_client"
        ]
    c2_score = min(100, sum(score_components.values()))
    destination_ips = list(candidate.get("destination_ips") or [])
    destinations = list(candidate.get("destinations") or [])
    first_destination_name = next(
        (value for value in destinations if _normalized_ip(value) is None),
        None,
    )
    summary = {
        "first_seen": isoformat_utc(
            datetime.fromtimestamp(candidate["first_seen"], tz=timezone.utc)
        ),
        "last_seen": isoformat_utc(
            datetime.fromtimestamp(candidate["last_seen"], tz=timezone.utc)
        ),
        "host": first.get("host"),
        "process": process,
        "process_guid": first.get("process_guid"),
        "process_id": first.get("process_id"),
        "process_instance_id": first.get("process_instance_id"),
        "destination_ip": destination_ips[0] if destination_ips else None,
        "destination_ips": destination_ips,
        "destination_hostname": first_destination_name,
        "destination_port": None,
        "candidate_destinations": destinations,
        "candidate_ports": list(candidate.get("ports") or []),
        "fanout_destination_count": int(candidate.get("destination_count") or 0),
        "fanout_port_count": int(candidate.get("port_count") or 0),
        "connection_count": int(candidate.get("window_connection_count") or 0),
        "sampled_connection_count": len(observations),
        "external_destination": True,
        "network_direction": "outbound",
        "anomaly_signals": signals,
        "correlation_reasons": [],
        "possible_beacon": False,
        "beacon_signal": False,
        "suspicious_domain_pattern": False,
        "suspicious_domain_signal": False,
        "known_tunnel_client": known_tunnel_client,
        "sensitive_loopback": False,
        "suspicious_parent_or_lolbin": suspicious_parent_or_lolbin,
        "process_fanout": True,
        "c2_candidate": True,
        "c2_score": c2_score,
        "c2_score_level": _c2_score_level(c2_score),
        "c2_score_version": C2_SCORE_VERSION,
        "c2_score_components": score_components,
        "suspicious": True,
        "_score": c2_score,
    }
    return summary, related_events


def _correlated_process_event(
    event: EventRecord,
    by_guid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    by_pid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    terminations_by_guid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ],
    terminations_by_pid: dict[
        tuple[str, str], list[tuple[float, int, EventRecord]]
    ],
) -> tuple[EventRecord | None, str | None, str | None, EventRecord | None]:
    host = _normalized_host(event.computer)
    guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    if guid:
        candidates = by_guid.get((host, guid), [])
        if candidate := _most_recent_preceding_event(event, candidates, None):
            process_end = _first_process_termination(
                candidate,
                terminations_by_guid.get((host, guid), []),
            )
            if _event_ended_before_target(process_end, event):
                return (
                    None,
                    "동일 ProcessGuid 프로세스가 연결 전에 종료되어 생성 이벤트 상관 제외",
                    _ended_guid_process_instance_id(guid, process_end),
                    process_end,
                )
            reason = "동일 ProcessGuid와 프로세스 수명으로 프로세스 생성 이벤트 연결"
            return candidate, reason, _process_instance_id(candidate, event), process_end
        recent_end = _most_recent_preceding_event(
            event,
            terminations_by_guid.get((host, guid), []),
            None,
        )
        if recent_end is not None:
            return (
                None,
                "동일 ProcessGuid의 최근 종료 이후 생성 이벤트가 없어 원인 프로세스 상관 보류",
                _ended_guid_process_instance_id(guid, recent_end),
                recent_end,
            )
        return None, None, f"guid:{guid}", None

    pid = _normalized_process_id(_field(event, "ProcessId", "ProcessID"))
    if not pid:
        return None, None, None, None
    candidates = by_pid.get((host, pid), [])
    candidate = _most_recent_preceding_event(
        event,
        candidates,
        NETWORK_CORRELATION_WINDOW_SECONDS,
    )
    if candidate is None:
        recent_end = _most_recent_preceding_event(
            event,
            terminations_by_pid.get((host, pid), []),
            None,
        )
        return (
            None,
            "동일 PID의 최근 종료 이후 생성 이벤트가 없어 원인 프로세스 상관 보류"
            if recent_end is not None
            else None,
            None,
            recent_end,
        )
    connection_image = str(_process(event) or "").casefold()
    process_image = str(_process(candidate) or "").casefold()
    image_relation = "프로세스 경로"
    if connection_image and process_image and connection_image != process_image:
        connection_name = _windows_basename(connection_image)
        process_name = _windows_basename(process_image)
        if not connection_name or connection_name != process_name:
            recent_end = _most_recent_preceding_event(
                event,
                terminations_by_pid.get((host, pid), []),
                None,
            )
            return None, None, None, recent_end
        # Security 5156 commonly records an NT device path while 4688 records
        # a drive-letter path.  Host + PID + a short time window + the same
        # executable basename is useful supporting evidence, but the wording
        # keeps this weaker than an exact path or ProcessGuid match.
        image_relation = "프로세스 파일명(경로 표기 상이)"
    process_end = _first_process_termination(
        candidate,
        terminations_by_pid.get((host, pid), []),
    )
    if _event_ended_before_target(process_end, event):
        return (
            None,
            "동일 호스트·PID 후보 프로세스가 연결 전에 종료되어 PID 재사용 가능성으로 상관 제외",
            None,
            process_end,
        )
    return (
        candidate,
        f"동일 호스트·PID·{image_relation}, 10분 시간창과 프로세스 수명으로 생성 이벤트 연결",
        _process_instance_id(candidate, event),
        process_end,
    )


def _first_process_termination(
    process_start: EventRecord,
    candidates: list[tuple[float, int, EventRecord]],
) -> EventRecord | None:
    if process_start.time_created is None or not candidates:
        return None
    started_at = _as_utc(process_start.time_created).timestamp()
    position = bisect_left(candidates, (started_at, -1))
    start_name = _windows_basename(_process(process_start))
    for _, _, candidate in candidates[position:]:
        end_name = _windows_basename(_process(candidate))
        if start_name and end_name and start_name != end_name:
            continue
        return candidate
    return None


def _event_ended_before_target(
    process_end: EventRecord | None,
    target: EventRecord,
) -> bool:
    if (
        process_end is None
        or process_end.time_created is None
        or target.time_created is None
    ):
        return False
    return _as_utc(process_end.time_created) < _as_utc(target.time_created)


def _process_instance_id(
    process_start: EventRecord,
    connection: EventRecord,
) -> str:
    guid = _normalized_process_guid(
        _field(connection, "ProcessGuid") or _field(process_start, "ProcessGuid")
    )
    host = _normalized_host(connection.computer or process_start.computer)
    pid = _normalized_process_id(
        _field(connection, "ProcessId", "ProcessID")
        or _process_id(process_start)
    )
    started_at = isoformat_utc(process_start.time_created) or "time-unknown"
    source_identity = process_start.record_id or started_at
    prefix = f"guid:{guid}|start:" if guid else "start:"
    return prefix + "|".join(
        (
            host,
            process_start.source_file,
            str(source_identity),
            started_at,
            str(pid or ""),
            _windows_basename(_process(process_start)),
        )
    )


def _ended_guid_process_instance_id(
    guid: str,
    process_end: EventRecord,
) -> str:
    ended_at = isoformat_utc(process_end.time_created) or "time-unknown"
    source_identity = process_end.record_id or ended_at
    return "ended-guid:" + "|".join(
        (
            guid,
            _normalized_host(process_end.computer),
            process_end.source_file,
            str(source_identity),
            ended_at,
        )
    )


def _correlated_dns_events(
    event: EventRecord,
    by_guid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    by_pid: dict[tuple[str, str], list[tuple[float, int, EventRecord]]],
    matches_by_guid: dict[
        tuple[str, str, str], list[tuple[float, int, EventRecord]]
    ],
    matches_by_pid: dict[
        tuple[str, str, str], list[tuple[float, int, EventRecord]]
    ],
    *,
    process_start: EventRecord | None,
    process_end: EventRecord | None,
) -> tuple[list[EventRecord], str | None, bool]:
    host = _normalized_host(event.computer)
    guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    pid = _normalized_process_id(_field(event, "ProcessId", "ProcessID"))
    destination_hostname = _normalized_domain(_field(event, "DestinationHostname"))
    destination_ip = _normalized_ip(_destination_ip(event))
    candidates: list[EventRecord] = []
    link_kind: str | None = None
    candidates_truncated = False
    if guid:
        candidates, candidates_truncated = _events_near_target(
            event,
            by_guid.get((host, guid), []),
            DNS_CORRELATION_WINDOW_SECONDS,
            priority_indexes=_dns_priority_indexes(
                matches_by_guid,
                host,
                guid,
                destination_ip,
                destination_hostname,
            ),
        )
        if candidates:
            link_kind = "동일 ProcessGuid"
    if not candidates and pid and not guid:
        candidates, candidates_truncated = _events_near_target(
            event,
            by_pid.get((host, pid), []),
            DNS_CORRELATION_WINDOW_SECONDS,
            priority_indexes=_dns_priority_indexes(
                matches_by_pid,
                host,
                pid,
                destination_ip,
                destination_hostname,
            ),
        )
        if candidates:
            link_kind = "동일 호스트·PID"
    if not candidates:
        return [], None, candidates_truncated

    linked: list[tuple[bool, float, EventRecord]] = []
    for candidate in candidates:
        delta = _event_time_delta_seconds(event, candidate)
        if delta is None or delta > DNS_CORRELATION_WINDOW_SECONDS:
            continue
        if not _dns_event_matches_process_lifetime(
            candidate,
            event,
            process_start=process_start,
            process_end=process_end,
        ):
            continue
        query = _normalized_domain(_field(candidate, "QueryName"))
        result_ips = _dns_result_ips(_field(candidate, "QueryResults"))
        result_matches = bool(destination_ip and destination_ip in result_ips)
        if destination_hostname:
            if not query or not _domains_equivalent(destination_hostname, query):
                continue
        elif not result_matches:
            # A PID/time-only DNS association is too weak when a 5156-style
            # connection has no hostname. Require QueryResults to contain the
            # exact normalized destination IP before promoting a domain.
            continue
        linked.append((result_matches, delta, candidate))
    if not linked:
        return [], None, candidates_truncated
    linked.sort(key=lambda item: (not item[0], item[1]))
    exact_result = any(item[0] for item in linked)
    if destination_hostname and exact_result:
        match_note = "동일 도메인 및 DNS QueryResults 목적지 IP 일치"
    elif destination_hostname:
        match_note = "동일 도메인"
    else:
        match_note = "DNS QueryResults 목적지 IP 일치"
    return (
        [item[2] for item in linked[:NETWORK_CORRELATED_DNS_LIMIT]],
        f"{link_kind}, {match_note}, 프로세스 수명과 5분 시간창으로 DNS 질의 연결",
        candidates_truncated,
    )


def _dns_event_matches_process_lifetime(
    dns_event: EventRecord,
    connection: EventRecord,
    *,
    process_start: EventRecord | None,
    process_end: EventRecord | None,
) -> bool:
    if dns_event.time_created is None or connection.time_created is None:
        return False
    dns_time = _as_utc(dns_event.time_created)
    connection_time = _as_utc(connection.time_created)
    if process_start is not None and process_start.time_created is not None:
        if dns_time < _as_utc(process_start.time_created):
            return False
    if process_end is not None and process_end.time_created is not None:
        end_time = _as_utc(process_end.time_created)
        if end_time < connection_time:
            # The matched/most-recent prior lifetime has ended. Only a DNS
            # event after that boundary can belong to an otherwise unlogged
            # replacement process using the same PID.
            return dns_time > end_time
        if dns_time > end_time:
            return False
    return True


def _dns_hostname_for_destination(
    destination_ip: Any,
    dns_events: Iterable[EventRecord],
) -> str | None:
    normalized_destination = _normalized_ip(destination_ip)
    if not normalized_destination:
        return None
    for event in dns_events:
        if normalized_destination not in _dns_result_ips(
            _field(event, "QueryResults")
        ):
            continue
        query = _normalized_domain(_field(event, "QueryName"))
        if query:
            return query
    return None


def _dns_match_tokens(event: EventRecord) -> list[str]:
    """Return deterministic exact-match keys used by the bounded DNS index."""
    tokens = [
        f"ip:{value}"
        for value in sorted(_dns_result_ips(_field(event, "QueryResults")))
    ]
    if query := _normalized_domain(_field(event, "QueryName")):
        tokens.append(f"domain:{query}")
    return tokens


def _dns_priority_indexes(
    index: dict[tuple[str, str, str], list[tuple[float, int, EventRecord]]],
    host: str,
    process_identity: str,
    destination_ip: str | None,
    destination_hostname: str,
) -> list[list[tuple[float, int, EventRecord]]]:
    keys: list[str] = []
    if destination_ip:
        keys.append(f"ip:{destination_ip}")
    if destination_hostname:
        keys.append(f"domain:{destination_hostname}")
    return [
        candidates
        for key in keys
        if (candidates := index.get((host, process_identity, key)))
    ]


def _dns_result_ips(value: Any) -> set[str]:
    text = str(value or "")
    if not text:
        return set()
    # Sysmon commonly separates answers with semicolons, but versions and DNS
    # record types vary. Extract syntactically plausible IPv4/IPv6 tokens and
    # let ipaddress perform the actual validation.
    tokens = re.findall(
        r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]+)(?![0-9A-Fa-f:.])",
        text,
    )
    return {
        normalized
        for token in tokens
        if (normalized := _normalized_ip(token)) is not None
    }


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
    *,
    priority_indexes: Iterable[
        list[tuple[float, int, EventRecord]]
    ] = (),
) -> tuple[list[EventRecord], bool]:
    if target.time_created is None or not candidates:
        return [], False
    target_timestamp = _as_utc(target.time_created).timestamp()
    left = bisect_left(candidates, (target_timestamp - max_delta_seconds, -1))
    right = bisect_right(candidates, (target_timestamp + max_delta_seconds, 10**30))
    total_candidates = right - left
    if total_candidates <= 0:
        return [], False

    selected: list[tuple[float, int, EventRecord]] = []
    selected_events: set[int] = set()
    prioritized: list[tuple[float, int, EventRecord]] = []
    for priority_index in priority_indexes:
        priority_left = bisect_left(
            priority_index,
            (target_timestamp - max_delta_seconds, -1),
        )
        priority_right = bisect_right(
            priority_index,
            (target_timestamp + max_delta_seconds, 10**30),
        )
        position = bisect_left(
            priority_index,
            (target_timestamp, -1),
            priority_left,
            priority_right,
        )
        half_limit = NETWORK_CORRELATION_CANDIDATE_LIMIT // 2
        nearby_left = max(priority_left, position - half_limit)
        nearby_right = min(
            priority_right,
            nearby_left + NETWORK_CORRELATION_CANDIDATE_LIMIT,
        )
        nearby_left = max(
            priority_left,
            nearby_right - NETWORK_CORRELATION_CANDIDATE_LIMIT,
        )
        prioritized.extend(priority_index[nearby_left:nearby_right])

    prioritized.sort(
        key=lambda item: (abs(item[0] - target_timestamp), item[0], item[1])
    )
    for item in prioritized:
        event_identity = id(item[2])
        if event_identity in selected_events:
            continue
        selected.append(item)
        selected_events.add(event_identity)
        if len(selected) >= NETWORK_CORRELATION_CANDIDATE_LIMIT:
            break

    position = bisect_left(candidates, (target_timestamp, -1), left, right)
    half_limit = NETWORK_CORRELATION_CANDIDATE_LIMIT // 2
    nearby_left = max(left, position - half_limit)
    nearby_right = min(
        right,
        nearby_left + NETWORK_CORRELATION_CANDIDATE_LIMIT,
    )
    nearby_left = max(left, nearby_right - NETWORK_CORRELATION_CANDIDATE_LIMIT)
    nearby = sorted(
        candidates[nearby_left:nearby_right],
        key=lambda item: (abs(item[0] - target_timestamp), item[0], item[1]),
    )
    for item in nearby:
        event_identity = id(item[2])
        if event_identity in selected_events:
            continue
        selected.append(item)
        selected_events.add(event_identity)
        if len(selected) >= NETWORK_CORRELATION_CANDIDATE_LIMIT:
            break
    return (
        [item[2] for item in selected],
        total_candidates > len(selected),
    )


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
    if int(summary.get("c2_score") or 0) >= 70:
        return "high"
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
            "10분 내 다수 외부 목적지",
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


@dataclass
class _IntrusionProcessNode:
    key: tuple[str, ...]
    process_instance_id: str
    host: str
    process: str | None
    process_id: str | None
    process_guid: str | None
    start_time: datetime | None
    source_file: str
    record_id: str | None
    event_id: str | None
    account: str | None
    command_line: str | None
    hashes: str | None
    parent_process: str | None
    parent_process_id: str | None
    parent_process_guid: str | None
    source_ref: str
    creation_observed: bool = True
    parent_key: tuple[str, ...] | None = None
    parent_link_basis: str | None = None
    local_signals: list[str] = field(default_factory=list)
    event_refs: list[str] = field(default_factory=list)
    creation_event_refs: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)


def _iter_intrusion_source_records(
    parse_result: ParseResult,
    retained_records: list[EventRecord],
) -> Iterator[EventRecord]:
    """Yield retained records plus non-duplicate endpoint spool records.

    The normal retained list contains event types outside the endpoint spool,
    while the rewindable spool contains Sysmon/Security process and network
    records beyond the general retention cap.  The retained identity set is
    bounded by the parser's existing record limit.
    """
    for event in retained_records:
        yield event
    if not parse_result.has_network_record_spool:
        return
    retained_identities = {
        _intrusion_raw_event_identity(event) for event in retained_records
    }
    for event in parse_result.iter_network_records():
        if _intrusion_raw_event_identity(event) not in retained_identities:
            yield event


def _intrusion_select_suspicious_events(
    suspicious_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep high-signal items and time-balanced coverage of a long input."""
    limit = INTRUSION_SUSPICIOUS_EVENT_LIMIT
    if len(suspicious_events) <= limit:
        return list(suspicious_events)
    priority_indexes = [
        index
        for index, event in enumerate(suspicious_events)
        if SEVERITY_RANK.get(str(event.get("severity") or ""), 0)
        >= SEVERITY_RANK["high"]
        or any(
            str(rule).startswith("suspicious_process_")
            or rule
            in {
                "suspicious_powershell",
                "suspicious_network_connection",
                "possible_network_beacon",
                "suspicious_dns_network_activity",
                "possible_process_fanout",
            }
            for rule in event.get("rule_ids") or []
        )
    ]
    selected = set(
        _intrusion_evenly_spaced(priority_indexes, min(len(priority_indexes), limit * 3 // 4))
    )
    selected.update({0, len(suspicious_events) - 1})
    remaining = [
        index for index in range(len(suspicious_events)) if index not in selected
    ]
    selected.update(
        _intrusion_evenly_spaced(remaining, max(0, limit - len(selected)))
    )
    return [suspicious_events[index] for index in sorted(selected)[:limit]]


def _intrusion_chain(
    record_source: Callable[[], Iterator[EventRecord]],
    suspicious_events: list[dict[str, Any]],
    *,
    retained_record_count: int,
    network_scan_complete: bool,
    network_spool_limit_reached: bool,
    spool_scan_used: bool,
) -> dict[str, Any]:
    """Build a bounded, evidence-linked process-centric intrusion hypothesis.

    This is deliberately a local correlation result, not an intrusion verdict.
    ProcessGuid and ParentProcessGuid links are preferred. PID-only parent and
    follow-on links require matching host/image and a short lifetime window.
    """
    selected_suspicious = _intrusion_select_suspicious_events(suspicious_events)
    suspicious_event_limit_reached = len(suspicious_events) > len(
        selected_suspicious
    )
    priority_raw_ids = {
        _intrusion_raw_dict_identity(event) for event in selected_suspicious
    }
    priority_guids = {
        (_normalized_host(event.get("host")), guid)
        for event in selected_suspicious
        if (
            guid := _normalized_process_guid(
                event.get("process_guid")
                or (event.get("fields") or {}).get("ProcessGuid")
            )
        )
    }
    priority_pid_images = {
        (
            _normalized_host(event.get("host")),
            pid,
            _windows_basename(event.get("process")),
        )
        for event in selected_suspicious
        if (pid := _intrusion_dict_process_id(event))
    }

    nodes: dict[tuple[str, ...], _IntrusionProcessNode] = {}
    source_record_count = 0
    process_record_count = 0
    process_node_limit_reached = False
    priority_node_count = 0
    important_guids = set(priority_guids)

    for event in record_source():
        source_record_count += 1
        if not _is_process_creation_event(event):
            continue
        process_record_count += 1
        node = _intrusion_process_node(event)
        if node is None:
            continue
        existing = nodes.get(node.key)
        if existing is not None:
            if _intrusion_node_sort_key(node) < _intrusion_node_sort_key(existing):
                nodes[node.key] = node
            continue
        raw_id = _intrusion_raw_event_identity(event)
        node_host = _normalized_host(node.host)
        pid_image = (node_host, node.process_id or "", _windows_basename(node.process))
        is_priority = bool(
            raw_id in priority_raw_ids
            or (node.process_guid and (node_host, node.process_guid) in important_guids)
            or pid_image in priority_pid_images
            or node.local_signals
            or (
                node.parent_process_guid
                and (node_host, node.parent_process_guid) in important_guids
            )
        )
        if len(nodes) >= INTRUSION_PROCESS_NODE_LIMIT:
            process_node_limit_reached = True
            if not is_priority or priority_node_count >= INTRUSION_PRIORITY_PROCESS_NODE_LIMIT:
                continue
            priority_node_count += 1
        nodes[node.key] = node
        if is_priority and node.process_guid:
            important_guids.add((node_host, node.process_guid))

    guid_index, pid_index, raw_index = _intrusion_process_indexes(nodes)
    raw_event_refs: dict[tuple[str, ...], str] = {}
    event_node_keys: dict[str, tuple[str, ...]] = {}
    synthetic_node_count = 0

    for event in selected_suspicious:
        event_ref = str(event.get("event_ref") or "")
        if not event_ref:
            continue
        raw_identity = _intrusion_raw_dict_identity(event)
        raw_event_refs[raw_identity] = event_ref
        node_key = raw_index.get(raw_identity)
        if node_key is None:
            node_key = _intrusion_node_for_evidence(
                event,
                nodes,
                guid_index,
                pid_index,
            )
        if node_key is None and synthetic_node_count < INTRUSION_PRIORITY_PROCESS_NODE_LIMIT:
            synthetic = _intrusion_observed_process_node(event)
            if synthetic is not None:
                node = nodes.get(synthetic.key)
                if node is None:
                    nodes[synthetic.key] = synthetic
                    synthetic_node_count += 1
                    guid_index, pid_index, raw_index = _intrusion_process_indexes(nodes)
                    node_key = synthetic.key
                else:
                    node_key = node.key
        if node_key is None:
            continue
        node = nodes[node_key]
        _append_bounded_unique(node.event_refs, event_ref, 64)
        if raw_index.get(raw_identity) == node_key and str(event.get("event_id") or "") in {
            "1",
            "4688",
        }:
            _append_bounded_unique(node.creation_event_refs, event_ref, 16)
        for rule_id in event.get("rule_ids") or []:
            _append_bounded_unique(node.rule_ids, str(rule_id), 32)
        _append_bounded_unique(
            node.severities,
            str(event.get("severity") or "unknown"),
            8,
        )
        event_node_keys[event_ref] = node_key

    # Synthetic nodes may have introduced new identities. Link the complete
    # bounded set only after all evidence-backed nodes are present.
    guid_index, pid_index, raw_index = _intrusion_process_indexes(nodes)
    _link_intrusion_process_nodes(
        nodes,
        guid_index,
        pid_index,
    )
    signal_keys = {
        key for key, node in nodes.items() if node.event_refs or node.local_signals
    }
    candidate_groups: dict[tuple[str, ...], list[tuple[str, ...]]] = defaultdict(list)
    for node_key in sorted(signal_keys, key=lambda key: _intrusion_node_sort_key(nodes[key])):
        root_key = _intrusion_suspicious_root(node_key, nodes, signal_keys)
        candidate_groups[root_key].append(node_key)

    ranked_candidates = sorted(
        (
            (_intrusion_candidate_score(nodes[root], members, nodes), root, members)
            for root, members in candidate_groups.items()
        ),
        key=lambda item: (
            -item[0],
            _intrusion_node_sort_key(nodes[item[1]]),
        ),
    )

    base_limitations = [
        "이 결과는 EVTX에 기록된 프로세스·DNS·통신의 시간 및 식별자 상관관계에 기반한 후보이며 침해를 확정하지 않습니다.",
        "파일 내용, 메모리, 패킷 payload, 목적지 평판이 없으므로 실제 명령 수행·데이터 유출·C2 여부는 별도 검증해야 합니다.",
    ]
    if not network_scan_complete or network_spool_limit_reached:
        base_limitations.append(
            "입력 파싱 또는 endpoint spool이 완전하지 않아 시작 프로세스나 후속 통신이 누락됐을 수 있습니다."
        )
    if process_node_limit_reached:
        base_limitations.append(
            f"프로세스 그래프는 최대 {INTRUSION_PROCESS_NODE_LIMIT}개 일반 노드와 "
            f"{INTRUSION_PRIORITY_PROCESS_NODE_LIMIT}개 증거 우선 노드로 제한되었습니다."
        )
    if suspicious_event_limit_reached:
        base_limitations.append(
            f"침해 체인 연결에는 시간순 의심 이벤트 {INTRUSION_SUSPICIOUS_EVENT_LIMIT}개까지만 사용했습니다."
        )

    source_metadata = {
        "retained_record_count": retained_record_count,
        "record_count_scanned": source_record_count,
        "process_record_count": process_record_count,
        "process_node_count": len(nodes),
        "process_node_limit": INTRUSION_PROCESS_NODE_LIMIT,
        "process_node_limit_reached": process_node_limit_reached,
        "spool_scan_used": spool_scan_used,
        "source_scan_complete": bool(
            network_scan_complete and not network_spool_limit_reached
        ),
        "network_scan_complete": network_scan_complete,
        "network_spool_limit_reached": network_spool_limit_reached,
        "suspicious_event_count": len(suspicious_events),
        "suspicious_events_used": len(selected_suspicious),
    }
    if not ranked_candidates:
        limitations = [
            *base_limitations,
            "프로세스 GUID/PID로 연결 가능한 의심 실행 또는 통신 증거가 없어 시작 프로세스를 식별하지 못했습니다.",
        ]
        return {
            "schema_version": 1,
            "status": "insufficient_process_evidence",
            "candidate_only": True,
            "selection_method": "연결 가능한 의심 프로세스 증거 없음",
            "confidence": "unknown",
            "confidence_scope": "프로세스 및 이벤트 연결 신뢰도이며 악성 여부 신뢰도가 아닙니다.",
            "origin_process": None,
            "alternative_origin_candidates": [],
            "processes": [],
            "steps": [],
            "evidence_refs": [],
            "source_refs": [],
            "source": source_metadata,
            "truncated": bool(
                process_node_limit_reached
                or suspicious_event_limit_reached
                or not network_scan_complete
                or network_spool_limit_reached
            ),
            "chain_truncated": bool(
                process_node_limit_reached
                or suspicious_event_limit_reached
                or not network_scan_complete
                or network_spool_limit_reached
            ),
            "limitations": limitations,
        }

    _, origin_key, primary_signal_keys = ranked_candidates[0]
    origin = nodes[origin_key]
    children = _intrusion_children_index(nodes)
    relevant_keys, descendant_limit_reached = _intrusion_relevant_processes(
        origin_key,
        primary_signal_keys,
        nodes,
        children,
    )
    unresolved_parent_count = sum(
        1
        for key in relevant_keys
        if nodes[key].parent_key is None
        and (
            nodes[key].parent_process_guid
            or nodes[key].parent_process_id
            or nodes[key].parent_process
        )
    )
    pid_parent_link_count = sum(
        1
        for key in relevant_keys
        if nodes[key].parent_link_basis
        and "ProcessGuid 부재" in str(nodes[key].parent_link_basis)
    )
    relevant_set = set(relevant_keys)
    relevant_guid_index, relevant_pid_index, _ = _intrusion_process_indexes(
        {key: nodes[key] for key in relevant_keys}
    )
    followon_groups: dict[tuple[str, ...], dict[str, Any]] = {}
    followon_record_count = 0
    omitted_followon_event_count = 0

    for event in record_source():
        followon_record_count += 1
        if not (_is_dns_query_event(event) or _is_network_connection_event(event)):
            continue
        node_key = _intrusion_process_for_event(
            event,
            nodes,
            relevant_guid_index,
            relevant_pid_index,
        )
        if node_key not in relevant_set:
            continue
        raw_identity = _intrusion_raw_event_identity(event)
        event_ref = raw_event_refs.get(raw_identity)
        group_key = _intrusion_followon_key(node_key, event)
        group = followon_groups.get(group_key)
        if group is None:
            if len(followon_groups) >= INTRUSION_FOLLOWON_GROUP_LIMIT:
                replace_key = next(
                    (
                        key
                        for key, value in followon_groups.items()
                        if not value.get("event_refs")
                    ),
                    None,
                ) if event_ref else None
                if replace_key is None:
                    omitted_followon_event_count += 1
                    continue
                omitted_followon_event_count += int(
                    followon_groups[replace_key].get("event_count") or 0
                )
                del followon_groups[replace_key]
            group = _new_intrusion_followon_group(node_key, event)
            followon_groups[group_key] = group
        else:
            _update_intrusion_followon_group(group, event)
        if event_ref:
            _append_bounded_unique(group["event_refs"], event_ref, 16)

    process_entries = [
        _intrusion_process_entry(
            nodes[key],
            role=(
                "origin_candidate"
                if key == origin_key
                else "suspicious_descendant"
                if key in signal_keys
                else "descendant_context"
            ),
            nodes=nodes,
        )
        for key in sorted(relevant_keys, key=lambda key: _intrusion_node_sort_key(nodes[key]))
    ]
    steps = [
        _intrusion_process_step(
            nodes[key],
            origin=(key == origin_key),
            suspicious=(key in signal_keys),
            nodes=nodes,
        )
        for key in relevant_keys
    ]
    for event in selected_suspicious:
        event_ref = str(event.get("event_ref") or "")
        node_key = event_node_keys.get(event_ref)
        if node_key not in relevant_set:
            continue
        if str(event.get("event_id") or "") in {"1", "3", "22", "4688", "5156"}:
            continue
        steps.append(_intrusion_suspicious_step(event, nodes[node_key]))
    steps.extend(
        _intrusion_followon_step(group, nodes[group["node_key"]])
        for group in followon_groups.values()
    )
    steps, omitted_step_count = _limit_intrusion_steps(steps)

    component_rules = sorted(
        {
            rule_id
            for key in primary_signal_keys
            for rule_id in nodes[key].rule_ids
        }
    )
    component_refs = sorted(
        {
            event_ref
            for key in primary_signal_keys
            for event_ref in nodes[key].event_refs
        }
    )
    confidence = _intrusion_linkage_confidence(
        origin,
        primary_signal_keys,
        nodes,
        component_rules,
    )
    parent_context = _intrusion_parent_context(origin, nodes)
    origin_basis = _intrusion_origin_basis(
        origin,
        primary_signal_keys,
        nodes,
        component_rules,
    )
    alternatives = [
        _intrusion_origin_candidate(nodes[root], members, nodes)
        for _, root, members in ranked_candidates[1 : 1 + INTRUSION_ORIGIN_ALTERNATIVE_LIMIT]
    ]
    limitations = list(base_limitations)
    if unresolved_parent_count:
        limitations.append(
            f"부모 프로세스 생성 이벤트가 없거나 안전하게 연결되지 않은 노드가 {unresolved_parent_count}개입니다."
        )
    if pid_parent_link_count:
        limitations.append(
            f"{pid_parent_link_count}개 부모 연결은 ProcessGuid가 없어 동일 호스트·PID·이미지·시간창으로 보조 연결했습니다. PID 재사용 가능성을 확인해야 합니다."
        )
    if descendant_limit_reached:
        limitations.append(
            f"후속 프로세스는 최대 {INTRUSION_CHAIN_PROCESS_LIMIT}개, 깊이 {INTRUSION_DESCENDANT_DEPTH_LIMIT}단계로 제한했습니다."
        )
    if omitted_followon_event_count:
        limitations.append(
            f"DNS/통신 그룹 상한 {INTRUSION_FOLLOWON_GROUP_LIMIT}개를 넘어 최소 {omitted_followon_event_count}개 후속 이벤트 상세를 생략했습니다."
        )
    if omitted_step_count:
        limitations.append(
            f"연대기 단계는 최대 {INTRUSION_CHAIN_STEP_LIMIT}개 대표 단계로 제한되어 {omitted_step_count}개 단계를 생략했습니다."
        )

    source_metadata["followon_record_count_scanned"] = followon_record_count
    source_metadata["followon_group_count"] = len(followon_groups)
    source_metadata["followon_group_limit"] = INTRUSION_FOLLOWON_GROUP_LIMIT
    truncated = bool(
        process_node_limit_reached
        or suspicious_event_limit_reached
        or descendant_limit_reached
        or omitted_followon_event_count
        or omitted_step_count
        or not network_scan_complete
        or network_spool_limit_reached
    )
    evidence_refs = sorted(
        {
            event_ref
            for step in steps
            for event_ref in step.get("event_refs") or []
        }
        | set(component_refs)
    )
    source_refs = sorted(
        {
            source_ref
            for step in steps
            for source_ref in step.get("source_refs") or []
            if source_ref
        }
    )
    return {
        "schema_version": 1,
        "status": "origin_process_candidate_identified",
        "candidate_only": True,
        "selection_method": (
            "ProcessGuid/부모 계보와 의심 규칙·로컬 명령 신호가 가장 강하게 연결된 "
            "후보 묶음을 선택한 뒤 그 안의 가장 이른 의심 프로세스를 시작 후보로 지정"
        ),
        "confidence": confidence,
        "confidence_scope": "프로세스 및 이벤트 연결 신뢰도이며 악성 여부 신뢰도가 아닙니다.",
        "origin_process": {
            **_intrusion_process_entry(
                origin,
                role="origin_candidate",
                nodes=nodes,
            ),
            "confirmed": False,
            "assessment": "현재 증거에서 가장 이른 침해 시작 프로세스 후보이며 악성 여부는 미확정입니다.",
            "basis": origin_basis,
            "parent_context": parent_context,
        },
        "alternative_origin_candidates": alternatives,
        "component_rule_ids": component_rules,
        "processes": process_entries,
        "steps": steps,
        "evidence_refs": evidence_refs,
        "source_refs": source_refs,
        "source": source_metadata,
        "truncated": truncated,
        "chain_truncated": truncated,
        "limitations": limitations,
    }


def _intrusion_process_node(event: EventRecord) -> _IntrusionProcessNode | None:
    host = str(event.computer or "")
    host_key = _normalized_host(host)
    process_guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    process_id = _process_id(event)
    process = _process(event)
    if not (process_guid or process_id or process):
        return None
    source_ref = _intrusion_source_ref(
        event.source_file,
        event.record_id,
        event.time_created,
    )
    if process_guid:
        key = ("guid", host_key, process_guid)
        instance_id = f"guid:{host_key}|{process_guid}"
    else:
        key = (
            "pid",
            host_key,
            process_id or "",
            isoformat_utc(event.time_created) or "time-unknown",
            event.source_file,
            str(event.record_id or ""),
        )
        instance_id = "start:" + "|".join(key[1:])
    return _IntrusionProcessNode(
        key=key,
        process_instance_id=instance_id,
        host=host,
        process=process,
        process_id=process_id,
        process_guid=process_guid,
        start_time=event.time_created,
        source_file=event.source_file,
        record_id=event.record_id,
        event_id=event.event_id,
        account=_account(event),
        command_line=_truncate(_command_line(event), 600),
        hashes=_truncate(_field(event, "Hashes"), 600),
        parent_process=_parent_process(event),
        parent_process_id=_parent_process_id(event),
        parent_process_guid=_normalized_process_guid(
            _field(event, "ParentProcessGuid")
        ),
        source_ref=source_ref,
        local_signals=_intrusion_local_process_signals(event),
    )


def _intrusion_observed_process_node(
    event: dict[str, Any],
) -> _IntrusionProcessNode | None:
    fields = event.get("fields") or {}
    host = str(event.get("host") or "")
    host_key = _normalized_host(host)
    process_guid = _normalized_process_guid(
        event.get("process_guid") or fields.get("ProcessGuid")
    )
    process_id = _intrusion_dict_process_id(event)
    process = event.get("process") or fields.get("Image") or fields.get("NewProcessName")
    if not (process_guid or process_id or process):
        return None
    event_ref = str(event.get("event_ref") or "unknown")
    if process_guid:
        key = ("guid", host_key, process_guid)
        instance_id = f"guid:{host_key}|{process_guid}"
    else:
        key = (
            "observed",
            host_key,
            process_id or "",
            _windows_basename(process),
            str(event.get("time") or "time-unknown"),
            event_ref,
        )
        instance_id = "observed:" + "|".join(key[1:])
    start_time = _parse_analysis_time(event.get("time"))
    source_file = str(event.get("source_file") or "")
    record_id = str(event.get("record_id") or "") or None
    return _IntrusionProcessNode(
        key=key,
        process_instance_id=instance_id,
        host=host,
        process=str(process) if process else None,
        process_id=process_id,
        process_guid=process_guid,
        start_time=start_time,
        source_file=source_file,
        record_id=record_id,
        event_id=str(event.get("event_id") or "") or None,
        account=str(event.get("account") or "") or None,
        command_line=_truncate(str(event.get("command_line") or "") or None, 600),
        hashes=_truncate(str(fields.get("Hashes") or "") or None, 600),
        parent_process=_intrusion_dict_parent_process(event),
        parent_process_id=_intrusion_dict_parent_process_id(event),
        parent_process_guid=_normalized_process_guid(fields.get("ParentProcessGuid")),
        source_ref=_intrusion_source_ref(source_file, record_id, start_time),
        creation_observed=False,
    )


def _intrusion_dict_process_id(event: dict[str, Any]) -> str | None:
    fields = event.get("fields") or {}
    if str(event.get("event_id") or "") == "4688":
        return _normalized_process_id(
            fields.get("NewProcessId")
            or event.get("process_id")
            or fields.get("ProcessID")
            or fields.get("ProcessId")
        )
    return _normalized_process_id(
        event.get("process_id")
        or fields.get("ProcessId")
        or fields.get("ProcessID")
        or fields.get("NewProcessId")
    )


def _intrusion_dict_parent_process_id(event: dict[str, Any]) -> str | None:
    fields = event.get("fields") or {}
    if str(event.get("event_id") or "") == "4688":
        return _normalized_process_id(
            fields.get("CreatorProcessId")
            or fields.get("ProcessId")
            or fields.get("ParentProcessId")
        )
    return _normalized_process_id(fields.get("ParentProcessId"))


def _intrusion_dict_parent_process(event: dict[str, Any]) -> str | None:
    fields = event.get("fields") or {}
    if str(event.get("event_id") or "") == "4688":
        value = (
            fields.get("CreatorProcessName")
            or fields.get("ParentProcessName")
            or fields.get("ParentImage")
        )
    else:
        value = fields.get("ParentImage") or fields.get("ParentProcessName")
    return str(value) if value else None


def _intrusion_local_process_signals(event: EventRecord) -> list[str]:
    signals: list[str] = []
    if _event_has_suspicious_command(event):
        signals.append("프로세스 생성 이벤트의 의심 명령줄 패턴")
    process_name = _windows_basename(_process(event))
    parent_name = _windows_basename(_parent_process(event))
    if process_name in KNOWN_TUNNEL_CLIENTS:
        signals.append(f"터널링 도구로 자주 사용되는 실행 파일명 {process_name}")
    if (
        process_name in SCRIPT_OR_LOLBIN_NETWORK_CLIENTS
        and parent_name in SUSPICIOUS_NETWORK_PARENT_PROCESSES
    ):
        signals.append(
            f"{parent_name} 부모가 스크립트/LOLBIN 프로세스 {process_name} 실행"
        )
    return signals


def _intrusion_process_indexes(
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> tuple[
    dict[tuple[str, str], tuple[str, ...]],
    dict[tuple[str, str], list[tuple[str, ...]]],
    dict[tuple[str, ...], tuple[str, ...]],
]:
    guid_index: dict[tuple[str, str], tuple[str, ...]] = {}
    pid_index: dict[tuple[str, str], list[tuple[str, ...]]] = defaultdict(list)
    raw_index: dict[tuple[str, ...], tuple[str, ...]] = {}
    for key, node in nodes.items():
        host = _normalized_host(node.host)
        if node.process_guid:
            guid_index[(host, node.process_guid)] = key
        if node.process_id:
            pid_index[(host, node.process_id)].append(key)
        if node.creation_observed:
            raw_index[
                _intrusion_raw_parts_identity(
                    node.source_file,
                    node.record_id,
                    node.event_id,
                    node.start_time,
                    node.host,
                )
            ] = key
    for keys in pid_index.values():
        keys.sort(key=lambda key: _intrusion_node_sort_key(nodes[key]))
    return guid_index, pid_index, raw_index


def _intrusion_node_for_evidence(
    event: dict[str, Any],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    guid_index: dict[tuple[str, str], tuple[str, ...]],
    pid_index: dict[tuple[str, str], list[tuple[str, ...]]],
) -> tuple[str, ...] | None:
    fields = event.get("fields") or {}
    host = _normalized_host(event.get("host"))
    guid = _normalized_process_guid(
        event.get("process_guid") or fields.get("ProcessGuid")
    )
    if guid and (host, guid) in guid_index:
        return guid_index[(host, guid)]
    pid = _intrusion_dict_process_id(event)
    if not pid:
        return None
    return _intrusion_pid_candidate(
        event_time=_parse_analysis_time(event.get("time")),
        image=event.get("process"),
        candidates=pid_index.get((host, pid), []),
        nodes_by_key=nodes,
    )


def _intrusion_pid_candidate(
    *,
    event_time: datetime | None,
    image: Any,
    candidates: list[tuple[str, ...]],
    nodes_by_key: dict[tuple[str, ...], _IntrusionProcessNode],
) -> tuple[str, ...] | None:
    target_image = _windows_basename(image)
    selected: tuple[str, ...] | None = None
    selected_time: datetime | None = None
    for key in candidates:
        node = nodes_by_key[key]
        if target_image and _windows_basename(node.process) != target_image:
            continue
        if event_time is None or node.start_time is None:
            continue
        delta = (_as_utc(event_time) - _as_utc(node.start_time)).total_seconds()
        if delta < 0 or delta > INTRUSION_PID_LINK_WINDOW_SECONDS:
            continue
        if selected_time is None or _as_utc(node.start_time) > _as_utc(selected_time):
            selected = key
            selected_time = node.start_time
    return selected


def _link_intrusion_process_nodes(
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    guid_index: dict[tuple[str, str], tuple[str, ...]],
    pid_index: dict[tuple[str, str], list[tuple[str, ...]]],
) -> tuple[int, int]:
    unresolved = 0
    pid_links = 0
    for node in nodes.values():
        parent_key: tuple[str, ...] | None = None
        link_basis: str | None = None
        if node.parent_process_guid:
            candidate = guid_index.get(
                (_normalized_host(node.host), node.parent_process_guid)
            )
            if candidate != node.key and candidate is not None:
                parent = nodes[candidate]
                if (
                    node.start_time is None
                    or parent.start_time is None
                    or _as_utc(parent.start_time) <= _as_utc(node.start_time)
                ):
                    parent_key = candidate
                    link_basis = "동일 호스트의 ParentProcessGuid/ProcessGuid 정확 일치"
        elif node.parent_process_id and node.start_time is not None:
            parent_key = _intrusion_pid_candidate(
                event_time=node.start_time,
                image=node.parent_process,
                candidates=pid_index.get(
                    (_normalized_host(node.host), node.parent_process_id),
                    [],
                ),
                nodes_by_key=nodes,
            )
            if parent_key == node.key:
                parent_key = None
            if parent_key is not None:
                link_basis = (
                    "ProcessGuid 부재: 동일 호스트·부모 PID·이미지·60분 시간창 일치"
                )
                pid_links += 1
        if parent_key is None and (
            node.parent_process_guid
            or node.parent_process_id
            or node.parent_process
        ):
            unresolved += 1
        node.parent_key = parent_key
        node.parent_link_basis = link_basis
    return unresolved, pid_links


def _intrusion_suspicious_root(
    node_key: tuple[str, ...],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    signal_keys: set[tuple[str, ...]],
) -> tuple[str, ...]:
    root = node_key
    current = node_key
    seen = {node_key}
    while True:
        parent_key = nodes[current].parent_key
        if parent_key is None or parent_key in seen or parent_key not in nodes:
            return root
        seen.add(parent_key)
        if parent_key in signal_keys:
            root = parent_key
        current = parent_key


def _intrusion_candidate_score(
    origin: _IntrusionProcessNode,
    member_keys: list[tuple[str, ...]],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> int:
    # The score ranks candidate components only; it is never exposed as a
    # probability or maliciousness score.
    members = [nodes[key] for key in member_keys]
    rule_ids = {rule for node in members for rule in node.rule_ids}
    severities = {severity for node in members for severity in node.severities}
    event_refs = {ref for node in members for ref in node.event_refs}
    has_execution = bool(
        origin.local_signals
        or any(
            rule == "suspicious_powershell"
            or rule.startswith("suspicious_process_")
            for rule in rule_ids
        )
    )
    has_network = bool(
        rule_ids
        & {
            "suspicious_network_connection",
            "possible_network_beacon",
            "suspicious_dns_network_activity",
            "possible_process_fanout",
        }
    )
    severity_score = max(
        (SEVERITY_RANK.get(value, 0) for value in severities),
        default=0,
    )
    return (
        severity_score * 20
        + min(len(event_refs), 12) * 3
        + min(len(rule_ids), 8) * 5
        + min(len(member_keys), 8) * 4
        + sum(min(len(node.local_signals), 2) * 8 for node in members)
        + (35 if has_execution and has_network else 0)
        + (5 if origin.process_guid else 0)
    )

def _intrusion_children_index(
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> dict[tuple[str, ...], list[tuple[str, ...]]]:
    children: dict[tuple[str, ...], list[tuple[str, ...]]] = defaultdict(list)
    for key, node in nodes.items():
        if node.parent_key in nodes:
            children[node.parent_key].append(key)
    for values in children.values():
        values.sort(key=lambda key: _intrusion_node_sort_key(nodes[key]))
    return children


def _intrusion_relevant_processes(
    origin_key: tuple[str, ...],
    primary_signal_keys: list[tuple[str, ...]],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    children: dict[tuple[str, ...], list[tuple[str, ...]]],
) -> tuple[list[tuple[str, ...]], bool]:
    relevant: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()

    def add(key: tuple[str, ...]) -> bool:
        if key in seen:
            return True
        if len(relevant) >= INTRUSION_CHAIN_PROCESS_LIMIT:
            return False
        seen.add(key)
        relevant.append(key)
        return True

    add(origin_key)
    limit_reached = False
    # Preserve every path that supports the selected candidate before adding
    # contextual descendants.
    for signal_key in sorted(
        primary_signal_keys,
        key=lambda key: _intrusion_node_sort_key(nodes[key]),
    ):
        path: list[tuple[str, ...]] = []
        current: tuple[str, ...] | None = signal_key
        visited: set[tuple[str, ...]] = set()
        while current is not None and current in nodes and current not in visited:
            visited.add(current)
            path.append(current)
            if current == origin_key:
                break
            current = nodes[current].parent_key
        for key in reversed(path):
            if not add(key):
                limit_reached = True

    queue: deque[tuple[tuple[str, ...], int]] = deque([(origin_key, 0)])
    walked: set[tuple[str, ...]] = set()
    while queue:
        parent_key, depth = queue.popleft()
        if parent_key in walked:
            continue
        walked.add(parent_key)
        child_keys = children.get(parent_key, [])
        if depth >= INTRUSION_DESCENDANT_DEPTH_LIMIT:
            if child_keys:
                limit_reached = True
            continue
        for child_key in child_keys:
            if not add(child_key):
                limit_reached = True
                continue
            queue.append((child_key, depth + 1))
    return relevant, limit_reached


def _intrusion_process_for_event(
    event: EventRecord,
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    guid_index: dict[tuple[str, str], tuple[str, ...]],
    pid_index: dict[tuple[str, str], list[tuple[str, ...]]],
) -> tuple[str, ...] | None:
    host = _normalized_host(event.computer)
    guid = _normalized_process_guid(_field(event, "ProcessGuid"))
    if guid:
        return guid_index.get((host, guid))
    pid = _normalized_process_id(_field(event, "ProcessId", "ProcessID"))
    if not pid:
        return None
    return _intrusion_pid_candidate(
        event_time=event.time_created,
        image=_process(event),
        candidates=pid_index.get((host, pid), []),
        nodes_by_key=nodes,
    )


def _intrusion_followon_key(
    node_key: tuple[str, ...],
    event: EventRecord,
) -> tuple[str, ...]:
    if _is_dns_query_event(event):
        return (
            "dns",
            *node_key,
            _normalized_domain(_field(event, "QueryName")),
        )
    return (
        "network",
        *node_key,
        _normalized_domain(_field(event, "DestinationHostname"))
        or _normalized_ip(_destination_ip(event))
        or str(_destination_ip(event) or "").casefold(),
        str(_normalized_port(_destination_port(event)) or ""),
        _normalized_protocol(_field(event, "Protocol")) or "",
        _network_direction(event, _normalized_boolean(_field(event, "Initiated")))
        or "",
    )


def _new_intrusion_followon_group(
    node_key: tuple[str, ...],
    event: EventRecord,
) -> dict[str, Any]:
    time_value = event.time_created
    return {
        "node_key": node_key,
        "event_kind": "dns_query" if _is_dns_query_event(event) else "network_connection",
        "event_count": 1,
        "first_seen": time_value,
        "last_seen": time_value,
        "query_name": _field(event, "QueryName"),
        "query_results": _truncate(_field(event, "QueryResults"), 600),
        "destination_ip": _destination_ip(event),
        "destination_hostname": _field(event, "DestinationHostname"),
        "destination_port": _normalized_port(_destination_port(event)),
        "protocol": _normalized_protocol(_field(event, "Protocol")),
        "network_direction": _network_direction(
            event,
            _normalized_boolean(_field(event, "Initiated")),
        ),
        "external_destination": _is_external_destination(
            _destination_ip(event),
            _field(event, "DestinationHostname"),
        ),
        "event_refs": [],
        "source_refs": [
            _intrusion_source_ref(
                event.source_file,
                event.record_id,
                event.time_created,
            )
        ],
        "sample": _intrusion_event_snapshot(event),
    }


def _update_intrusion_followon_group(
    group: dict[str, Any],
    event: EventRecord,
) -> None:
    group["event_count"] = int(group.get("event_count") or 0) + 1
    event_time = event.time_created
    first_seen = group.get("first_seen")
    last_seen = group.get("last_seen")
    source_ref = _intrusion_source_ref(
        event.source_file,
        event.record_id,
        event.time_created,
    )
    if event_time is not None and (
        first_seen is None or _as_utc(event_time) < _as_utc(first_seen)
    ):
        group["first_seen"] = event_time
        group["sample"] = _intrusion_event_snapshot(event)
        if group["source_refs"]:
            group["source_refs"][0] = source_ref
    if event_time is not None and (
        last_seen is None or _as_utc(event_time) > _as_utc(last_seen)
    ):
        group["last_seen"] = event_time
        if len(group["source_refs"]) == 1:
            group["source_refs"].append(source_ref)
        else:
            group["source_refs"][-1] = source_ref


def _intrusion_process_entry(
    node: _IntrusionProcessNode,
    *,
    role: str,
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> dict[str, Any]:
    parent = nodes.get(node.parent_key) if node.parent_key else None
    return {
        "role": role,
        "process_instance_id": node.process_instance_id,
        "host": node.host or None,
        "start_time": isoformat_utc(node.start_time),
        "process": node.process,
        "process_id": node.process_id,
        "process_guid": node.process_guid,
        "command_line": node.command_line,
        "account": node.account,
        "hashes": node.hashes,
        "creation_event_observed": node.creation_observed,
        "parent_process_instance_id": parent.process_instance_id if parent else None,
        "parent_process": node.parent_process or (parent.process if parent else None),
        "parent_process_id": node.parent_process_id,
        "parent_process_guid": node.parent_process_guid,
        "parent_link_basis": node.parent_link_basis,
        "signals": list(node.local_signals),
        "rule_ids": sorted(node.rule_ids),
        "event_refs": sorted(node.event_refs),
        "source_ref": node.source_ref,
    }


def _intrusion_process_step(
    node: _IntrusionProcessNode,
    *,
    origin: bool,
    suspicious: bool,
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> dict[str, Any]:
    parent = nodes.get(node.parent_key) if node.parent_key else None
    if origin:
        assessment = "가장 이른 침해 시작 프로세스 후보; 악성 여부 미확정"
        event_kind = "origin_process_candidate"
    elif suspicious:
        assessment = "시작 후보의 후속 프로세스이며 의심 규칙 또는 로컬 실행 신호와 연결됨"
        event_kind = "suspicious_child_process"
    else:
        assessment = "시작 후보의 후속 자식 프로세스로 관측됨; 악성 여부 확인되지 않음"
        event_kind = "child_process_context"
    return {
        "time": isoformat_utc(node.start_time),
        "event_kind": event_kind,
        "phase": "침해 시작 후보" if origin else "후속 프로세스 실행",
        "assessment": assessment,
        "process_instance_id": node.process_instance_id,
        "parent_process_instance_id": parent.process_instance_id if parent else None,
        "relationship_basis": node.parent_link_basis,
        "host": node.host or None,
        "process": node.process,
        "process_id": node.process_id,
        "process_guid": node.process_guid,
        "command_line": node.command_line,
        "parent_process": node.parent_process,
        "event_id": node.event_id,
        "event_count": 1,
        "event_refs": sorted(node.creation_event_refs),
        "source_refs": [node.source_ref] if node.source_ref else [],
    }


def _intrusion_suspicious_step(
    event: dict[str, Any],
    node: _IntrusionProcessNode,
) -> dict[str, Any]:
    titles = [
        str(reason.get("title"))
        for reason in event.get("reasons") or []
        if isinstance(reason, dict) and reason.get("title")
    ]
    return {
        "time": event.get("time"),
        "event_kind": "suspicious_activity",
        "phase": _scenario_phase(event.get("rule_ids") or []),
        "assessment": "; ".join(titles[:3]) or "규칙 기반 의심 활동",
        "process_instance_id": node.process_instance_id,
        "host": event.get("host"),
        "process": event.get("process"),
        "process_id": event.get("process_id"),
        "process_guid": event.get("process_guid"),
        "command_line": event.get("command_line"),
        "event_id": event.get("event_id"),
        "event_count": 1,
        "event_refs": [event["event_ref"]] if event.get("event_ref") else [],
        "source_refs": [
            _intrusion_source_ref(
                str(event.get("source_file") or ""),
                str(event.get("record_id") or "") or None,
                _parse_analysis_time(event.get("time")),
            )
        ],
    }


def _intrusion_followon_step(
    group: dict[str, Any],
    node: _IntrusionProcessNode,
) -> dict[str, Any]:
    event_kind = str(group["event_kind"])
    linked_to_finding = bool(group.get("event_refs"))
    return {
        "time": isoformat_utc(group.get("first_seen")),
        "last_seen": isoformat_utc(group.get("last_seen")),
        "event_kind": event_kind,
        "phase": "DNS 질의" if event_kind == "dns_query" else "후속 네트워크 통신",
        "assessment": (
            "규칙 기반 의심 이벤트와 연결된 관측; 악성/C2 여부는 별도 검증 필요"
            if linked_to_finding
            else "프로세스 계보에 연결된 관측; 정상 가능성이 있으며 악성 여부 확인되지 않음"
        ),
        "process_instance_id": node.process_instance_id,
        "host": node.host or None,
        "process": node.process,
        "process_id": node.process_id,
        "process_guid": node.process_guid,
        "query_name": group.get("query_name"),
        "query_results": group.get("query_results"),
        "destination_ip": group.get("destination_ip"),
        "destination_hostname": group.get("destination_hostname"),
        "destination_port": group.get("destination_port"),
        "protocol": group.get("protocol"),
        "network_direction": group.get("network_direction"),
        "external_destination": group.get("external_destination"),
        "event_count": group.get("event_count"),
        "event_refs": sorted(group.get("event_refs") or []),
        "source_refs": list(group.get("source_refs") or []),
        "sample_evidence": group.get("sample"),
    }


def _limit_intrusion_steps(
    steps: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    ordered = sorted(
        steps,
        key=lambda item: (
            item.get("time") is None,
            item.get("time") or "",
            item.get("event_kind") or "",
            item.get("process_instance_id") or "",
            str(item.get("destination_ip") or item.get("query_name") or ""),
        ),
    )
    if len(ordered) <= INTRUSION_CHAIN_STEP_LIMIT:
        for index, item in enumerate(ordered, start=1):
            item["order"] = index
        return ordered, 0

    essential_indexes: set[int] = {0, len(ordered) - 1}
    first_by_kind: dict[str, int] = {}
    for index, item in enumerate(ordered):
        kind = str(item.get("event_kind") or "")
        if kind not in first_by_kind:
            first_by_kind[kind] = index
        if kind == "origin_process_candidate":
            essential_indexes.add(index)
    essential_indexes.update(first_by_kind.values())
    priority_indexes = [
        index
        for index, item in enumerate(ordered)
        if item.get("event_refs") and index not in essential_indexes
    ]
    available = INTRUSION_CHAIN_STEP_LIMIT - len(essential_indexes)
    selected = set(essential_indexes)
    selected.update(_intrusion_evenly_spaced(priority_indexes, max(0, available)))
    available = INTRUSION_CHAIN_STEP_LIMIT - len(selected)
    remaining = [index for index in range(len(ordered)) if index not in selected]
    selected.update(_intrusion_evenly_spaced(remaining, max(0, available)))
    limited = [ordered[index] for index in sorted(selected)]
    for index, item in enumerate(limited, start=1):
        item["order"] = index
    return limited, len(ordered) - len(limited)


def _intrusion_evenly_spaced(indexes: list[int], limit: int) -> list[int]:
    if limit <= 0 or not indexes:
        return []
    if len(indexes) <= limit:
        return list(indexes)
    if limit == 1:
        return [indexes[0]]
    positions = {
        round(position * (len(indexes) - 1) / (limit - 1))
        for position in range(limit)
    }
    return [indexes[position] for position in sorted(positions)]


def _intrusion_linkage_confidence(
    origin: _IntrusionProcessNode,
    signal_keys: list[tuple[str, ...]],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    rule_ids: list[str],
) -> str:
    has_execution = bool(
        origin.local_signals
        or any(
            rule == "suspicious_powershell"
            or rule.startswith("suspicious_process_")
            for rule in rule_ids
        )
    )
    has_network = bool(
        set(rule_ids)
        & {
            "suspicious_network_connection",
            "possible_network_beacon",
            "suspicious_dns_network_activity",
            "possible_process_fanout",
        }
    )
    exact_child_link = any(
        nodes[key].parent_link_basis
        and "ParentProcessGuid" in str(nodes[key].parent_link_basis)
        for key in signal_keys
        if key != origin.key
    )
    if origin.process_guid and has_execution and has_network and exact_child_link:
        return "high"
    if origin.process_guid and (has_execution or has_network) and len(signal_keys) >= 1:
        return "medium"
    return "low"


def _intrusion_origin_basis(
    origin: _IntrusionProcessNode,
    signal_keys: list[tuple[str, ...]],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
    rule_ids: list[str],
) -> list[str]:
    basis = list(origin.local_signals)
    if origin.event_refs:
        basis.append(
            f"직접 연결된 의심 이벤트 참조 {', '.join(sorted(origin.event_refs)[:8])}"
        )
    exact_descendants = sum(
        1
        for key in signal_keys
        if key != origin.key
        and nodes[key].parent_link_basis
        and "ParentProcessGuid" in str(nodes[key].parent_link_basis)
    )
    if exact_descendants:
        basis.append(
            f"ParentProcessGuid로 연결된 후속 의심 프로세스 {exact_descendants}개"
        )
    network_rules = sorted(
        set(rule_ids)
        & {
            "suspicious_network_connection",
            "possible_network_beacon",
            "suspicious_dns_network_activity",
            "possible_process_fanout",
        }
    )
    if network_rules:
        basis.append(f"후속 DNS/통신 규칙 연결: {', '.join(network_rules)}")
    if not basis:
        basis.append("프로세스 식별자와 시간으로 의심 이벤트에 연결됨")
    return basis[:8]


def _intrusion_parent_context(
    origin: _IntrusionProcessNode,
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> dict[str, Any] | None:
    parent = nodes.get(origin.parent_key) if origin.parent_key else None
    if parent is not None:
        return {
            "process_instance_id": parent.process_instance_id,
            "start_time": isoformat_utc(parent.start_time),
            "process": parent.process,
            "process_id": parent.process_id,
            "process_guid": parent.process_guid,
            "relationship_basis": origin.parent_link_basis,
            "maliciousness_assessed": False,
            "note": "부모 계보 문맥이며 부모 프로세스 자체를 악성으로 판정하지 않습니다.",
            "source_ref": parent.source_ref,
        }
    if not (
        origin.parent_process
        or origin.parent_process_id
        or origin.parent_process_guid
    ):
        return None
    return {
        "process_instance_id": None,
        "start_time": None,
        "process": origin.parent_process,
        "process_id": origin.parent_process_id,
        "process_guid": origin.parent_process_guid,
        "relationship_basis": "자식 생성 이벤트의 부모 필드만 관측됨",
        "maliciousness_assessed": False,
        "note": "부모 생성 이벤트가 없어 계보 문맥만 제공하며 악성 여부는 판단할 수 없습니다.",
        "source_ref": None,
    }


def _intrusion_origin_candidate(
    origin: _IntrusionProcessNode,
    member_keys: list[tuple[str, ...]],
    nodes: dict[tuple[str, ...], _IntrusionProcessNode],
) -> dict[str, Any]:
    return {
        "process_instance_id": origin.process_instance_id,
        "start_time": isoformat_utc(origin.start_time),
        "host": origin.host or None,
        "process": origin.process,
        "process_id": origin.process_id,
        "process_guid": origin.process_guid,
        "linked_signal_process_count": len(member_keys),
        "event_refs": sorted(
            {
                event_ref
                for key in member_keys
                for event_ref in nodes[key].event_refs
            }
        )[:16],
        "assessment": "별도 시작 프로세스 후보이며 악성 여부 미확정",
    }


def _intrusion_event_snapshot(event: EventRecord) -> dict[str, Any]:
    return {
        "time": isoformat_utc(event.time_created),
        "source_file": event.source_file,
        "record_id": event.record_id,
        "event_id": event.event_id,
        "host": event.computer,
        "account": _account(event),
        "process": _process(event),
        "process_id": _process_id(event),
        "process_guid": _normalized_process_guid(_field(event, "ProcessGuid")),
        "command_line": _truncate(_command_line(event), 300),
        "query_name": _field(event, "QueryName"),
        "query_results": _truncate(_field(event, "QueryResults"), 300),
        "destination_ip": _destination_ip(event),
        "destination_hostname": _field(event, "DestinationHostname"),
        "destination_port": _normalized_port(_destination_port(event)),
        "protocol": _normalized_protocol(_field(event, "Protocol")),
    }


def _intrusion_node_sort_key(
    node: _IntrusionProcessNode,
) -> tuple[bool, str, str, str]:
    return (
        node.start_time is None,
        isoformat_utc(node.start_time) or "",
        node.source_file,
        str(node.record_id or node.process_instance_id),
    )


def _intrusion_source_ref(
    source_file: str,
    record_id: str | None,
    time_value: datetime | None,
) -> str:
    identity = str(record_id or isoformat_utc(time_value) or "unknown")
    return f"{source_file or 'source-unknown'}#{identity}"


def _intrusion_raw_event_identity(event: EventRecord) -> tuple[str, ...]:
    return _intrusion_raw_parts_identity(
        event.source_file,
        event.record_id,
        event.event_id,
        event.time_created,
        _normalized_host(event.computer),
    )


def _intrusion_raw_dict_identity(event: dict[str, Any]) -> tuple[str, ...]:
    return _intrusion_raw_parts_identity(
        str(event.get("source_file") or ""),
        str(event.get("record_id") or "") or None,
        str(event.get("event_id") or "") or None,
        _parse_analysis_time(event.get("time")),
        _normalized_host(event.get("host")),
    )


def _intrusion_raw_parts_identity(
    source_file: str,
    record_id: str | None,
    event_id: str | None,
    time_value: datetime | None,
    host: str,
) -> tuple[str, ...]:
    return (
        source_file,
        str(record_id or ""),
        str(event_id or ""),
        isoformat_utc(time_value) or "",
        _normalized_host(host),
    )


def _append_bounded_unique(values: list[str], value: str, limit: int) -> None:
    if value and value not in values and len(values) < limit:
        values.append(value)


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
        "possible_process_fanout",
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
        "possible_process_fanout": "프로세스 단시간 다수 목적지 통신 후보",
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
    event_count: int | None = None,
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
        "event_count": max(len(events), int(event_count or 0)),
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
            "CreatorProcessName",
            "CreatorProcessId",
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
        "process_id": _process_id(event),
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


def _is_process_termination_event(event: EventRecord) -> bool:
    if _event_id(event) == "4689":
        return _is_security_event(event)
    if _event_id(event) != "5":
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
        "possible_process_fanout",
    }:
        return {
            "cause_focus": "ProcessGuid를 우선으로 Sysmon 1/3/5/22와 Security 4688/4689/5156을 연결하고 프로세스 수명, Image, CommandLine, DestinationIp/Port/Hostname, QueryName/QueryResults를 원인 후보로 추적합니다.",
            "observed_behavior": "외부·비로컬 목적지, 고위험 포트, 사용자 쓰기 가능 경로, 터널링 도구, DNS 응답 IP 연결, 반복 주기성 또는 단시간 다수 목적지 중 하나 이상의 구체적 통신 신호가 관찰되었습니다. C2 점수는 로컬 휴리스틱 우선순위입니다.",
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


def _process_id(event: EventRecord) -> str | None:
    # Security 4688 uses ProcessId for the creator and NewProcessId for the
    # process being created. Sysmon and network events use ProcessId/ProcessID
    # for the process described by the event.
    if _event_id(event) == "4688" and _is_security_event(event):
        return _normalized_process_id(
            _field(event, "NewProcessId", "ProcessID", "ProcessId")
        )
    return _normalized_process_id(
        _field(event, "ProcessId", "ProcessID", "NewProcessId")
    )


def _parent_process_id(event: EventRecord) -> str | None:
    if _event_id(event) == "4688" and _is_security_event(event):
        return _normalized_process_id(
            _field(event, "CreatorProcessId", "ProcessId", "ParentProcessId")
        )
    return _normalized_process_id(_field(event, "ParentProcessId"))


def _parent_process(event: EventRecord) -> str | None:
    if _event_id(event) == "4688" and _is_security_event(event):
        return _field(
            event,
            "CreatorProcessName",
            "ParentProcessName",
            "ParentImage",
        )
    return _field(event, "ParentImage", "ParentProcessName")


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


def _normalized_ip(value: Any) -> str | None:
    text = str(value or "").strip().strip("[]")
    if not text or text == "-":
        return None
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return address.compressed.casefold()


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
