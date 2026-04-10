"""
KronoTrace — Detection Engine
Rule-based threat detection with 5 algorithms:
1. Brute Force Detection
2. New IP Detection
3. Privilege Escalation
4. File Access Correlation (Anomaly)
5. Data Exfiltration Detection
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
import re


@dataclass
class Alert:
    """A detected threat/anomaly."""
    rule_name: str
    severity: str
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    timestamp: str = ''
    end_timestamp: str = ''
    source_ip: str = ''
    target: str = ''
    event_indices: List[int] = field(default_factory=list)
    confidence: float = 0.0
    mitre_tactic: str = ''
    mitre_technique: str = ''

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def _ts_diff_seconds(ts1: str, ts2: str) -> Optional[float]:
    dt1 = _parse_ts(ts1)
    dt2 = _parse_ts(ts2)
    if dt1 and dt2:
        return abs((dt2 - dt1).total_seconds())
    return None


def _is_private_ip(ip: str) -> bool:
    if not ip or ip in ('N/A', '-', '::1', '127.0.0.1', '0.0.0.0'):
        return True
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        return False
    except (ValueError, IndexError):
        return True


FAILED_AUTH_EVENTS = {
    '4625', '4771', 'SSH_LOGIN_FAILED', 'PAM_AUTH_FAIL',
    'AUTH_FAILED', 'SUDO_DENIED',
}

SUCCESS_AUTH_EVENTS = {
    '4624', 'SSH_LOGIN_SUCCESS', 'AUTH_SUCCESS', 'PAM_SESSION_OPEN',
}


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR 1: Brute Force Detection
# ═══════════════════════════════════════════════════════════════════════════════

def detect_brute_force(events: list, window_seconds: int = 300, threshold: int = 5) -> List[Alert]:
    alerts = []
    failed_by_source: Dict[str, List[Tuple[int, Any]]] = defaultdict(list)

    for idx, event in enumerate(events):
        if event.event_id in FAILED_AUTH_EVENTS or (
            event.category == 'authentication' and
            any(w in event.message.lower() for w in ['failed', 'failure', 'denied', 'invalid'])
        ):
            source_key = event.source_ip or event.username or 'unknown'
            if source_key not in ('unknown', '-', 'N/A'):
                failed_by_source[source_key].append((idx, event))

    for source, failed_events in failed_by_source.items():
        if len(failed_events) < threshold:
            continue

        i = 0
        while i < len(failed_events):
            window_events = [failed_events[i]]
            j = i + 1
            while j < len(failed_events):
                time_diff = _ts_diff_seconds(failed_events[i][1].timestamp, failed_events[j][1].timestamp)
                if time_diff is not None and time_diff <= window_seconds:
                    window_events.append(failed_events[j])
                    j += 1
                else:
                    break

            if len(window_events) >= threshold:
                first_event = window_events[0][1]
                last_event = window_events[-1][1]
                success_after = False
                for idx2, evt in enumerate(events):
                    if evt.event_id in SUCCESS_AUTH_EVENTS and evt.source_ip == source:
                        t_diff = _ts_diff_seconds(last_event.timestamp, evt.timestamp)
                        if t_diff is not None and 0 <= t_diff <= 600:
                            success_after = True
                            break

                severity = 'critical' if success_after else 'high'
                desc = f"Detected {len(window_events)} failed authentication attempts from {source} within {window_seconds}s"
                if success_after:
                    desc += " — FOLLOWED BY SUCCESSFUL LOGIN (possible compromise)"
                target_user = first_event.username
                if target_user:
                    desc += f" targeting user '{target_user}'"

                alerts.append(Alert(
                    rule_name='brute_force',
                    severity=severity,
                    title='Brute Force Attack Detected',
                    description=desc,
                    evidence=[f"{e.timestamp} - {e.event_id}: {e.message[:80]}" for _, e in window_events[:10]],
                    timestamp=first_event.timestamp,
                    end_timestamp=last_event.timestamp,
                    source_ip=source,
                    target=target_user or 'unknown',
                    event_indices=[idx for idx, _ in window_events],
                    confidence=min(0.5 + (len(window_events) - threshold) * 0.1, 1.0),
                    mitre_tactic='Credential Access',
                    mitre_technique='T1110 - Brute Force',
                ))
                i = j
            else:
                i += 1

    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR 2: New/Anomalous IP Detection
# ═══════════════════════════════════════════════════════════════════════════════

def detect_new_ip(events: list) -> List[Alert]:
    alerts = []
    ip_events: Dict[str, List[Tuple[int, Any]]] = defaultdict(list)

    for idx, event in enumerate(events):
        ip = event.source_ip
        if ip and ip not in ('', 'N/A', '-', '127.0.0.1', '::1', '0.0.0.0'):
            ip_events[ip].append((idx, event))

    if not ip_events:
        return alerts

    avg_count = sum(len(v) for v in ip_events.values()) / max(len(ip_events), 1)
    rarity_threshold = max(3, avg_count * 0.1)

    privileged_events = {
        '4672', '4673', '4674', '4720', '4726', '4728', '4732',
        '4719', '4739', '1102', 'SUDO_COMMAND', 'SSH_LOGIN_SUCCESS', '4624',
    }

    for ip, ip_event_list in ip_events.items():
        if len(ip_event_list) > rarity_threshold:
            continue

        priv_actions = [
            (idx, e) for idx, e in ip_event_list
            if e.event_id in privileged_events or
            e.severity in ('high', 'critical') or
            any(w in e.message.lower() for w in ['privilege', 'admin', 'root', 'sudo'])
        ]

        if priv_actions:
            first_event = ip_event_list[0][1]
            alerts.append(Alert(
                rule_name='new_ip',
                severity='high',
                title=f'Suspicious New IP: {ip}',
                description=(
                    f"IP {ip} appeared only {len(ip_event_list)} time(s) "
                    f"but performed {len(priv_actions)} privileged action(s). "
                    f"This may indicate unauthorized access from an unknown source."
                ),
                evidence=[f"{e.timestamp} - {e.event_id}: {e.message[:80]}" for _, e in priv_actions[:10]],
                timestamp=first_event.timestamp,
                source_ip=ip,
                target=first_event.hostname or first_event.username or '',
                event_indices=[idx for idx, _ in priv_actions],
                confidence=min(0.6 + (len(priv_actions) * 0.15), 0.95),
                mitre_tactic='Initial Access',
                mitre_technique='T1078 - Valid Accounts',
            ))

    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR 3: Privilege Escalation
# ═══════════════════════════════════════════════════════════════════════════════

def detect_privilege_escalation(events: list, escalation_window: int = 600) -> List[Alert]:
    alerts = []

    # Pattern 1: Failed auth -> Success + Privilege
    for idx, event in enumerate(events):
        if event.event_id not in FAILED_AUTH_EVENTS:
            continue
        source = event.source_ip or event.username
        if not source or source in ('-', 'N/A', 'unknown'):
            continue

        success_event = None
        privilege_event = None
        for j in range(idx + 1, min(idx + 200, len(events))):
            future = events[j]
            future_source = future.source_ip or future.username
            time_diff = _ts_diff_seconds(event.timestamp, future.timestamp)
            if time_diff is not None and time_diff > escalation_window:
                break
            if future_source == source:
                if future.event_id in SUCCESS_AUTH_EVENTS and not success_event:
                    success_event = (j, future)
                if future.event_id in ('4672', '4673', 'SUDO_COMMAND') and not privilege_event:
                    privilege_event = (j, future)

        if success_event and privilege_event:
            alerts.append(Alert(
                rule_name='privilege_escalation',
                severity='critical',
                title='Privilege Escalation Detected',
                description=(
                    f"Source {source}: Failed authentication at {event.timestamp}, "
                    f"followed by successful logon and privilege elevation within "
                    f"{escalation_window}s."
                ),
                evidence=[
                    f"FAIL: {event.timestamp} - {event.event_id}: {event.message[:60]}",
                    f"SUCCESS: {success_event[1].timestamp} - {success_event[1].event_id}",
                    f"PRIVILEGE: {privilege_event[1].timestamp} - {privilege_event[1].event_id}",
                ],
                timestamp=event.timestamp,
                end_timestamp=privilege_event[1].timestamp,
                source_ip=event.source_ip,
                target=event.username or success_event[1].username or '',
                event_indices=[idx, success_event[0], privilege_event[0]],
                confidence=0.85,
                mitre_tactic='Privilege Escalation',
                mitre_technique='T1068 - Exploitation for Privilege Escalation',
            ))

    # Pattern 2: Rapid account management
    account_mgmt_events = {
        '4720': 'created', '4722': 'enabled', '4724': 'password reset',
        '4726': 'deleted', '4728': 'added to group', '4732': 'added to local group',
    }
    mgmt_sequence = [(idx, e) for idx, e in enumerate(events) if e.event_id in account_mgmt_events]

    if len(mgmt_sequence) >= 3:
        for i in range(len(mgmt_sequence) - 2):
            window = mgmt_sequence[i:i+5]
            time_span = _ts_diff_seconds(window[0][1].timestamp, window[-1][1].timestamp)
            if time_span is not None and time_span <= 300 and len(window) >= 3:
                alerts.append(Alert(
                    rule_name='privilege_escalation',
                    severity='high',
                    title='Rapid Account Manipulation',
                    description=f"Detected {len(window)} account management operations within {time_span:.0f}s.",
                    evidence=[f"{e.timestamp} - {e.event_id}: {e.message[:60]}" for _, e in window],
                    timestamp=window[0][1].timestamp,
                    end_timestamp=window[-1][1].timestamp,
                    event_indices=[idx for idx, _ in window],
                    confidence=0.75,
                    mitre_tactic='Persistence',
                    mitre_technique='T1136 - Create Account',
                ))
                break

    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR 4: File Access Correlation
# ═══════════════════════════════════════════════════════════════════════════════

def detect_file_access_anomaly(events: list, window_seconds: int = 120, threshold: int = 10) -> List[Alert]:
    alerts = []
    file_events_by_source: Dict[str, List[Tuple[int, Any]]] = defaultdict(list)

    for idx, event in enumerate(events):
        is_file_event = (
            event.category == 'file_access' or
            event.event_id in ('4663', '4656', '4660', '4670') or
            any(w in event.message.lower() for w in ['file', 'object access', 'delete', 'modify'])
        )
        if is_file_event:
            source_key = event.source_ip or event.username or event.process or 'unknown'
            if source_key not in ('unknown', '-', 'N/A'):
                file_events_by_source[source_key].append((idx, event))

    for source, file_events in file_events_by_source.items():
        if len(file_events) < threshold:
            continue

        i = 0
        while i < len(file_events):
            window = [file_events[i]]
            j = i + 1
            while j < len(file_events):
                time_diff = _ts_diff_seconds(file_events[i][1].timestamp, file_events[j][1].timestamp)
                if time_diff is not None and time_diff <= window_seconds:
                    window.append(file_events[j])
                    j += 1
                else:
                    break

            if len(window) >= threshold:
                first = window[0][1]
                last = window[-1][1]
                deletions = sum(1 for _, e in window if e.event_id == '4660' or 'delete' in e.message.lower())
                is_ransomware_like = deletions > len(window) * 0.3
                severity = 'critical' if is_ransomware_like else 'high'
                title = 'Possible Ransomware Activity' if is_ransomware_like else 'Bulk File Access Anomaly'

                alerts.append(Alert(
                    rule_name='file_access_anomaly',
                    severity=severity,
                    title=title,
                    description=f"Detected {len(window)} file operations by '{source}' within {window_seconds}s.",
                    evidence=[f"{e.timestamp} - {e.event_id}: {e.message[:80]}" for _, e in window[:10]],
                    timestamp=first.timestamp,
                    end_timestamp=last.timestamp,
                    source_ip=first.source_ip,
                    target=source,
                    event_indices=[idx for idx, _ in window],
                    confidence=min(0.6 + (len(window) - threshold) * 0.05, 0.95),
                    mitre_tactic='Collection' if not is_ransomware_like else 'Impact',
                    mitre_technique='T1005' if not is_ransomware_like else 'T1486',
                ))
                i = j
            else:
                i += 1

    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR 5: Data Exfiltration Detection
# ═══════════════════════════════════════════════════════════════════════════════

def detect_data_exfiltration(events: list, bytes_threshold: int = 50000,
                              packet_threshold: int = 50, window_seconds: int = 300) -> List[Alert]:
    alerts = []
    flows: Dict[str, Dict] = defaultdict(lambda: {
        'total_bytes': 0, 'packet_count': 0, 'events': [],
        'first_ts': '', 'last_ts': '', 'dst_ip': '', 'src_ip': '',
        'services': set(), 'dns_queries': []
    })

    for idx, event in enumerate(events):
        if event.category != 'network':
            continue
        src = event.source_ip
        dst = event.dest_ip or event.raw_data.get('dst_ip', '')
        if not src or not dst:
            continue

        if _is_private_ip(src) and not _is_private_ip(dst):
            flow_key = f"{src}->{dst}"
            flow = flows[flow_key]
            flow['total_bytes'] += event.raw_data.get('payload_size', 0) or 0
            flow['packet_count'] += 1
            flow['events'].append((idx, event))
            flow['dst_ip'] = dst
            flow['src_ip'] = src
            if not flow['first_ts']:
                flow['first_ts'] = event.timestamp
            flow['last_ts'] = event.timestamp
            service = event.raw_data.get('service', '')
            if service:
                flow['services'].add(service)
            dns_q = event.raw_data.get('dns_query', '')
            if dns_q:
                flow['dns_queries'].append(dns_q)

    for flow_key, flow in flows.items():
        reasons = []
        if flow['total_bytes'] >= bytes_threshold:
            reasons.append(f"Large data transfer: {flow['total_bytes']:,} bytes")
        if flow['packet_count'] >= packet_threshold:
            time_span = _ts_diff_seconds(flow['first_ts'], flow['last_ts'])
            if time_span is not None and time_span <= window_seconds:
                reasons.append(f"High packet volume: {flow['packet_count']} packets in {time_span:.0f}s")
        if len(flow['dns_queries']) >= 20:
            unique_queries = len(set(flow['dns_queries']))
            if unique_queries >= 15:
                reasons.append(f"Possible DNS tunneling: {unique_queries} unique DNS queries")

        if reasons:
            alerts.append(Alert(
                rule_name='data_exfiltration',
                severity='critical',
                title=f'Potential Data Exfiltration to {flow["dst_ip"]}',
                description=f"Suspicious outbound traffic from {flow['src_ip']} \u2192 {flow['dst_ip']}: " + "; ".join(reasons),
                evidence=[f"{e.timestamp} - {e.message[:80]}" for _, e in flow['events'][:10]],
                timestamp=flow['first_ts'],
                end_timestamp=flow['last_ts'],
                source_ip=flow['src_ip'],
                target=flow['dst_ip'],
                event_indices=[idx for idx, _ in flow['events']],
                confidence=min(0.5 + len(reasons) * 0.2, 0.95),
                mitre_tactic='Exfiltration',
                mitre_technique='T1048 - Exfiltration Over Alternative Protocol',
            ))

    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# Event Correlation Module — Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class EventCorrelationModule:
    """Orchestrates all detection algorithms against a normalized event timeline."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.alerts: List[Alert] = []
        self.summary: Dict[str, Any] = {}

    def analyze(self, events: list) -> Tuple[list, List[Alert], Dict]:
        all_alerts = []

        all_alerts.extend(detect_brute_force(
            events,
            window_seconds=self.config.get('brute_force_window', 300),
            threshold=self.config.get('brute_force_threshold', 5),
        ))
        all_alerts.extend(detect_new_ip(events))
        all_alerts.extend(detect_privilege_escalation(
            events,
            escalation_window=self.config.get('escalation_window', 600),
        ))
        all_alerts.extend(detect_file_access_anomaly(
            events,
            window_seconds=self.config.get('file_access_window', 120),
            threshold=self.config.get('file_access_threshold', 10),
        ))
        all_alerts.extend(detect_data_exfiltration(
            events,
            bytes_threshold=self.config.get('exfil_bytes_threshold', 50000),
            packet_threshold=self.config.get('exfil_packet_threshold', 50),
        ))

        # Annotate events with their alerts
        for alert in all_alerts:
            alert_dict = {'rule_name': alert.rule_name, 'severity': alert.severity, 'title': alert.title}
            for event_idx in alert.event_indices:
                if 0 <= event_idx < len(events):
                    events[event_idx].alerts.append(alert_dict)

        summary = self._build_summary(events, all_alerts)
        self.alerts = all_alerts
        self.summary = summary
        return events, all_alerts, summary

    def _build_summary(self, events: list, alerts: List[Alert]) -> Dict:
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        rule_counts = defaultdict(int)
        source_ip_counts = defaultdict(int)

        for event in events:
            severity_counts[event.severity] += 1
            category_counts[event.category] += 1

        for alert in alerts:
            rule_counts[alert.rule_name] += 1
            if alert.source_ip:
                source_ip_counts[alert.source_ip] += 1

        timestamps = [e.timestamp for e in events if e.timestamp]
        time_range = {'start': min(timestamps), 'end': max(timestamps)} if timestamps else {}

        top_attackers = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        risk_score = min(100, sum(
            {'critical': 30, 'high': 15, 'medium': 5}.get(a.severity, 1) for a in alerts
        ))

        return {
            'total_events': len(events),
            'total_alerts': len(alerts),
            'risk_score': risk_score,
            'severity_distribution': dict(severity_counts),
            'category_distribution': dict(category_counts),
            'detection_counts': dict(rule_counts),
            'time_range': time_range,
            'top_attackers': [{'ip': ip, 'alert_count': cnt} for ip, cnt in top_attackers],
            'source_files': list(set(e.source_file for e in events if e.source_file)),
        }
