"""
KronoTrace — Event Normalizer
Maps raw parser output from diverse formats into a unified EventLog schema.
All timestamps are converted to UTC ISO 8601.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import re


@dataclass
class EventLog:
    """Unified event schema for all log sources."""
    timestamp: str              # ISO 8601 UTC
    source: str                 # e.g., "Windows-Security", "network-pcap", "auth.log"
    event_id: str               # Numeric for EVTX, synthetic for PCAP/syslog
    category: str               # "authentication", "network", "system", "file_access"
    severity: str               # "info", "low", "medium", "high", "critical"
    message: str                # Human-readable description
    raw_data: Dict[str, Any] = field(default_factory=dict)
    source_file: str = ''       # Which uploaded file this came from
    alerts: List[Dict] = field(default_factory=list)
    source_ip: str = ''
    dest_ip: str = ''
    username: str = ''
    hostname: str = ''
    process: str = ''
    details: str = ''

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        d = asdict(self)
        if 'raw_xml' in d.get('raw_data', {}):
            del d['raw_data']['raw_xml']
        if 'raw_line' in d.get('raw_data', {}):
            del d['raw_data']['raw_line']
        return d


# ─── EVTX Event ID Knowledge Base ────────────────────────────────────────────

EVTX_EVENT_MAP = {
    '4624': {'category': 'authentication', 'severity': 'info', 'desc': 'Successful logon'},
    '4625': {'category': 'authentication', 'severity': 'high', 'desc': 'Failed logon attempt'},
    '4634': {'category': 'authentication', 'severity': 'info', 'desc': 'Account logoff'},
    '4647': {'category': 'authentication', 'severity': 'info', 'desc': 'User-initiated logoff'},
    '4648': {'category': 'authentication', 'severity': 'medium', 'desc': 'Logon using explicit credentials'},
    '4768': {'category': 'authentication', 'severity': 'info', 'desc': 'Kerberos TGT requested'},
    '4769': {'category': 'authentication', 'severity': 'info', 'desc': 'Kerberos service ticket requested'},
    '4771': {'category': 'authentication', 'severity': 'high', 'desc': 'Kerberos pre-authentication failed'},
    '4776': {'category': 'authentication', 'severity': 'info', 'desc': 'NTLM authentication attempt'},
    '4672': {'category': 'authentication', 'severity': 'medium', 'desc': 'Special privileges assigned to logon'},
    '4673': {'category': 'authentication', 'severity': 'high', 'desc': 'Privileged service called'},
    '4674': {'category': 'authentication', 'severity': 'medium', 'desc': 'Operation attempted on privileged object'},
    '4720': {'category': 'system', 'severity': 'high', 'desc': 'User account created'},
    '4722': {'category': 'system', 'severity': 'medium', 'desc': 'User account enabled'},
    '4723': {'category': 'authentication', 'severity': 'medium', 'desc': 'Password change attempted'},
    '4724': {'category': 'authentication', 'severity': 'high', 'desc': 'Password reset attempted'},
    '4725': {'category': 'system', 'severity': 'medium', 'desc': 'User account disabled'},
    '4726': {'category': 'system', 'severity': 'high', 'desc': 'User account deleted'},
    '4728': {'category': 'system', 'severity': 'high', 'desc': 'Member added to security-enabled global group'},
    '4732': {'category': 'system', 'severity': 'high', 'desc': 'Member added to security-enabled local group'},
    '4735': {'category': 'system', 'severity': 'medium', 'desc': 'Security-enabled local group changed'},
    '4740': {'category': 'authentication', 'severity': 'high', 'desc': 'Account locked out'},
    '4756': {'category': 'system', 'severity': 'high', 'desc': 'Member added to universal group'},
    '4663': {'category': 'file_access', 'severity': 'info', 'desc': 'Object access attempted'},
    '4656': {'category': 'file_access', 'severity': 'info', 'desc': 'Handle to object requested'},
    '4658': {'category': 'file_access', 'severity': 'info', 'desc': 'Handle to object closed'},
    '4660': {'category': 'file_access', 'severity': 'medium', 'desc': 'Object deleted'},
    '4670': {'category': 'file_access', 'severity': 'medium', 'desc': 'Permissions on object changed'},
    '4719': {'category': 'system', 'severity': 'critical', 'desc': 'System audit policy changed'},
    '4739': {'category': 'system', 'severity': 'high', 'desc': 'Domain policy changed'},
    '1102': {'category': 'system', 'severity': 'critical', 'desc': 'Audit log cleared'},
    '4697': {'category': 'system', 'severity': 'high', 'desc': 'Service installed'},
    '7045': {'category': 'system', 'severity': 'high', 'desc': 'New service installed'},
    '4688': {'category': 'system', 'severity': 'info', 'desc': 'New process created'},
    '4689': {'category': 'system', 'severity': 'info', 'desc': 'Process exited'},
    '5156': {'category': 'network', 'severity': 'info', 'desc': 'WFP connection allowed'},
    '5157': {'category': 'network', 'severity': 'medium', 'desc': 'WFP connection blocked'},
    '4104': {'category': 'system', 'severity': 'medium', 'desc': 'PowerShell script block logging'},
    '400':  {'category': 'system', 'severity': 'info', 'desc': 'PowerShell engine started'},
    '403':  {'category': 'system', 'severity': 'info', 'desc': 'PowerShell engine stopped'},
}

LOGON_TYPES = {
    '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service',
    '7': 'Unlock', '8': 'NetworkCleartext', '9': 'NewCredentials',
    '10': 'RemoteInteractive (RDP)', '11': 'CachedInteractive',
}


def normalize_evtx_record(raw: Dict[str, Any]) -> EventLog:
    """Normalize an EVTX parsed record into the unified EventLog schema."""
    event_id = str(raw.get('event_id', 'unknown'))
    event_info = EVTX_EVENT_MAP.get(event_id, {
        'category': 'system', 'severity': 'info', 'desc': f'Windows Event {event_id}'
    })
    event_data = raw.get('event_data', {})
    message = event_info['desc']
    extra_parts = []

    username = (event_data.get('TargetUserName', '') or
                event_data.get('SubjectUserName', '') or
                event_data.get('UserName', ''))
    domain = (event_data.get('TargetDomainName', '') or
              event_data.get('SubjectDomainName', ''))
    if username:
        user_str = f'{domain}\\{username}' if domain else username
        extra_parts.append(f'User: {user_str}')

    source_ip = event_data.get('IpAddress', '') or event_data.get('SourceAddress', '')
    if source_ip and source_ip != '-':
        extra_parts.append(f'Source IP: {source_ip}')

    logon_type = event_data.get('LogonType', '')
    if logon_type:
        logon_desc = LOGON_TYPES.get(str(logon_type), logon_type)
        extra_parts.append(f'Logon Type: {logon_desc}')

    process_name = event_data.get('ProcessName', '') or event_data.get('NewProcessName', '')
    if process_name:
        extra_parts.append(f'Process: {process_name}')

    if event_id == '4625':
        failure_reason = event_data.get('FailureReason', '')
        sub_status = event_data.get('SubStatus', '')
        if failure_reason:
            extra_parts.append(f'Reason: {failure_reason}')
        elif sub_status:
            extra_parts.append(f'SubStatus: {sub_status}')

    object_name = event_data.get('ObjectName', '')
    if object_name:
        extra_parts.append(f'Object: {object_name}')

    if extra_parts:
        message += ' | ' + ' | '.join(extra_parts)

    severity = event_info['severity']
    if event_id == '4625' and source_ip:
        severity = 'high'
    if event_id in ('1102', '4719'):
        severity = 'critical'

    return EventLog(
        timestamp=_parse_evtx_timestamp(raw.get('timestamp', '')),
        source=f"Windows-{raw.get('channel', 'System')}",
        event_id=event_id,
        category=event_info['category'],
        severity=severity,
        message=message,
        raw_data={k: v for k, v in raw.items() if not k.startswith('_') and k != 'raw_xml'},
        source_file=raw.get('_source_file', ''),
        source_ip=source_ip if source_ip != '-' else '',
        username=username,
        hostname=raw.get('computer', ''),
        process=process_name,
        details=str(event_data),
    )


def normalize_pcap_record(raw: Dict[str, Any]) -> EventLog:
    """Normalize a PCAP parsed record into the unified EventLog schema."""
    protocol = raw.get('protocol', 'UNKNOWN')
    service = raw.get('service', protocol)
    src_ip = raw.get('src_ip', 'N/A')
    dst_ip = raw.get('dst_ip', 'N/A')
    src_port = raw.get('src_port', '')
    dst_port = raw.get('dst_port', '')
    payload_size = raw.get('payload_size', 0)
    packet_size = raw.get('packet_size', 0)

    msg_parts = [f'{protocol}']
    if src_port:
        msg_parts.append(f'{src_ip}:{src_port} \u2192 {dst_ip}:{dst_port}')
    else:
        msg_parts.append(f'{src_ip} \u2192 {dst_ip}')
    if service and service != protocol:
        msg_parts.append(f'[{service}]')
    flags = raw.get('tcp_flags', '')
    if flags:
        msg_parts.append(f'Flags: {flags}')
    if payload_size > 0:
        msg_parts.append(f'Payload: {payload_size}B')
    dns_query = raw.get('dns_query', '')
    if dns_query:
        msg_parts.append(f'DNS: {dns_query}')

    message = ' | '.join(msg_parts)

    severity = 'info'
    if dst_port in (22, 3389, 445):
        severity = 'medium'
    if payload_size > 10000:
        severity = 'medium'

    return EventLog(
        timestamp=raw.get('timestamp', datetime.now(timezone.utc).isoformat()),
        source=f'network-{service.lower()}' if service else 'network',
        event_id=raw.get('event_id', f'NET_{protocol}'),
        category='network',
        severity=severity,
        message=message,
        raw_data={k: v for k, v in raw.items() if not k.startswith('_')},
        source_file=raw.get('_source_file', ''),
        source_ip=src_ip,
        dest_ip=dst_ip,
        details=f'Size: {packet_size}B',
    )


def normalize_syslog_record(raw: Dict[str, Any]) -> EventLog:
    """Normalize a syslog parsed record into the unified EventLog schema."""
    message = raw.get('message', raw.get('raw_line', ''))
    category = raw.get('category', 'system')
    severity = raw.get('severity_hint', 'info')

    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    ips = ip_pattern.findall(message)
    source_ip = ips[0] if ips else ''

    username = ''
    user_patterns = [
        re.compile(r'user[= ]+(\S+)', re.IGNORECASE),
        re.compile(r'for (?:invalid user )?(\S+)'),
        re.compile(r'session opened for user (\S+)'),
        re.compile(r'pam_unix\(\S+\): session \S+ for user (\S+)'),
    ]
    for up in user_patterns:
        m = up.search(message)
        if m:
            username = m.group(1)
            break

    full_message = message
    process = raw.get('process', '')
    if process and process not in message:
        full_message = f'[{process}] {message}'

    return EventLog(
        timestamp=raw.get('timestamp', datetime.now(timezone.utc).isoformat()),
        source=raw.get('_source_file', 'syslog'),
        event_id=raw.get('event_id', 'SYS_EVENT'),
        category=category,
        severity=severity,
        message=full_message,
        raw_data={k: v for k, v in raw.items() if not k.startswith('_')},
        source_file=raw.get('_source_file', ''),
        source_ip=source_ip,
        username=username,
        hostname=raw.get('hostname', ''),
        process=process,
    )


def normalize_csv_record(raw: Dict[str, Any]) -> EventLog:
    """Normalize a CSV record with intelligent column mapping."""
    timestamp = ''
    ts_columns = ['timestamp', 'time', 'date', 'datetime', 'created', 'timecreated',
                  'event_time', 'log_time', 'received_time', '@timestamp']
    for col in ts_columns:
        val = raw.get(col, '')
        if val:
            timestamp = _parse_generic_timestamp(val)
            break
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    event_id = ''
    id_columns = ['event_id', 'eventid', 'id', 'event_code', 'code', 'rule_id', 'alert_id']
    for col in id_columns:
        val = raw.get(col, '')
        if val:
            event_id = str(val)
            break
    if not event_id:
        event_id = 'CSV_EVENT'

    message = ''
    msg_columns = ['message', 'msg', 'description', 'detail', 'details', 'summary',
                   'event_message', 'log_message', 'text', 'info']
    for col in msg_columns:
        val = raw.get(col, '')
        if val:
            message = val
            break
    if not message:
        parts = [f'{k}={v}' for k, v in raw.items()
                 if not k.startswith('_') and v and k not in ts_columns + id_columns]
        message = ' | '.join(parts[:5])

    category = 'system'
    cat_columns = ['category', 'type', 'event_type', 'class', 'log_type']
    for col in cat_columns:
        val = raw.get(col, '').lower()
        if val:
            if any(w in val for w in ['auth', 'login', 'logon', 'password']):
                category = 'authentication'
            elif any(w in val for w in ['net', 'connection', 'traffic', 'flow']):
                category = 'network'
            elif any(w in val for w in ['file', 'access', 'object']):
                category = 'file_access'
            else:
                category = val
            break

    severity = 'info'
    sev_columns = ['severity', 'level', 'priority', 'risk', 'alert_level']
    for col in sev_columns:
        val = raw.get(col, '').lower()
        if val:
            if any(w in val for w in ['critical', 'crit', 'fatal', 'emergency']):
                severity = 'critical'
            elif any(w in val for w in ['high', 'error', 'err']):
                severity = 'high'
            elif any(w in val for w in ['medium', 'med', 'warning', 'warn']):
                severity = 'medium'
            elif any(w in val for w in ['low']):
                severity = 'low'
            break

    source_ip = ''
    for col in ['source_ip', 'src_ip', 'src', 'source_address', 'client_ip', 'remote_ip']:
        val = raw.get(col, '')
        if val:
            source_ip = val
            break

    dest_ip = ''
    for col in ['dest_ip', 'dst_ip', 'dst', 'destination_address', 'target_ip', 'server_ip']:
        val = raw.get(col, '')
        if val:
            dest_ip = val
            break

    username = ''
    for col in ['username', 'user', 'account', 'user_name', 'target_user', 'actor']:
        val = raw.get(col, '')
        if val:
            username = val
            break

    return EventLog(
        timestamp=timestamp,
        source=raw.get('_source_file', 'csv'),
        event_id=event_id,
        category=category,
        severity=severity,
        message=message,
        raw_data={k: v for k, v in raw.items() if not k.startswith('_')},
        source_file=raw.get('_source_file', ''),
        source_ip=source_ip,
        dest_ip=dest_ip,
        username=username,
    )


# ─── Dispatcher ───────────────────────────────────────────────────────────────

NORMALIZER_MAP = {
    'evtx': normalize_evtx_record,
    'pcap': normalize_pcap_record,
    'syslog': normalize_syslog_record,
    'csv': normalize_csv_record,
}


def normalize_records(raw_records: List[Dict[str, Any]]) -> List[EventLog]:
    """Normalize a list of raw parsed records into unified EventLog objects."""
    normalized = []
    for raw in raw_records:
        parser_type = raw.get('_parser', 'csv')
        normalizer_fn = NORMALIZER_MAP.get(parser_type, normalize_csv_record)
        try:
            event = normalizer_fn(raw)
            normalized.append(event)
        except Exception as e:
            normalized.append(EventLog(
                timestamp=raw.get('timestamp', datetime.now(timezone.utc).isoformat()),
                source=raw.get('_source_file', 'unknown'),
                event_id='PARSE_ERROR',
                category='system',
                severity='low',
                message=f'Normalization error: {str(e)}',
                raw_data=raw,
                source_file=raw.get('_source_file', ''),
            ))
    return normalized


def merge_and_sort(events: List[EventLog]) -> List[EventLog]:
    """Merge events from multiple sources and sort chronologically."""
    def sort_key(event: EventLog) -> str:
        return event.timestamp if event.timestamp else '0000-00-00T00:00:00'
    return sorted(events, key=sort_key)


# ─── Timestamp Helpers ────────────────────────────────────────────────────────

def _parse_evtx_timestamp(raw_ts: str) -> str:
    """Parse EVTX SystemTime format to ISO 8601 UTC."""
    if not raw_ts:
        return datetime.now(timezone.utc).isoformat()
    try:
        if raw_ts.endswith('Z'):
            raw_ts = raw_ts[:-1] + '+00:00'
        parsed = datetime.fromisoformat(raw_ts)
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass
    for fmt in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S']:
        try:
            parsed = datetime.strptime(raw_ts, fmt)
            return parsed.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return raw_ts


def _parse_generic_timestamp(raw_ts: str) -> str:
    """Try to parse any timestamp format to ISO 8601 UTC."""
    if not raw_ts:
        return datetime.now(timezone.utc).isoformat()
    try:
        raw_clean = raw_ts[:-1] + '+00:00' if raw_ts.endswith('Z') else raw_ts
        parsed = datetime.fromisoformat(raw_clean)
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass
    for fmt in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S',
                '%d/%m/%Y %H:%M:%S', '%Y/%m/%d %H:%M:%S']:
        try:
            parsed = datetime.strptime(raw_ts.strip(), fmt)
            return parsed.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    try:
        epoch = float(raw_ts)
        if epoch > 1e12:
            epoch = epoch / 1000
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass
    return datetime.now(timezone.utc).isoformat()
