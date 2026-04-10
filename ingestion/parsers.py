"""
KronoTrace — Multi-Format Log Parsers
Dedicated parsing functions for CSV, EVTX, PCAP, and Syslog files.
Each parser returns a list of raw dicts that the normalizer will unify.
"""

import csv
import re
import os
import io
import struct
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path


# ─── CSV Parser ───────────────────────────────────────────────────────────────

def parse_csv(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse a CSV file into a list of dicts.
    Auto-detects delimiter (comma, tab, semicolon, pipe).
    Handles common edge cases: BOM, quoted fields, mixed line endings.
    """
    records = []
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        sample = f.read(8192)
        f.seek(0)

        # Auto-detect delimiter
        sniffer = csv.Sniffer()
        try:
            dialect = sniffer.sniff(sample, delimiters=',\t;|')
        except csv.Error:
            dialect = csv.excel  # fallback to comma

        reader = csv.DictReader(f, dialect=dialect)
        for i, row in enumerate(reader):
            cleaned = {}
            for k, v in row.items():
                if k is not None:
                    clean_key = k.strip().lower().replace(' ', '_')
                    cleaned[clean_key] = v.strip() if v else ''
            cleaned['_parser'] = 'csv'
            cleaned['_source_file'] = os.path.basename(filepath)
            cleaned['_row_number'] = i + 1
            records.append(cleaned)

    return records


# ─── EVTX Parser ─────────────────────────────────────────────────────────────

def parse_evtx(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse a Windows Event Log (.evtx) file using python-evtx.
    Extracts EventID, TimeCreated, Channel, Computer, Provider, UserData, EventData.
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as evtx_views
    except ImportError:
        raise ImportError(
            "python-evtx is required for .evtx parsing. "
            "Install it with: pip install python-evtx"
        )

    import xml.etree.ElementTree as ET

    records = []
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

    with evtx.Evtx(filepath) as log:
        for i, record in enumerate(log.records()):
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                system = root.find(f'{ns}System')
                event_id_elem = system.find(f'{ns}EventID') if system is not None else None
                time_created_elem = system.find(f'{ns}TimeCreated') if system is not None else None
                provider_elem = system.find(f'{ns}Provider') if system is not None else None
                computer_elem = system.find(f'{ns}Computer') if system is not None else None
                channel_elem = system.find(f'{ns}Channel') if system is not None else None
                level_elem = system.find(f'{ns}Level') if system is not None else None
                keywords_elem = system.find(f'{ns}Keywords') if system is not None else None

                event_id = event_id_elem.text if event_id_elem is not None else 'unknown'
                if event_id_elem is not None and event_id_elem.get('Qualifiers'):
                    event_id = event_id_elem.text

                time_created = ''
                if time_created_elem is not None:
                    time_created = time_created_elem.get('SystemTime', '')

                provider_name = ''
                if provider_elem is not None:
                    provider_name = provider_elem.get('Name', '')

                computer = computer_elem.text if computer_elem is not None else ''
                channel = channel_elem.text if channel_elem is not None else ''
                level = level_elem.text if level_elem is not None else ''
                keywords = keywords_elem.text if keywords_elem is not None else ''

                # Extract EventData fields
                event_data = {}
                event_data_elem = root.find(f'{ns}EventData')
                if event_data_elem is not None:
                    for data in event_data_elem.findall(f'{ns}Data'):
                        name = data.get('Name', f'field_{len(event_data)}')
                        event_data[name] = data.text or ''

                # Extract UserData if present
                user_data = {}
                user_data_elem = root.find(f'{ns}UserData')
                if user_data_elem is not None:
                    for child in user_data_elem.iter():
                        tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if child.text and child.text.strip():
                            user_data[tag] = child.text.strip()

                record_dict = {
                    'event_id': str(event_id),
                    'timestamp': time_created,
                    'provider': provider_name,
                    'computer': computer,
                    'channel': channel,
                    'level': level,
                    'keywords': keywords,
                    'event_data': event_data,
                    'user_data': user_data,
                    'raw_xml': xml_str,
                    '_parser': 'evtx',
                    '_source_file': os.path.basename(filepath),
                    '_record_number': i + 1,
                }
                records.append(record_dict)

            except Exception as e:
                records.append({
                    'event_id': 'parse_error',
                    'timestamp': '',
                    'message': f'Failed to parse record {i+1}: {str(e)}',
                    'error': str(e),
                    '_parser': 'evtx',
                    '_source_file': os.path.basename(filepath),
                    '_record_number': i + 1,
                })

    return records


# ─── PCAP Parser ──────────────────────────────────────────────────────────────

def parse_pcap(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse a PCAP/PCAPNG file using scapy.
    Extracts: timestamp, src/dst IP, src/dst port, protocol, flags, payload size.
    """
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
    except ImportError:
        raise ImportError(
            "scapy is required for .pcap parsing. "
            "Install it with: pip install scapy"
        )

    records = []

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return [{
            'event_id': 'pcap_error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message': f'Failed to read PCAP file: {str(e)}',
            '_parser': 'pcap',
            '_source_file': os.path.basename(filepath),
        }]

    for i, pkt in enumerate(packets):
        try:
            record = {
                '_parser': 'pcap',
                '_source_file': os.path.basename(filepath),
                '_packet_number': i + 1,
            }

            # Timestamp
            record['timestamp'] = datetime.fromtimestamp(
                float(pkt.time), tz=timezone.utc
            ).isoformat()

            # IP layer
            if IP in pkt:
                ip_layer = pkt[IP]
                record['src_ip'] = ip_layer.src
                record['dst_ip'] = ip_layer.dst
                record['ip_version'] = 4
                record['ttl'] = ip_layer.ttl
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                record['src_ip'] = ip_layer.src
                record['dst_ip'] = ip_layer.dst
                record['ip_version'] = 6
            else:
                record['src_ip'] = 'N/A'
                record['dst_ip'] = 'N/A'
                record['protocol'] = pkt.summary().split('/')[0] if pkt.summary() else 'L2'

            # Transport layer
            if TCP in pkt:
                tcp = pkt[TCP]
                record['src_port'] = tcp.sport
                record['dst_port'] = tcp.dport
                record['protocol'] = 'TCP'
                record['tcp_flags'] = str(tcp.flags)
                record['seq'] = tcp.seq
                record['ack'] = tcp.ack
                record['window'] = tcp.window

                ports = {tcp.sport, tcp.dport}
                if 80 in ports or 8080 in ports:
                    record['service'] = 'HTTP'
                elif 443 in ports:
                    record['service'] = 'HTTPS'
                elif 22 in ports:
                    record['service'] = 'SSH'
                elif 21 in ports:
                    record['service'] = 'FTP'
                elif 25 in ports or 587 in ports:
                    record['service'] = 'SMTP'
                elif 53 in ports:
                    record['service'] = 'DNS'
                elif 3389 in ports:
                    record['service'] = 'RDP'
                elif 445 in ports:
                    record['service'] = 'SMB'
                else:
                    record['service'] = f'TCP/{min(ports)}'

            elif UDP in pkt:
                udp = pkt[UDP]
                record['src_port'] = udp.sport
                record['dst_port'] = udp.dport
                record['protocol'] = 'UDP'

                ports = {udp.sport, udp.dport}
                if 53 in ports:
                    record['service'] = 'DNS'
                elif 67 in ports or 68 in ports:
                    record['service'] = 'DHCP'
                elif 123 in ports:
                    record['service'] = 'NTP'
                else:
                    record['service'] = f'UDP/{min(ports)}'

            elif ICMP in pkt:
                record['protocol'] = 'ICMP'
                record['icmp_type'] = pkt[ICMP].type
                record['icmp_code'] = pkt[ICMP].code
                record['service'] = 'ICMP'
                record['src_port'] = 0
                record['dst_port'] = 0

            # DNS layer
            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qd:
                    try:
                        record['dns_query'] = dns.qd.qname.decode('utf-8', errors='replace')
                    except:
                        record['dns_query'] = str(dns.qd.qname)

            # Payload size
            if Raw in pkt:
                record['payload_size'] = len(pkt[Raw].load)
            else:
                record['payload_size'] = 0

            record['packet_size'] = len(pkt)

            # Generate synthetic event_id
            protocol = record.get('protocol', 'UNKNOWN')
            flags = record.get('tcp_flags', '')
            if 'S' in flags and 'A' not in flags:
                record['event_id'] = f'NET_SYN_{protocol}'
            elif 'S' in flags and 'A' in flags:
                record['event_id'] = f'NET_SYNACK_{protocol}'
            elif 'F' in flags:
                record['event_id'] = f'NET_FIN_{protocol}'
            elif 'R' in flags:
                record['event_id'] = f'NET_RST_{protocol}'
            else:
                record['event_id'] = f'NET_{protocol}'

            records.append(record)

        except Exception as e:
            records.append({
                'event_id': 'pcap_parse_error',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'message': f'Failed to parse packet {i+1}: {str(e)}',
                '_parser': 'pcap',
                '_source_file': os.path.basename(filepath),
                '_packet_number': i + 1,
            })

    return records


# ─── Syslog Parser ────────────────────────────────────────────────────────────

SYSLOG_PATTERNS = [
    # BSD/traditional: "MMM DD HH:MM:SS hostname process[pid]: message"
    re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)$'
    ),
    # ISO timestamp: "2024-01-15T10:30:00+00:00 hostname process: message"
    re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)$'
    ),
    # Simple timestamp: "2024-01-15 10:30:00 message"
    re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
        r'(?P<message>.*)$'
    ),
    # Epoch-based: "1705312200.123 hostname process: message"
    re.compile(
        r'^(?P<timestamp>\d{10,13}(?:\.\d+)?)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)$'
    ),
]

AUTH_KEYWORDS = [
    'authentication', 'login', 'logout', 'password', 'pam_unix',
    'sshd', 'sudo', 'failed', 'accepted', 'invalid user',
    'session opened', 'session closed', 'publickey', 'preauth',
    'authorized', 'unauthorized', 'credential', 'kerberos',
    'logon', 'logoff', 'privilege', 'su:', 'su[',
]

NETWORK_KEYWORDS = [
    'connection', 'listening', 'port', 'firewall', 'iptables',
    'ufw', 'denied', 'allowed', 'interface', 'dhcp',
    'dns', 'resolved', 'tcp', 'udp',
]

FILE_ACCESS_KEYWORDS = [
    'file', 'open', 'read', 'write', 'delete', 'create',
    'modify', 'access', 'permission', 'chmod', 'chown',
    'rename', 'move', 'copy',
]


def parse_syslog(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse syslog/auth.log/system.log files using regex.
    Handles BSD, ISO, and epoch timestamp formats.
    """
    records = []
    current_year = datetime.now().year

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            record = {
                '_parser': 'syslog',
                '_source_file': os.path.basename(filepath),
                '_line_number': line_num,
                'raw_line': line,
            }

            matched = False
            for pattern in SYSLOG_PATTERNS:
                m = pattern.match(line)
                if m:
                    groups = m.groupdict()
                    record.update({k: v for k, v in groups.items() if v is not None})
                    matched = True
                    break

            if not matched:
                record['message'] = line
                record['timestamp'] = ''

            raw_ts = record.get('timestamp', '')
            record['timestamp'] = _normalize_syslog_timestamp(raw_ts, current_year)

            # Categorize by keywords
            msg_lower = record.get('message', '').lower()
            process_lower = record.get('process', '').lower()
            full_text = f'{msg_lower} {process_lower}'

            if any(kw in full_text for kw in AUTH_KEYWORDS):
                record['category'] = 'authentication'
            elif any(kw in full_text for kw in NETWORK_KEYWORDS):
                record['category'] = 'network'
            elif any(kw in full_text for kw in FILE_ACCESS_KEYWORDS):
                record['category'] = 'file_access'
            else:
                record['category'] = 'system'

            if any(w in msg_lower for w in ['error', 'fail', 'denied', 'invalid', 'critical']):
                record['severity_hint'] = 'warning'
            elif any(w in msg_lower for w in ['alert', 'emergency', 'panic', 'fatal']):
                record['severity_hint'] = 'critical'
            else:
                record['severity_hint'] = 'info'

            record['event_id'] = _generate_syslog_event_id(record)
            records.append(record)

    return records


def _normalize_syslog_timestamp(raw_ts: str, current_year: int) -> str:
    """Convert various syslog timestamp formats to ISO 8601 UTC."""
    if not raw_ts:
        return datetime.now(timezone.utc).isoformat()

    try:
        parsed = datetime.strptime(f'{current_year} {raw_ts}', '%Y %b %d %H:%M:%S')
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        pass

    try:
        parsed = datetime.strptime(f'{current_year} {raw_ts}', '%Y %b  %d %H:%M:%S')
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        pass

    try:
        if raw_ts.endswith('Z'):
            raw_ts = raw_ts[:-1] + '+00:00'
        parsed = datetime.fromisoformat(raw_ts)
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass

    try:
        epoch = float(raw_ts)
        if epoch > 1e12:
            epoch = epoch / 1000
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass

    return datetime.now(timezone.utc).isoformat()


def _generate_syslog_event_id(record: dict) -> str:
    """Generate a meaningful synthetic event ID for syslog entries."""
    msg = record.get('message', '').lower()
    process = record.get('process', '').lower()

    if 'sshd' in process or 'ssh' in process:
        if 'accepted' in msg:
            return 'SSH_LOGIN_SUCCESS'
        elif 'failed' in msg or 'invalid' in msg:
            return 'SSH_LOGIN_FAILED'
        elif 'disconnect' in msg:
            return 'SSH_DISCONNECT'
        elif 'connection closed' in msg:
            return 'SSH_CONN_CLOSED'
        return 'SSH_EVENT'

    if 'pam_unix' in msg or 'pam_' in msg:
        if 'session opened' in msg:
            return 'PAM_SESSION_OPEN'
        elif 'session closed' in msg:
            return 'PAM_SESSION_CLOSE'
        elif 'authentication failure' in msg:
            return 'PAM_AUTH_FAIL'
        return 'PAM_EVENT'

    if 'sudo' in process:
        if 'command' in msg:
            return 'SUDO_COMMAND'
        elif 'not allowed' in msg or 'incorrect password' in msg:
            return 'SUDO_DENIED'
        return 'SUDO_EVENT'

    if 'systemd' in process:
        if 'started' in msg:
            return 'SERVICE_START'
        elif 'stopped' in msg:
            return 'SERVICE_STOP'
        elif 'failed' in msg:
            return 'SERVICE_FAIL'
        return 'SYSTEMD_EVENT'

    if 'kernel' in process:
        if 'firewall' in msg or 'iptables' in msg or 'ufw' in msg:
            return 'FIREWALL_EVENT'
        return 'KERNEL_EVENT'

    if 'cron' in process:
        return 'CRON_EVENT'

    if record.get('category') == 'authentication':
        if 'failed' in msg:
            return 'AUTH_FAILED'
        elif 'success' in msg or 'accepted' in msg:
            return 'AUTH_SUCCESS'
        return 'AUTH_EVENT'

    return 'SYS_EVENT'


# ─── File Router ──────────────────────────────────────────────────────────────

EXTENSION_MAP = {
    '.csv': parse_csv,
    '.evtx': parse_evtx,
    '.pcap': parse_pcap,
    '.pcapng': parse_pcap,
    '.log': parse_syslog,
    '.txt': parse_syslog,
    '.syslog': parse_syslog,
}

SUPPORTED_EXTENSIONS = set(EXTENSION_MAP.keys())


def parse_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Route a file to the correct parser based on extension.
    Returns a list of raw parsed records.
    """
    ext = Path(filepath).suffix.lower()

    if ext not in EXTENSION_MAP:
        raise ValueError(
            f"Unsupported file type: '{ext}'. "
            f"Supported types: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    parser_fn = EXTENSION_MAP[ext]
    return parser_fn(filepath)


def get_supported_extensions() -> List[str]:
    """Return list of supported file extensions."""
    return sorted(SUPPORTED_EXTENSIONS)
