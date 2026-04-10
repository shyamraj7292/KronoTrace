"""Test the KronoTrace pipeline by uploading sample files via API."""
import urllib.request
import json
import os
import uuid
import time

def upload_files():
    boundary = uuid.uuid4().hex
    lines = []

    for fname in ['sample_data/security_events.csv', 'sample_data/auth.log']:
        with open(fname, 'rb') as f:
            data = f.read()
        basename = os.path.basename(fname)
        lines.append(f'--{boundary}'.encode())
        lines.append(f'Content-Disposition: form-data; name="files"; filename="{basename}"'.encode())
        lines.append(b'Content-Type: application/octet-stream')
        lines.append(b'')
        lines.append(data)

    lines.append(f'--{boundary}--'.encode())
    lines.append(b'')
    body = b'\r\n'.join(lines)

    req = urllib.request.Request('http://localhost:8000/api/upload', data=body, method='POST')
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')

    print("Uploading files...")
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    print(f"Upload response: {json.dumps(result, indent=2)}")

    pid = result['pipeline_id']

    # Wait for pipeline to complete
    for i in range(30):
        time.sleep(1)
        resp2 = urllib.request.urlopen(f'http://localhost:8000/api/status/{pid}')
        status = json.loads(resp2.read())
        print(f"[{i+1}s] Status: {status['status']} | Events: {status.get('total_events', 0)} | Alerts: {status.get('total_alerts', 0)}")
        if status['status'] in ('complete', 'error'):
            break

    # Get full results
    print("\n" + "="*60)
    resp3 = urllib.request.urlopen(f'http://localhost:8000/api/results/{pid}')
    results = json.loads(resp3.read())

    print(f"PIPELINE STATUS: {results['status']}")
    print(f"TOTAL EVENTS: {len(results['events'])}")
    print(f"TOTAL ALERTS: {len(results['alerts'])}")

    if results.get('summary'):
        s = results['summary']
        print(f"\nRISK SCORE: {s.get('risk_score', 0)}/100")
        print(f"DETECTION COUNTS: {json.dumps(s.get('detection_counts', {}), indent=2)}")
        print(f"CATEGORY DISTRIBUTION: {json.dumps(s.get('category_distribution', {}), indent=2)}")
        print(f"SEVERITY DISTRIBUTION: {json.dumps(s.get('severity_distribution', {}), indent=2)}")
        print(f"TOP ATTACKERS: {json.dumps(s.get('top_attackers', []), indent=2)}")
        print(f"SOURCE FILES: {s.get('source_files', [])}")

    if results['alerts']:
        print(f"\n{'='*60}")
        print("DETECTED THREATS:")
        print(f"{'='*60}")
        for i, alert in enumerate(results['alerts']):
            print(f"\n[{i+1}] {alert['title']}")
            print(f"    Severity: {alert['severity']}")
            print(f"    Rule: {alert['rule_name']}")
            print(f"    Description: {alert['description']}")
            if alert.get('source_ip'):
                print(f"    Source IP: {alert['source_ip']}")
            if alert.get('mitre_technique'):
                print(f"    MITRE ATT&CK: {alert['mitre_technique']}")
            if alert.get('confidence'):
                print(f"    Confidence: {alert['confidence']*100:.0f}%")

if __name__ == '__main__':
    upload_files()
