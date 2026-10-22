import random, re
from collections import defaultdict
from datetime import datetime, timedelta

SQLI = re.compile(r"(union\s+select|or\s+1=1|;\s*drop|<script>|\.\./\.\./)", re.I)
ADMINS = {"admin", "root"}
EXFIL_BYTES = 500_000_000

def generate_logs(n_noise=60):
    """Synthetic logs: normal noise + 5 injected attack scenarios."""
    base = datetime.now().replace(microsecond=0) - timedelta(minutes=30)
    logs = []
    def add(sec, ip, user, event, **kw):
        logs.append({"ts": (base + timedelta(seconds=sec)).isoformat(),
                     "src_ip": ip, "user": user, "event": event, **kw})
    for _ in range(n_noise):
        add(random.randint(0, 1700), f"10.0.0.{random.randint(10, 40)}",
            random.choice(["alice", "bob", "carol", "dave"]),
            random.choice(["login_success", "web_request"]), path="/home")
    for i in range(8):
        add(600 + i * 5, "185.220.101.5", "admin", "login_failed")
    add(650, "185.220.101.5", "admin", "login_success")
    for i, p in enumerate([21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]):
        add(900 + i, "45.155.205.9", "-", "port_probe", port=p)
    add(1000, "103.77.192.4", "-", "web_request", path="/products?id=1 UNION SELECT username,password FROM users--")
    add(1010, "103.77.192.4", "-", "web_request", path="/login?u=admin' OR 1=1--")
    add(1200, "10.0.0.23", "bob", "sudo", command="sudo su -")
    add(1300, "10.0.0.23", "bob", "outbound", bytes=850_000_000, dest="91.214.124.7")
    return sorted(logs, key=lambda l: l["ts"])

def detect(logs):
    by_ip = defaultdict(list)
    for l in logs:
        by_ip[l.get("src_ip", "?")].append(l)
    alerts = []
    def alert(rule, sev, mitre, ip, user, desc, ev):
        alerts.append({"id": f"ALR-{len(alerts)+1:03d}", "rule": rule, "severity": sev,
                       "mitre": mitre, "src_ip": ip, "user": user, "description": desc,
                       "evidence": ev[:6], "status": "open"})
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e["event"] == "login_failed"]
        succ = [e for e in evs if e["event"] == "login_success"]
        if len(fails) >= 5:
            alert("Brute Force", "High", "T1110 Brute Force", ip, fails[0].get("user"),
                  f"{len(fails)} failed logins from {ip}", fails)
            if succ and succ[-1]["ts"] > fails[-1]["ts"]:
                alert("Possible Account Compromise", "Critical", "T1078 Valid Accounts", ip,
                      succ[-1].get("user"), f"Successful login right after {len(fails)} failures", fails[-2:] + succ[-1:])
        ports = {e["port"] for e in evs if e["event"] == "port_probe"}
        if len(ports) >= 8:
            alert("Port Scan", "Medium", "T1046 Network Service Discovery", ip, "-",
                  f"{len(ports)} distinct ports probed", [e for e in evs if e["event"] == "port_probe"])
        web = [e for e in evs if e["event"] == "web_request" and SQLI.search(e.get("path", ""))]
        if web:
            alert("Web Attack (SQLi/XSS/Traversal)", "High", "T1190 Exploit Public-Facing App", ip, "-",
                  f"{len(web)} malicious web requests", web)
        for e in evs:
            if e["event"] == "sudo" and e.get("user") not in ADMINS:
                alert("Privilege Escalation", "High", "T1068 Privilege Escalation", ip, e["user"],
                      f"Non-admin '{e['user']}' ran: {e.get('command')}", [e])
            if e["event"] == "outbound" and e.get("bytes", 0) > EXFIL_BYTES:
                alert("Data Exfiltration", "Critical", "T1041 Exfiltration Over C2", ip, e.get("user"),
                      f"{e['bytes']//1_000_000} MB sent to {e.get('dest')}", [e])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    alerts.sort(key=lambda a: order[a["severity"]])
    return alerts
