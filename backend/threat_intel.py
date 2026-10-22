"""Mock threat-intel feed. Replace with AbuseIPDB / VirusTotal / OTX in production."""
BAD_IPS = {
    "185.220.101.5": {"score": 95, "tags": ["tor-exit-node", "ssh-bruteforce"], "country": "DE"},
    "45.155.205.9":  {"score": 88, "tags": ["mass-scanner"], "country": "RU"},
    "103.77.192.4":  {"score": 80, "tags": ["web-exploit", "sqli-botnet"], "country": "IN"},
    "91.214.124.7":  {"score": 92, "tags": ["c2-server", "data-exfil"], "country": "UA"},
}

def lookup(ip: str) -> dict:
    if ip in BAD_IPS:
        return {"ip": ip, "known_malicious": True, **BAD_IPS[ip]}
    kind = "internal" if ip.startswith(("10.", "192.168.", "172.16.")) else "unknown-external"
    return {"ip": ip, "known_malicious": False, "score": 0, "tags": [kind]}
