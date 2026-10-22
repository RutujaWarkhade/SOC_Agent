"""SOC triage agent. Uses Claude tool-use if ANTHROPIC_API_KEY is set, else an offline playbook.
Agent tools are READ-ONLY; blocking an IP needs human approval in the UI."""
import json, os
import threat_intel

MODEL = os.getenv("MODEL", "claude-sonnet-5-5")
SYSTEM = ("You are a Tier-1 SOC analyst agent. Investigate the alert using tools, then reply with: "
          "1) Verdict (True Positive / Suspicious / False Positive) 2) Reasoning 3) Recommended actions. "
          "Be concise. You cannot block IPs yourself; recommend actions for a human to approve.")
TOOLS = [
    {"name": "get_ip_reputation", "description": "Threat-intel lookup for an IP.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "get_ip_activity", "description": "Summarise all log events from an IP.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
]

def run_tool(name, args, logs):
    if name == "get_ip_reputation":
        return threat_intel.lookup(args["ip"])
    if name == "get_ip_activity":
        evs = [l for l in logs if l.get("src_ip") == args["ip"]]
        counts = {}
        for e in evs:
            counts[e["event"]] = counts.get(e["event"], 0) + 1
        return {"total_events": len(evs), "by_type": counts,
                "first_seen": evs[0]["ts"] if evs else None, "last_seen": evs[-1]["ts"] if evs else None}
    return {"error": "unknown tool"}

def _offline(alert, logs):
    steps = []
    rep = threat_intel.lookup(alert["src_ip"]); steps.append({"tool": "get_ip_reputation", "result": rep})
    act = run_tool("get_ip_activity", {"ip": alert["src_ip"]}, logs)
    steps.append({"tool": "get_ip_activity", "result": act})
    sev = alert["severity"]
    if rep["known_malicious"] or sev == "Critical":
        verdict, actions = "True Positive", ["Block source IP at firewall", "Reset credentials for affected user", "Escalate to Tier-2 / open incident"]
    elif sev == "High":
        verdict, actions = "Suspicious", ["Monitor IP for 24h", "Review affected user activity", "Consider temporary block"]
    else:
        verdict, actions = "Suspicious", ["Add IP to watchlist", "Re-check on next scan"]
    report = (f"Verdict: {verdict}\n\nReasoning: {alert['rule']} ({alert['mitre']}). {alert['description']}. "
              f"Reputation score {rep['score']}/100 (tags: {', '.join(rep['tags'])}). "
              f"{act['total_events']} events seen from this IP.\n\nRecommended actions:\n- " + "\n- ".join(actions)
              + "\n\n(offline playbook mode - set ANTHROPIC_API_KEY for LLM reasoning)")
    return report, steps

def investigate(alert, logs):
    if not os.getenv("ANTHROPIC_API_KEY"):
        return _offline(alert, logs)
    import anthropic
    client = anthropic.Anthropic()
    steps = []
    messages = [{"role": "user", "content": "Investigate this alert:\n" + json.dumps(alert, indent=2)}]
    try:
        for _ in range(6):
            r = client.messages.create(model=MODEL, max_tokens=1000, system=SYSTEM, tools=TOOLS, messages=messages)
            if r.stop_reason != "tool_use":
                return "".join(b.text for b in r.content if b.type == "text"), steps
            messages.append({"role": "assistant", "content": r.content})
            results = []
            for b in r.content:
                if b.type == "tool_use":
                    out = run_tool(b.name, b.input, logs)
                    steps.append({"tool": b.name, "input": b.input, "result": out})
                    results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(out)})
            messages.append({"role": "user", "content": results})
        return "Agent stopped: step limit reached.", steps
    except Exception as e:
        report, s = _offline(alert, logs)
        return f"LLM call failed ({e}); fell back to playbook.\n\n{report}", s
