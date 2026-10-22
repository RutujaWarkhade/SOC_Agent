import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import detector, agent

FRONT = os.path.join(os.path.dirname(__file__), "..", "frontend")
app = Flask(__name__, static_folder=FRONT, static_url_path="")
CORS(app)

STATE = {"logs": [], "alerts": [], "blocklist": []}

@app.get("/")
def index():
    return send_from_directory(FRONT, "index.html")

def _load(logs):
    STATE["logs"] = logs
    STATE["alerts"] = detector.detect(logs)

@app.post("/api/generate")
def generate():
    _load(detector.generate_logs())
    return jsonify(ok=True, logs=len(STATE["logs"]), alerts=len(STATE["alerts"]))

@app.post("/api/upload")
def upload():
    logs = request.get_json(force=True)
    if not isinstance(logs, list):
        return jsonify(error="Expected a JSON array of log events"), 400
    _load(sorted(logs, key=lambda l: l.get("ts", "")))
    return jsonify(ok=True, logs=len(logs), alerts=len(STATE["alerts"]))

@app.get("/api/alerts")
def alerts():
    return jsonify(alerts=STATE["alerts"], blocklist=STATE["blocklist"], total_logs=len(STATE["logs"]),
                   llm_enabled=bool(os.getenv("ANTHROPIC_API_KEY")))

def _find(aid):
    return next((a for a in STATE["alerts"] if a["id"] == aid), None)

@app.post("/api/investigate/<aid>")
def investigate(aid):
    a = _find(aid)
    if not a:
        return jsonify(error="Alert not found"), 404
    report, steps = agent.investigate(a, STATE["logs"])
    a["report"], a["steps"] = report, steps
    a["status"] = "investigated"
    return jsonify(report=report, steps=steps)

@app.post("/api/block")
def block():
    ip = (request.get_json(force=True) or {}).get("ip")
    if not ip:
        return jsonify(error="ip required"), 400
    if ip not in STATE["blocklist"]:
        STATE["blocklist"].append(ip)          # simulated firewall action
    for a in STATE["alerts"]:
        if a["src_ip"] == ip:
            a["status"] = "contained"
    return jsonify(ok=True, blocklist=STATE["blocklist"])

if __name__ == "__main__":
    _load(detector.generate_logs())
    app.run(debug=True, port=5000)
