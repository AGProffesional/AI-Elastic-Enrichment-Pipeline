from flask import Flask, request, jsonify
import requests
import json
import re

app = Flask(__name__)

DEEPSEEK_URL = "DEEPSEEK_URL"


# ---------------------------
# VALIDATOR (works for ALL alerts)
# ---------------------------

VALID_MITRE = {
    "T1059", "T1021", "T1071", "T1047", "T1105", "T1569",
    "T1218", "T1036", "T1053", "T1003", "T1110", "T1555"
}

def validate_model_output(model_json, alert_json):
    fixed = {}

    required_fields = [
        "mitre_techniques",
        "attack_classification",
        "severity_justification",
        "host_context",
        "process_context",
        "pivot_indicators",
        "attacker_intent",
        "recommended_actions",
        "true_false_assessment"
    ]

    # Ensure all required fields exist
    for field in required_fields:
        fixed[field] = model_json.get(field, "not present in alert")

    # 1. MITRE techniques
    techniques = model_json.get("mitre_techniques", [])
    fixed["mitre_techniques"] = [t for t in techniques if t in VALID_MITRE]

    # 2. Attacker intent
    fixed["attacker_intent"] = "not present in alert"

    # 3. Recommended actions
    fixed["recommended_actions"] = []

    # 4. Pivot indicators
    pivots = []

    if "source" in alert_json and "ip" in alert_json["source"]:
        pivots.append(alert_json["source"]["ip"])

    if "destination" in alert_json and "ip" in alert_json["destination"]:
        pivots.append(alert_json["destination"]["ip"])

    if "destination" in alert_json and "port" in alert_json["destination"]:
        pivots.append(str(alert_json["destination"]["port"]))

    if "process" in alert_json and "command_line" in alert_json["process"]:
        pivots.append(alert_json["process"]["command_line"])

    fixed["pivot_indicators"] = pivots

        # 5. Normalize host_context
    host_name = alert_json.get("host", {}).get("name")
    host_ip = alert_json.get("host", {}).get("ip")
    host_os = alert_json.get("host", {}).get("os", {}).get("name")

    host_parts = []
    if host_name:
        host_parts.append(host_name)
    if host_ip:
        host_parts.append(host_ip)
    if host_os:
        host_parts.append(host_os)

    if len(host_parts) >= 2:
        fixed["host_context"] = f"{host_parts[0]} ({', '.join(host_parts[1:])})"
    elif len(host_parts) == 1:
        fixed["host_context"] = host_parts[0]
    else:
        fixed["host_context"] = "not present in alert"

    # 6. Normalize process_context
    proc = alert_json.get("process", {})
    pname = proc.get("name")
    pid = proc.get("pid")
    cmd = proc.get("command_line")

    if pname and pid and cmd:
        fixed["process_context"] = f"{pname} (PID {pid}) executed with command line: {cmd}"
    elif pname and pid:
        fixed["process_context"] = f"{pname} (PID {pid})"
    elif pname:
        fixed["process_context"] = pname
    else:
        fixed["process_context"] = "not present in alert"


    # 7. Severity justification
    sev = alert_json.get("kibana", {}).get("alert", {}).get("rule", {}).get("severity")
    risk = alert_json.get("kibana", {}).get("alert", {}).get("rule", {}).get("risk_score")

    if sev and risk:
        fixed["severity_justification"] = f"{sev.capitalize()} severity and risk_score {risk} as defined in the alert rule."
    else:
        fixed["severity_justification"] = "not present in alert"

    return fixed


# ---------------------------
# WEBHOOK ENDPOINT
# ---------------------------

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True, silent=True)
    alert_text = json.dumps(data, indent=2)

    payload = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior SOC analyst. Base your analysis ONLY on fields present in the provided Elastic Security alert JSON. "
                    "Do NOT invent fields, values, or indicators. Do NOT guess. Do NOT fabricate MITRE techniques, IPs, PIDs, usernames, or attack types.\n\n"
                    "You MUST output ONLY the following JSON structure:\n"
                    "{\n"
                    "  \"mitre_techniques\": [],\n"
                    "  \"attack_classification\": \"\",\n"
                    "  \"severity_justification\": \"\",\n"
                    "  \"host_context\": \"\",\n"
                    "  \"process_context\": \"\",\n"
                    "  \"pivot_indicators\": [],\n"
                    "  \"attacker_intent\": \"\",\n"
                    "  \"recommended_actions\": [],\n"
                    "  \"true_false_assessment\": \"\"\n"
                    "}\n\n"
                    "GENERAL RULES:\n"
                    "- All fields MUST be based ONLY on the JSON input.\n"
                    "- If information is missing, output: \"not present in alert\".\n"
                    "- Do NOT add extra fields.\n"
                    "- Do NOT output narrative paragraphs or explanations outside the JSON.\n"
                    "- Stay strictly within the JSON schema.\n\n"
                    "HOST/PROCESS CONTEXT:\n"
                    "- \"host_context\" MUST be a single string summarizing ONLY host fields present in the alert.\n"
                    "- \"process_context\" MUST be a single string summarizing ONLY process fields present in the alert.\n"
                    "- Do NOT add fields such as \"user\", \"parent process\", \"privilege_level\", or environment variables unless they exist in the alert.\n"
                    "- Do NOT reformat command_line into arrays or lists. Use the raw string exactly as provided.\n\n"
                    "MITRE TECHNIQUES:\n"
                    "- Behavioral inference IS allowed.\n"
                    "- Infer techniques ONLY from observable behavior in the command_line, process, network, or host fields.\n"
                    "- Use ONLY real ATT&CK technique IDs.\n"
                    "- If no technique can be inferred, return an empty list [].\n\n"
                    "PIVOT INDICATORS:\n"
                    "- Include ONLY values explicitly present in the alert.\n"
                    "- Do NOT invent or reformat indicators.\n\n"
                    "ATTACK CLASSIFICATION / INTENT / ACTIONS:\n"
                    "- \"attack_classification\" MUST be \"not present in alert\" unless explicitly stated.\n"
                    "- \"attacker_intent\" MUST be \"not present in alert\" unless explicitly stated.\n"
                    "- \"recommended_actions\" MUST be an empty list [] unless the alert explicitly contains malicious behavior.\n\n"
                    "SEVERITY JUSTIFICATION:\n"
                    "- MUST reference ONLY fields explicitly present in the alert.\n\n"
                    "TRUE/FALSE ASSESSMENT:\n"
                    "- MUST be \"not present in alert\" unless explicitly stated."
                )
            },
            {
                "role": "user",
                "content": f"Analyze the following Elastic Security alert JSON and fill the JSON fields:\n\n{alert_text}"
            }
        ]
    }

    # Send to DeepSeek
    response = requests.post(DEEPSEEK_URL, json=payload)
    raw_reply = response.json()["choices"][0]["message"]["content"]

    # Parse DeepSeek JSON safely
    try:
        model_json = json.loads(raw_reply)
    except:
        model_json = {}

    # Validate and clean output
    validated = validate_model_output(model_json, data)

    print("\n=== ALERT RECEIVED ===")
    print(alert_text)
    print("\n=== DEEPSEEK RAW OUTPUT ===")
    print(raw_reply)
    print("\n=== VALIDATED OUTPUT ===")
    print(validated)

    return jsonify({"status": "ok", "deepseek_reply": validated})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)

