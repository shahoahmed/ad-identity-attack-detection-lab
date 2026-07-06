import ollama
import json
from datetime import datetime

SOC_PROMPT = """You are a senior SOC analyst. When given a security alert analyze it and respond with exactly this format:

SUMMARY: [what happened in 2 sentences]
MITRE: [technique ID and name]
VERDICT: [TRUE POSITIVE or FALSE POSITIVE] - [one sentence reason]
ACTION: [single most important next step]
SEVERITY: [CRITICAL, HIGH, MEDIUM, or LOW]"""

def triage_alert(alert):
    message = f"""Analyze this security alert:

Rule: {alert.get('rule', 'Unknown')}
Severity: {alert.get('severity', 'Unknown')}
Risk Score: {alert.get('risk_score', 0)}
AI Anomaly Score: {alert.get('anomaly_score', 0)}
Timestamp: {alert.get('timestamp', 'Unknown')}"""

    response = ollama.chat(
        model='llama3.2',
        messages=[
            {'role': 'system', 'content': SOC_PROMPT},
            {'role': 'user', 'content': message}
        ]
    )
    return response['message']['content']

def run_triage():
    print("\n" + "="*55)
    print("OLLAMA LLM SOC TRIAGE - Llama 3.2")
    print(f"Model: Local, Private, Zero Cost")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*55)

    try:
        with open("scored_alerts.json", "r") as f:
            alerts = json.load(f)
    except FileNotFoundError:
        print("Run isolation_scorer.py first.")
        return

    for i, alert in enumerate(alerts[:3], 1):
        print(f"\n[Alert {i}] {alert.get('rule', 'Unknown')}")
        print(f"AI Score: {alert.get('anomaly_score')} | Severity: {alert.get('severity')}")
        print("-" * 40)
        analysis = triage_alert(alert)
        print(analysis)

    print("\n" + "="*55)
    print("LLM triage complete.")
    print("="*55)

if __name__ == "__main__":
    run_triage()