from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
import numpy as np
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

es = Elasticsearch(
    "https://192.168.56.101:9200",
    basic_auth=("elastic", "Cf5D=MJy2n9lM*5oNJC5"),
    verify_certs=False
)

def get_alerts():
    query = {
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "size": 100
    }
    try:
        response = es.search(index=".alerts-security.alerts-default", body=query)
        return response["hits"]["hits"]
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return []

def extract_features(alerts):
    features = []
    metadata = []
    for alert in alerts:
        src = alert["_source"]
        try:
            ts = src.get("@timestamp", "")
            hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour if ts else 12
        except:
            hour = 12
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity = severity_map.get(src.get("kibana.alert.severity", "low"), 1)
        risk = float(src.get("kibana.alert.risk_score", 0))
        features.append([hour, severity, risk])
        metadata.append({
            "rule": src.get("kibana.alert.rule.name", "Unknown"),
            "severity": src.get("kibana.alert.severity", "unknown"),
            "risk_score": risk,
            "timestamp": ts
        })
    return np.array(features), metadata

def run_scorer():
    print("\n" + "="*55)
    print("AI ALERT SCORER - Isolation Forest")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*55)
    
    alerts = get_alerts()
    if not alerts:
        print("No alerts found in last 24 hours.")
        return
    
    print(f"Found {len(alerts)} alerts. Scoring with Isolation Forest...")
    features, metadata = extract_features(alerts)
    
    model = IsolationForest(contamination=0.2, random_state=42)
    predictions = model.fit_predict(features)
    scores = model.score_samples(features)
    normalized = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
    
    results = []
    for i, meta in enumerate(metadata):
        results.append({
            **meta,
            "anomaly_score": round(float(normalized[i]), 3),
            "is_anomaly": bool(predictions[i] == -1)
        })
    
    results.sort(key=lambda x: x["anomaly_score"], reverse=True)
    
    print(f"\nTop Alerts by AI Anomaly Score:\n")
    for r in results:
        flag = "ANOMALY" if r["is_anomaly"] else "normal"
        print(f"[{flag}] Score: {r['anomaly_score']} | {r['rule']}")
        print(f"         Severity: {r['severity']} | Risk: {r['risk_score']} | {r['timestamp'][:19]}\n")
    
    with open("scored_alerts.json", "w") as f:
        json.dump(results[:5], f, indent=2)
    
    anomaly_count = sum(1 for r in results if r["is_anomaly"])
    print(f"Total alerts scored: {len(results)}")
    print(f"Flagged as anomalies: {anomaly_count}")
    print(f"Top 5 saved to scored_alerts.json for LLM triage")
    print("="*55)

if __name__ == "__main__":
    run_scorer()