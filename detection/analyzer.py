from detection import rules
from llm.client import classify_alert

def run_detection(rows):
    """
    Takes pre-fetched DB rows
    Returns alerts (no DB interaction)
    """

    print(f"[INFO] Running detection on {len(rows)} rows")

    all_alerts = []

    # call rules
    all_alerts += rules.detect_port_scan(rows)

    print(f"[INFO] Alerts generated: {len(all_alerts)}")

    # LLM Layer
    for alert in all_alerts:
        try:
            unique_ports = alert.get("ports", 0)
            connections = alert.get("connections", 0)

            llm_result = classify_alert(
                alert.get("src_ip"),
                alert.get("dst_ip"),
                connections,
                unique_ports
            )

            if llm_result:
                alert["threat_level"] = llm_result.get("threat_level", "Unknown")
                alert["llm_type"] = llm_result.get("type", "Unknown")
                alert["llm_reason"] = llm_result.get("reason", "")

            else:
                alert["threat_level"] = "Unknown"
                alert["llm_type"] = "Unknown"
                alert["llm_reason"] = "LLM unavailable"

        except Exception as e:
            print(f"[LLM ERROR] {e}")
            alert["threat_level"] = "Error"
            alert["llm_type"] = "Error"
            alert["llm_reason"] = str(e)

    return all_alerts
