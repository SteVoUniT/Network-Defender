# detection/analyzer.py

from detection import rules

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

    return all_alerts
