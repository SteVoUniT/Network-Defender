from detection.analyzer import run_detection

rows = [
    ("192.168.1.100", "8.8.8.8", 75, 120),  # triggers port scan
    ("10.0.0.5", "1.1.1.1", 10, 20)          # normal traffic
]

alerts = run_detection(rows)

for alert in alerts:
    print(alert)
