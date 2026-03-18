THRESHOLD = 50

def detect_port_scan(rows):
    alerts = []

    for src_ip, dst_ip, connections in rows:
        if connections > THRESHOLD:
            alerts.append({
                "type": "port_scan",
                "src": src_ip,
                "dst": dst_ip,
                "connections": connections
            })

    return alerts
