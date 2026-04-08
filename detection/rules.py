THRESHOLD = 50  # total connections
PORT_THRESHOLD = 20  # unique ports


def detect_port_scan(rows):
    alerts = []

    for src_ip, dst_ip, unique_ports, total_connections in rows:

        # detect port scan based on unique ports
        if unique_ports > PORT_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports": unique_ports,
                "connections": total_connections,
                "severity": "HIGH",
                "confidence": 0.9
            })

        # optional: detect high traffic (DoS-ish)
        elif total_connections > THRESHOLD:
            alerts.append({
                "type": "HIGH_TRAFFIC",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "connections": total_connections,
                "severity": "MEDIUM",
                "confidence": 0.7
            })

    return alerts
