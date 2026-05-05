THRESHOLD = 50        # total connections
PORT_THRESHOLD = 20   # unique ports

# make severity dynamic
def get_severity(confidence):
    if confidence > 0.8:
        return "HIGH"
    elif confidence > 0.5:
        return "MEDIUM"
    else:
        return "LOW"


def detect_port_scan(rows):
    alerts = []

    for src_ip, dst_ip, unique_ports, total_connections in rows:

        # PORT SCAN DETECTION
        if unique_ports > PORT_THRESHOLD:
            confidence = min(1.0, unique_ports / (PORT_THRESHOLD * 2))
            severity = get_severity(confidence)

            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports": unique_ports,
                "connections": total_connections,
                "severity": severity,
                "confidence": round(confidence, 2)
            })

        # HIGH TRAFFIC DETECTION
        elif total_connections > THRESHOLD:
            confidence = min(1.0, total_connections / (THRESHOLD * 2))
            severity = get_severity(confidence)

            alerts.append({
                "type": "HIGH_TRAFFIC",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "connections": total_connections,
                "severity": severity,
                "confidence": round(confidence, 2)
            })

    return alerts
