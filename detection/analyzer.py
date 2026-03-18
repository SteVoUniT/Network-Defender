import mysql.connector
import ipaddress

PORT_THRESHOLD = 20  # number of unique ports to trigger alert


def get_db():
    print("[INFO] Connecting to database...")
    return mysql.connector.connect(
        host="localhost",
        user="netdefender",
        password="1234",
        database="netcap"
    )


def classify_ip(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return "internal"
        else:
            return "external"
    except:
        return "unknown"


def fetch_connections(cursor):
    print("[INFO] Fetching recent connections...")
    cursor.execute("""
        SELECT
            src_ip,
            dst_ip,
            COUNT(DISTINCT dst_port) as unique_ports,
            COUNT(*) as total_connections
        FROM packets
        WHERE timestamp > NOW() - INTERVAL 30 SECOND
        AND src_ip IS NOT NULL
        AND dst_ip IS NOT NULL
        AND dst_ip NOT LIKE '224.%'
        GROUP BY src_ip, dst_ip
    """)
    return cursor.fetchall()


def store_alert(cursor, alert):
    description = (
        f"Port scan: {alert['ports']} ports, "
        f"{alert['connections']} connections "
        f"({alert['src_type']} source)"
    )

    cursor.execute("""
        INSERT INTO alerts (type, source_ip, destination_ip, description)
        VALUES (%s, %s, %s, %s)
    """, (
        alert["type"],
        alert["src"],
        alert["dst"],
        description
    ))


def run_detection():
    print("[INFO] Starting detection run...")

    db = get_db()
    cursor = db.cursor()

    rows = fetch_connections(cursor)
    print(f"[INFO] Rows fetched: {len(rows)}")

    alerts = []
    seen_pairs = set()  # prevents duplicate bidirectional alerts

    for row in rows:
        print(f"[DEBUG] Row: {row}")

    for src_ip, dst_ip, unique_ports, total_connections in rows:
        # skip non-suspicious traffic
        if not unique_ports or unique_ports <= PORT_THRESHOLD:
            continue

        # normalize pair to prevent A↔B duplicate alerts
        pair = tuple(sorted([src_ip, dst_ip]))

        if pair in seen_pairs:
            continue

        seen_pairs.add(pair)

        alert = {
            "type": "port_scan",
            "src": src_ip,
            "dst": dst_ip,
            "src_type": classify_ip(src_ip),
            "ports": unique_ports,
            "connections": total_connections
        }

        alerts.append(alert)

    print(f"[INFO] Alerts detected: {len(alerts)}")

    for alert in alerts:
        print(f"[ALERT] {alert}")
        store_alert(cursor, alert)

    db.commit()
    print("[INFO] Detection run complete.")

    cursor.close()
    db.close()


if __name__ == "__main__":
    run_detection()
