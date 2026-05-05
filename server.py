import pyshark
import mysql.connector
import asyncio
import threading
import time
from detection.analyzer import run_detection
from datetime import datetime
import signal
import sys
import os

# Alert Logging
# --------------------
LOG_PATH = None


def init_log():
    global LOG_PATH
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    LOG_PATH = f"logs/alerts_{timestamp}.log"

    print(f"[INFO] Logging alerts to {LOG_PATH}")


def log_alert(alert):
    global LOG_PATH

    if LOG_PATH is None:
        init_log()

    line = (
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"{alert['severity']} {alert['type']} "
        f"{alert['src_ip']} → {alert['dst_ip']} | "
        f"{alert.get('llm_type', '')} | "
        f"{alert.get('llm_reason', '')}"
    )

    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


""" OLD SELECTOR LOGIC
#-------User Input for Ethernet or Wireless-----------------
def select_interface():
    import pyshark

    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()

    print("[INFO] Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

    while True:
        try:
            choice = int(input("Select interface index: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("[ERROR] Invalid selection. Try again.")
        except ValueError:
            print("[ERROR] Enter a valid number.")

"""


# --------------------
# Database Connection
# --------------------
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="netdefender",
        password="1234",
        database="netcap",
        autocommit=False,
    )


db = get_db()
cursor = db.cursor()
# -----------------

insert_query = """
INSERT INTO packets
(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
VALUES (%s, %s, %s, %s, %s, %s, %s)
"""

BATCH_SIZE = 200
batch = []


# --------------------
# Packet Handler
# --------------------
def packet_handler(pkt):
    try:
        timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp))

        src_ip = pkt.ip.src if hasattr(pkt, "ip") else None
        dst_ip = pkt.ip.dst if hasattr(pkt, "ip") else None

        src_port = None
        dst_port = None

        if hasattr(pkt, "tcp"):
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)

        protocol = pkt.highest_layer[:10]
        length = int(pkt.length)

        batch.append((timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length))

        if len(batch) >= BATCH_SIZE:
            cursor.executemany(insert_query, batch)
            db.commit()
            batch.clear()
            print("Committed batch")

    except Exception as e:
        print("Packet error:", e)


# -----Fetch Function----------


def fetch_connections(cursor):
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


# --------Alert Insertion---No-Dups-----
def insert_or_update_alert(cursor, alert):

    # Build description based on alert type
    if alert["type"] == "PORT_SCAN":
        description = (
            f"Port scan: {alert['ports']} ports, " f"{alert['connections']} connections"
        )

    elif alert["type"] == "HIGH_TRAFFIC":
        description = f"High traffic: {alert['connections']} connections"

    else:
        description = "Unknown alert type"

    # Check for existing alert (dedup window)
    cursor.execute(
        """
        SELECT id, `count` FROM alerts
        WHERE type=%s AND source_ip=%s AND destination_ip=%s
        AND timestamp >= NOW() - INTERVAL 30 SECOND
    """,
        (alert["type"], alert["src_ip"], alert["dst_ip"]),
    )

    result = cursor.fetchone()

    if result:
        alert_id, count = result
        cursor.execute(
            """
            UPDATE alerts
            SET last_seen=NOW(), count=%s
            WHERE id=%s
        """,
            (count + 1, alert_id),
        )
    else:
        cursor.execute(
            """
            INSERT INTO alerts (
                type, source_ip, destination_ip,
                description, timestamp, last_seen, count
            )
            VALUES (%s, %s, %s, %s, NOW(), NOW(), 1)
        """,
            (alert["type"], alert["src_ip"], alert["dst_ip"], description),
        )


# ---------------Detection Threading-------------
def detection_loop():
    db = get_db()
    cursor = db.cursor()

    while True:
        try:
            print("[INFO] Running detection cycle...")

            rows = fetch_connections(cursor)
            alerts = run_detection(rows)

            for alert in alerts:
                print(f"[ALERT] {alert}")

                log_alert(alert)  # <-- NEW (writes to file)

                insert_or_update_alert(cursor, alert)

            db.commit()

        except Exception as e:
            print("[ERROR] Detection loop:", e)

        time.sleep(10)


# --------------------
# Graceful Shutdown
# --------------------
def shutdown(sig, frame):
    print("Shutting down...")
    if batch:
        cursor.executemany(insert_query, batch)
        db.commit()
    cursor.close()
    db.close()
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)

# --------------------
# Start Capture
try:
    asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)


# ---------------------
# Validation of Interface
def is_interface_valid(interface):
    import subprocess

    result = subprocess.run(["ip", "link", "show", interface], capture_output=True)
    return result.returncode == 0


print("Starting capture...")

# ---Accepts CLI arguments------------
if len(sys.argv) < 2:
    print("[ERROR] No interface provided")
    print("Usage: python server.py <interface>")
    sys.exit(1)

selected_interface = sys.argv[1]
print(f"[INFO] Using interface: {selected_interface}")


""" OLD SELECTOR LOGIC
#---------Integration of Interface Selection-----------_
selected_interface = select_interface()
print(f"[INFO] Using interface: {selected_interface}")
"""
capture = pyshark.LiveCapture(interface=selected_interface)

# ------------Threading Init------------------------------------
detection_thread = threading.Thread(target=detection_loop, daemon=True)
detection_thread.start()
# -------------Program Start-----------------------------------------
capture.apply_on_packets(packet_handler)
