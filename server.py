import pyshark
import mysql.connector
import asyncio
from datetime import datetime
import signal
import sys

# --------------------
# Database Connection
# --------------------
db = mysql.connector.connect(
    host="localhost",
    user="netdefender",
    password="1234",
    database="netcap",
    autocommit=False
)

cursor = db.cursor()

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

        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None

        src_port = None
        dst_port = None

        if hasattr(pkt, 'tcp'):
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
        elif hasattr(pkt, 'udp'):
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)

        protocol = pkt.highest_layer[:10]
        length = int(pkt.length)

        batch.append((
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length
        ))

        if len(batch) >= BATCH_SIZE:
            cursor.executemany(insert_query, batch)
            db.commit()
            batch.clear()
            print("Committed batch")

    except Exception as e:
        print("Packet error:", e)

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

print("Starting capture...")
capture = pyshark.LiveCapture(interface="enp7s0f4u1c2")
capture.apply_on_packets(packet_handler)
