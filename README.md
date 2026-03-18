# Network Defender - Feature Detection Branch

Lightweight edge-based network monitoring and threat detection system.

- Captures live traffic using Pyshark (tshark)
- Stores structured packet data in MySQL
- Rule-based detection engine (MVP: port scan detection)
- Modular design for AI/LLM-based analysis

```
Traffic → Capture → DB → Detection → Alerts
```

```bash
python -m capture.packet_capture
python -m detection.analyzer
```

**Stack:** Python, Pyshark, MySQL  
**Focus:** Network Security, Edge Systems, Real-Time Analysis

---

Steven Alvarez
