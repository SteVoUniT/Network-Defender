import requests
from functools import lru_cache

LLM_URL = "http://100.87.225.53:5454/v1/chat/completions"
MODEL_NAME = "microsoft_Phi-3-mini-4k-instruct-gguf_Phi-3-mini-4k-instruct-q4.gguf"


def test_connection():
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "user", "content": "Say: connection OK"}
        ],
        "temperature": 0.0,
        "max_tokens": 20
    }

    try:
        r = requests.post(LLM_URL, json=payload, timeout=10)
        r.raise_for_status()

        data = r.json()
        print("[LLM RAW RESPONSE]")
        print(data)

        content = data["choices"][0]["message"]["content"]
        print("\n[LLM PARSED]")
        print(content.strip())

    except Exception as e:
        print(f"[LLM ERROR] {e}")


# ---- small cache to avoid repeated calls for similar values ----
@lru_cache(maxsize=128)
def classify_alert(src_ip, dst_ip, total_connections, unique_ports):
    # very short prompt for speed
    user_content = f"""
	Ports:{unique_ports} Conns:{total_connections}

	Rules:
	Ports = 0 → NOT Port Scan
	>50 ports = HIGH Port Scan
	>20 ports = MEDIUM Port Scan
	Ports < 10 AND Conns > 100 → Flood

	Output:
	Threat Level:<Low/Medium/High>
	Type:<Normal/Port Scan/Flood/Suspicious>
	Reason:<short sentence mentioning ports or connections>
	"""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {
                "role": "system",
                "content": "You classify network activity. Follow rules exactly. Output only the format."
            },
            {
                "role": "user",
                "content": user_content
            }
        ],
        "temperature": 0.0,
        "max_tokens": 60
    }

    try:
        r = requests.post(LLM_URL, json=payload, timeout=10)
        r.raise_for_status()

        data = r.json()
        content = data["choices"][0]["message"]["content"]

        return parse_llm_response(content)

    except Exception as e:
        print(f"[LLM ERROR] {e}")
        return {
            "threat_level": "Unknown",
            "type": "Unknown",
            "reason": "LLM unavailable"
        }


def parse_llm_response(text):
    lines = text.split("\n")

    threat = ""
    typ = ""
    reason = ""

    for line in lines:
        line = line.strip()

        if line.lower().startswith("threat"):
            threat = line.split(":", 1)[-1].strip()

        elif line.lower().startswith("type"):
            typ = line.split(":", 1)[-1].strip()

        elif line.lower().startswith("reason"):
            reason = line.split(":", 1)[-1].strip()

    return {
        "threat_level": threat,
        "type": typ,
        "reason": reason
    }


if __name__ == "__main__":
    print("=== Testing LLM Connection ===")
    test_connection()

    print("\n=== Testing Classification ===")
    result = classify_alert(
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        total_connections=120,
        unique_ports=75
    )

    print("\n[CLASSIFICATION RESULT]")
    print(result)
