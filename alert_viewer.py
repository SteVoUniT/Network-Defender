import os
import time
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML


def find_latest_log():
    LOG_DIR = "logs"

    if not os.path.exists(LOG_DIR):
        return None

    files = [
        os.path.join(LOG_DIR, f)
        for f in os.listdir(LOG_DIR)
        if f.startswith("alerts_")
    ]

    if not files:
        return None

    return max(files, key=os.path.getmtime)


def display_line(line):
    print_formatted_text(HTML(
        f"<ansired><b>{line.strip()}</b></ansired>"
    ))


def follow(file, current_path):
    file.seek(0, 2)

    while True:
        line = file.readline()

        if line:
            display_line(line)
            continue

        # check for new file
        latest = find_latest_log()
        if latest and latest != current_path:
            print(f"[INFO] Switching to {latest}")
            return latest

        time.sleep(0.1)  # faster polling (was 0.2)

if __name__ == "__main__":
    print("[INFO] Alert Viewer Started")

    current_log = None

    while True:
        while current_log is None:
            current_log = find_latest_log()
            if current_log is None:
                print("[WAIT] Waiting for log file...")
                time.sleep(1)

        print(f"[INFO] Following {current_log}")

        try:
            with open(current_log, "r") as f:
                current_log = follow(f, current_log)

        except KeyboardInterrupt:
            print("\n[INFO] Viewer stopped.")
            break

        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(1)
