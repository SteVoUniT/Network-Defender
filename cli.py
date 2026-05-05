from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import radiolist_dialog
import subprocess
import sys

process = None
alert_process = None
selected_interface = None


def start_alert_viewer():
    global alert_process

    if alert_process is None:
        print("[INFO] Launching alert viewer...")

        alert_process = subprocess.Popen(
            ["mate-terminal", "--", "python", "alert_viewer.py"]
        )
    else:
        print("[WARN] Alert viewer already running")


# =========================
# Interface Selection
# =========================
def select_interface():
    result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)

    lines = result.stdout.strip().split("\n")

    interfaces = []

    for i, line in enumerate(lines):
        parts = line.split(". ", 1)
        if len(parts) == 2:
            _, name = parts
            interfaces.append((name, name))  # (value, label)

    choice = radiolist_dialog(
        title="Select Network Interface",
        text="Use arrow keys and press Enter:",
        values=interfaces,
    ).run()

    return choice


# =========================
# Capture Control (Spawns a Terminal Window with Output)
# =========================
def start_capture(interface):
    global process

    if process is None:
        print(f"[INFO] Launching capture in new terminal on {interface}...")

        process = subprocess.Popen(
            [
                "mate-terminal",
                "--",
                "bash",
                "-c",
                f"cd /home/stevopc/Network-Defender && python server.py {interface}; exec bash",
            ]
        )

        start_alert_viewer()

    else:
        print("[WARN] Capture already running")


def stop_capture():
    global process, alert_process

    if process is not None:
        print("[INFO] Stopping capture...")

        subprocess.run(["pkill", "-f", "server.py"])

        process = None

    if alert_process is not None:
        print("[INFO] Stopping alert viewer...")

        subprocess.run(["pkill", "-f", "alert_viewer.py"])
        alert_process = None

    else:
        print("[WARN] No capture running")


def run_detection():
    print("[INFO] Running detection...")
    subprocess.run(["python", "-m", "detection.analyzer"])


# =========================
# Main Menu (Arrow UI)
# =========================
def menu():
    global selected_interface

    while True:
        choice = radiolist_dialog(
            title="Network Defender CLI",
            text=f"Current Interface: {selected_interface}",
            values=[
                ("select", "Select Interface"),
                ("start", "Start Capture"),
                ("stop", "Stop Capture"),
                ("detect", "Run Detection"),
                ("exit", "Exit"),
            ],
        ).run()

        if choice == "select":
            selected_interface = select_interface()

        elif choice == "start":
            if selected_interface is None:
                print("[WARN] Select interface first")
            else:
                start_capture(selected_interface)

        elif choice == "stop":
            stop_capture()

        elif choice == "detect":
            run_detection()

        elif choice == "exit":
            stop_capture()
            print("[INFO] Exiting...")
            sys.exit(0)


if __name__ == "__main__":
    menu()
