import json
import os
import time
from collections import Counter
from datetime import datetime

LOG = "var/log/cowrie/cowrie.json"

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
RESET = "\033[0m"

def clear():
    os.system("clear")

def load_events():
    events = []

    if not os.path.exists(LOG):
        return events

    try:
        with open(LOG, "r") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except:
                    continue
    except:
        pass

    return events

def dashboard():
    events = load_events()

    connections = 0
    successful = 0
    failed = 0
    commands = 0

    categories = Counter()
    command_counter = Counter()
    attackers = Counter()
    timeline = []

    for e in events:

        eventid = e.get("eventid", "")
        src = e.get("src_ip", e.get("src_ip", "unknown"))

        if eventid == "cowrie.session.connect":
            connections += 1
            attackers[src] += 1

        elif eventid == "cowrie.login.success":
            successful += 1

        elif eventid == "cowrie.login.failed":
            failed += 1

        elif eventid == "cowrie.command.input":

            commands += 1

            cmd = e.get("input", "").strip()

            command_counter[cmd] += 1

            low = cmd.lower()

            if low.startswith(("whoami", "id ", "id", "pwd", "hostname", "uname")):
                category = "RECON"

            elif low.startswith(("ls", "find ", "locate ", "tree")):
                category = "FILE ENUM"

            elif low.startswith(("ip ", "ifconfig", "netstat", "ss ", "nmap", "ping ")):
                category = "NETWORK ENUM"

            elif any(x in low for x in
                     ["/etc/passwd", "/etc/shadow", "getent passwd",
                      ".ssh/", "authorized_keys"]):
                category = "CREDENTIAL ENUM"

            elif low.startswith(("wget ", "curl ", "fetch ", "aria2c ")):
                category = "DOWNLOAD"

            elif low.startswith(("chmod ", "chown ", "chgrp ", "setfacl ")):
                category = "PERMISSION"

            elif low.startswith(("sudo ", "sudo", "su ", "su", "doas ")):
                category = "PRIV ESC"

            elif low in ("bash", "sh", "/bin/bash", "/bin/sh"):
                category = "SHELL"

            else:
                category = "OTHER"

            categories[category] += 1

            timeline.append(
                (
                    e.get("timestamp", "")[-8:],
                    category,
                    cmd
                )
            )

    clear()

    print(CYAN + "=" * 78 + RESET)
    print(CYAN + "                 COWRIE SOC DASHBOARD" + RESET)
    print(CYAN + "=" * 78 + RESET)

    print()

    print(
        f"{WHITE}"
        f"CONNECTIONS : {connections:<8}"
        f"LOGINS : {successful:<8}"
        f"FAILED : {failed:<8}"
        f"COMMANDS : {commands}"
        f"{RESET}"
    )

    print()
    print(MAGENTA + "ATTACK CATEGORIES" + RESET)
    print("-" * 78)

    if categories:
        for cat, count in categories.most_common():
            bar = "█" * min(count, 40)

            color = RED if cat in (
                "DOWNLOAD",
                "PERMISSION",
                "PRIV ESC"
            ) else YELLOW

            print(
                f"{cat:<20} "
                f"{color}{bar}{RESET} {count}"
            )
    else:
        print("No activity detected.")

    print()
    print(MAGENTA + "TOP COMMANDS" + RESET)
    print("-" * 78)

    for cmd, count in command_counter.most_common(8):
        print(f"{count:<4} {cmd}")

    print()
    print(MAGENTA + "ATTACKERS" + RESET)
    print("-" * 78)

    for ip, count in attackers.most_common():
        print(
            f"{RED}{ip:<20}{RESET}"
            f" connections={count}"
        )

    print()
    print(MAGENTA + "RECENT ACTIVITY" + RESET)
    print("-" * 78)

    for timestamp, category, cmd in timeline[-8:]:
        print(
            f"{timestamp:<10} "
            f"{category:<18} "
            f"{cmd}"
        )

    print()
    print(CYAN + "=" * 78 + RESET)
    print(
        GREEN +
        "LIVE • Refreshing every 2 seconds • Ctrl+C to exit"
        + RESET
    )

def main():

    print("Starting Cowrie SOC Dashboard...")

    try:
        while True:
            dashboard()
            time.sleep(2)

    except KeyboardInterrupt:
        clear()
        print(GREEN + "Dashboard stopped." + RESET)

if __name__ == "__main__":
    main()
