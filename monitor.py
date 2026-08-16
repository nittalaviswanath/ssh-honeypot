#!/usr/bin/env python3

# ============================================================
# COWRIE SOC MONITOR v3
# ============================================================
# Features:
#   1. Real-time HIGH / CRITICAL alerts
#   2. Public-IP geolocation
#   3. Private/local IP detection
#   4. Detailed incident reports
#   5. MITRE ATT&CK technique mapping
#   6. Attack replay / chronological timeline
#   7. Attacker tracking
#   8. Attack classification
#   9. Command statistics
#  10. Persistent JSON history
#
# No external Python packages required.
# ============================================================

import json
import os
import time
import ipaddress
import urllib.request
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

LOG = "var/log/cowrie/cowrie.json"

HISTORY = "soc_history_v3.json"

REPORT_DIR = "reports"

WIDTH = 90

REFRESH_DELAY = 0.20

MAX_TIMELINE = 100

GEO_TIMEOUT = 4


# ============================================================
# COLORS
# ============================================================

RESET = "\033[0m"

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
ORANGE = "\033[38;5;208m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"
GRAY = "\033[90m"
MAGENTA = "\033[95m"


# ============================================================
# GLOBAL STATISTICS
# ============================================================

connections = 0

successful_logins = 0

failed_logins = 0

commands = 0

failed_commands = 0


attack_categories = Counter()

top_commands = Counter()

mitre_techniques = Counter()


# ============================================================
# SESSION / ATTACKER STORAGE
# ============================================================

sessions = {}

attackers = {}

timeline = []


# ============================================================
# TERMINAL HELPERS
# ============================================================

def clear_screen():
    print("\033[2J\033[H", end="")


def border(char="═"):
    return char * WIDTH


def box(text=""):
    text = str(text)

    if len(text) > WIDTH - 4:
        text = text[:WIDTH - 7] + "..."

    return "║ " + text.ljust(WIDTH - 3) + "║"


def section(title):
    print("╔" + border() + "╗")
    print(box(title.center(WIDTH - 2)))
    print("╚" + border() + "╝")


def severity_color(severity):
    if severity == "CRITICAL":
        return RED

    if severity == "HIGH":
        return ORANGE

    if severity == "MEDIUM":
        return YELLOW

    return GREEN


# ============================================================
# IP ANALYSIS
# ============================================================

def is_private_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )

    except Exception:
        return True


def network_type(ip):
    if not ip:
        return "UNKNOWN"

    if is_private_ip(ip):
        return "PRIVATE / LOCAL"

    return "PUBLIC INTERNET"


# ============================================================
# GEOLOCATION
# ============================================================

geo_cache = {}


def get_location(ip):

    if not ip:
        return {
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "isp": "UNKNOWN",
            "latitude": "-",
            "longitude": "-"
        }

    # Private IPs cannot be geolocated through public
    # Internet geolocation services.
    if is_private_ip(ip):

        return {
            "country": "LOCAL NETWORK",
            "region": "Private IP",
            "city": "Local",
            "isp": "Local Network",
            "latitude": "-",
            "longitude": "-"
        }

    if ip in geo_cache:
        return geo_cache[ip]

    result = {
        "country": "UNKNOWN",
        "region": "UNKNOWN",
        "city": "UNKNOWN",
        "isp": "UNKNOWN",
        "latitude": "-",
        "longitude": "-"
    }

    try:

        url = (
            "https://ipwho.is/"
            + urllib.parse.quote(ip)
        )

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":
                "Cowrie-SOC-Monitor/3.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=GEO_TIMEOUT
        ) as response:

            data = json.loads(
                response.read().decode()
            )

        if data.get("success"):

            connection = data.get(
                "connection",
                {}
            )

            result = {
                "country": data.get(
                    "country",
                    "UNKNOWN"
                ),
                "region": data.get(
                    "region",
                    "UNKNOWN"
                ),
                "city": data.get(
                    "city",
                    "UNKNOWN"
                ),
                "isp": connection.get(
                    "isp",
                    "UNKNOWN"
                ),
                "latitude": data.get(
                    "latitude",
                    "-"
                ),
                "longitude": data.get(
                    "longitude",
                    "-"
                )
            }

    except Exception:

        pass

    geo_cache[ip] = result

    return result


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

def map_mitre(command):

    cmd = command.lower().strip()

    mappings = []

    # User discovery
    if cmd in (
        "whoami",
        "id"
    ):
        mappings.append(
            (
                "T1033",
                "System Owner/User Discovery"
            )
        )

    # System information
    if (
        cmd == "uname"
        or cmd.startswith("uname ")
    ):
        mappings.append(
            (
                "T1082",
                "System Information Discovery"
            )
        )

    # Hostname
    if cmd == "hostname":
        mappings.append(
            (
                "T1033",
                "System Owner/User Discovery"
            )
        )

    # File discovery
    if (
        cmd in ("ls", "dir", "ll")
        or cmd.startswith("ls ")
        or cmd.startswith("find ")
        or cmd.startswith("locate ")
    ):
        mappings.append(
            (
                "T1083",
                "File and Directory Discovery"
            )
        )

    # Network configuration
    if (
        cmd.startswith("ip ")
        or cmd.startswith("ifconfig")
        or cmd.startswith("route")
    ):
        mappings.append(
            (
                "T1016",
                "System Network Configuration Discovery"
            )
        )

    # Network connections
    if (
        cmd.startswith("netstat")
        or cmd.startswith("ss ")
    ):
        mappings.append(
            (
                "T1049",
                "System Network Connections Discovery"
            )
        )

    # Process discovery
    if (
        cmd == "ps"
        or cmd.startswith("ps ")
        or cmd == "top"
    ):
        mappings.append(
            (
                "T1057",
                "Process Discovery"
            )
        )

    # Account discovery
    if (
        "/etc/passwd" in cmd
        or "getent passwd" in cmd
    ):
        mappings.append(
            (
                "T1087",
                "Account Discovery"
            )
        )

    # Permission / privilege discovery
    if (
        cmd == "groups"
        or cmd.startswith("groups ")
    ):
        mappings.append(
            (
                "T1069.001",
                "Permission Groups Discovery"
            )
        )

    # Download / transfer
    if (
        cmd.startswith("wget ")
        or cmd.startswith("curl ")
    ):
        mappings.append(
            (
                "T1105",
                "Ingress Tool Transfer"
            )
        )

    # Permission modification
    if (
        cmd.startswith("chmod ")
        or cmd.startswith("chown ")
    ):
        mappings.append(
            (
                "T1222",
                "File and Directory Permissions Modification"
            )
        )

    # Shell
    if cmd in (
        "bash",
        "sh",
        "/bin/bash",
        "/bin/sh"
    ):
        mappings.append(
            (
                "T1059.004",
                "Unix Shell"
            )
        )

    # Network scanning
    if (
        cmd.startswith("nmap ")
        or cmd == "nmap"
    ):
        mappings.append(
            (
                "T1046",
                "Network Service Scanning"
            )
        )

    # Remote system discovery
    if (
        cmd.startswith("ping ")
    ):
        mappings.append(
            (
                "T1018",
                "Remote System Discovery"
            )
        )

    # Credential discovery
    if (
        "/etc/shadow" in cmd
        or "passwd" in cmd
        and (
            "cat " in cmd
            or "grep " in cmd
        )
    ):
        mappings.append(
            (
                "T1003",
                "OS Credential Dumping"
            )
        )

    # Generic shell execution
    if (
        cmd.startswith("sudo ")
        or cmd == "sudo"
        or cmd == "su"
        or cmd.startswith("su ")
    ):
        mappings.append(
            (
                "T1548.003",
                "Sudo and Sudo Caching"
            )
        )

    return mappings


# ============================================================
# ATTACK CLASSIFICATION
# ============================================================

def classify_command(command):

    cmd = command.lower().strip()

    # --------------------------------------------------------
    # RECONNAISSANCE
    # --------------------------------------------------------

    if cmd in (
        "whoami",
        "id",
        "pwd",
        "hostname",
        "uname",
        "uname -a",
        "arch",
        "uptime",
        "w",
        "who",
        "last"
    ):
        return "RECON"

    # --------------------------------------------------------
    # FILE ENUMERATION
    # --------------------------------------------------------

    if (
        cmd in ("ls", "ll", "dir")
        or cmd.startswith("ls ")
        or cmd.startswith("find ")
        or cmd.startswith("locate ")
        or cmd.startswith("tree")
        or cmd.startswith("stat ")
        or cmd.startswith("file ")
        or cmd.startswith("du ")
        or cmd.startswith("df ")
    ):
        return "FILE ENUM"

    # --------------------------------------------------------
    # NETWORK ENUMERATION
    # --------------------------------------------------------

    if (
        cmd.startswith("ip ")
        or cmd.startswith("ifconfig")
        or cmd.startswith("netstat")
        or cmd.startswith("ss ")
        or cmd == "ss"
        or cmd.startswith("route")
        or cmd.startswith("arp")
        or cmd.startswith("ip neigh")
        or cmd.startswith("nmap")
        or cmd.startswith("ping ")
        or cmd.startswith("traceroute")
        or cmd.startswith("tracepath")
        or cmd.startswith("nslookup")
        or cmd.startswith("dig ")
        or cmd.startswith("host ")
    ):
        return "NETWORK ENUM"

    # --------------------------------------------------------
    # CREDENTIAL ENUMERATION
    # --------------------------------------------------------

    if (
        "/etc/passwd" in cmd
        or "/etc/shadow" in cmd
        or "getent passwd" in cmd
        or "getent group" in cmd
        or cmd.startswith("groups")
        or "history" in cmd
        or ".ssh/" in cmd
        or "authorized_keys" in cmd
    ):
        return "CREDENTIAL ENUM"

    # --------------------------------------------------------
    # DOWNLOAD / RETRIEVAL
    # --------------------------------------------------------

    if (
        cmd.startswith("wget ")
        or cmd == "wget"
        or cmd.startswith("curl ")
        or cmd == "curl"
        or cmd.startswith("fetch ")
        or cmd.startswith("aria2c ")
    ):
        return "DOWNLOAD"

    # --------------------------------------------------------
    # PERMISSION MANIPULATION
    # --------------------------------------------------------

    if (
        cmd.startswith("chmod ")
        or cmd.startswith("chown ")
        or cmd.startswith("chgrp ")
        or cmd.startswith("setfacl ")
    ):
        return "PERMISSION"

    # --------------------------------------------------------
    # PRIVILEGE ESCALATION
    # --------------------------------------------------------

    if (
        cmd == "sudo"
        or cmd.startswith("sudo ")
        or cmd == "su"
        or cmd.startswith("su ")
        or cmd.startswith("doas ")
    ):
        return "PRIV ESC"

    # --------------------------------------------------------
    # REMOTE ACCESS
    # --------------------------------------------------------

    if (
        cmd.startswith("ssh ")
        or cmd == "ssh"
        or cmd.startswith("scp ")
        or cmd.startswith("sftp ")
        or cmd.startswith("telnet ")
        or cmd.startswith("ftp ")
    ):
        return "REMOTE ACCESS"

    # --------------------------------------------------------
    # NETWORK / SOCKET TOOLS
    # --------------------------------------------------------

    if (
        cmd.startswith("nc ")
        or cmd == "nc"
        or cmd.startswith("netcat ")
        or cmd == "socat "
        or cmd.startswith("socat ")
    ):
        return "NETWORK"

    # --------------------------------------------------------
    # SHELL EXECUTION
    # --------------------------------------------------------

    if cmd in (
        "bash",
        "sh",
        "dash",
        "zsh",
        "ksh",
        "/bin/bash",
        "/bin/sh",
        "/bin/dash",
        "/bin/zsh"
    ):
        return "SHELL"

    if (
        cmd.startswith("bash -c ")
        or cmd.startswith("sh -c ")
        or cmd.startswith("python -c ")
        or cmd.startswith("python3 -c ")
        or cmd.startswith("perl -e ")
        or cmd.startswith("ruby -e ")
    ):
        return "SHELL"

    # --------------------------------------------------------
    # PERSISTENCE / SCHEDULED EXECUTION
    # --------------------------------------------------------

    if (
        "crontab" in cmd
        or cmd.startswith("cron")
        or cmd.startswith("systemctl enable")
        or cmd.startswith("systemctl start")
        or "/etc/cron" in cmd
        or "/etc/systemd" in cmd
    ):
        return "PERSISTENCE"

    # --------------------------------------------------------
    # PROCESS / SYSTEM ENUMERATION
    # --------------------------------------------------------

    if (
        cmd.startswith("ps ")
        or cmd == "ps"
        or cmd.startswith("top")
        or cmd.startswith("htop")
        or cmd.startswith("pstree")
        or cmd.startswith("free ")
        or cmd == "free"
        or cmd.startswith("mount")
        or cmd.startswith("lsblk")
    ):
        return "SYSTEM ENUM"

    # --------------------------------------------------------
    # COMMAND / SCRIPT EXECUTION
    # --------------------------------------------------------

    if (
        cmd.startswith("./")
        or cmd.startswith("../")
        or cmd.startswith("python ")
        or cmd.startswith("python3 ")
        or cmd.startswith("perl ")
        or cmd.startswith("ruby ")
    ):
        return "EXECUTION"

    # --------------------------------------------------------
    # FILE MANIPULATION
    # --------------------------------------------------------

    if (
        cmd.startswith("rm ")
        or cmd.startswith("mv ")
        or cmd.startswith("cp ")
        or cmd.startswith("touch ")
        or cmd.startswith("mkdir ")
        or cmd.startswith("rmdir ")
    ):
        return "FILE MANIP"

    # --------------------------------------------------------
    # ARCHIVE / COMPRESSION
    # --------------------------------------------------------

    if (
        cmd.startswith("tar ")
        or cmd.startswith("zip ")
        or cmd.startswith("unzip ")
        or cmd.startswith("gzip ")
        or cmd.startswith("gunzip ")
        or cmd.startswith("7z ")
    ):
        return "ARCHIVE"

    # --------------------------------------------------------
    # UNKNOWN / OTHER
    # --------------------------------------------------------

    return "OTHER"

# ============================================================
# ATTACKER CREATION
# ============================================================

def create_attacker(ip):

    if ip in attackers:
        return attackers[ip]

    location = get_location(ip)

    attacker = {

        "ip": ip,

        "network": network_type(ip),

        "country":
            location["country"],

        "region":
            location["region"],

        "city":
            location["city"],

        "isp":
            location["isp"],

        "latitude":
            location["latitude"],

        "longitude":
            location["longitude"],

        "connections": 0,

        "successful_logins": 0,

        "failed_logins": 0,

        "commands": 0,

        "failed_commands": 0,

        "categories": Counter(),

        "commands_seen": Counter(),

        "mitre": Counter(),

        "active": False,

        "first_seen":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "last_seen":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "last_alert": ""
    }

    attackers[ip] = attacker

    return attacker


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(attacker):

    categories = attacker.get("categories", {})

    score = 0

    # ========================================================
    # CATEGORY WEIGHTS
    # ========================================================

    weights = {

        # Low-risk reconnaissance
        "RECON": 1,
        "FILE ENUM": 1,
        "NETWORK ENUM": 2,

        # Credential discovery
        "CREDENTIAL ENUM": 6,

        # Potential payload retrieval
        "DOWNLOAD": 5,

        # Privilege / access manipulation
        "PRIV ESC": 8,
        "PERMISSION": 4,

        # Shell / execution
        "SHELL": 3,
        "EXECUTION": 6,

        # Remote access
        "REMOTE ACCESS": 5,

        # Persistence
        "PERSISTENCE": 8,

        # File manipulation
        "FILE MANIP": 4,

        # Session activity
        "SESSION": 1,

        # Unknown / miscellaneous
        "OTHER": 0
    }

    # ========================================================
    # CATEGORY SCORE
    # ========================================================

    for category, weight in weights.items():

        count = categories.get(
            category,
            0
        )

        score += count * weight

    # ========================================================
    # AUTHENTICATION ACTIVITY
    # ========================================================

    # Successful honeypot login is significant because
    # the attacker obtained valid-looking credentials.
    score += (
        attacker.get(
            "successful_logins",
            0
        ) * 3
    )

    # Repeated failed authentication attempts
    score += (
        attacker.get(
            "failed_logins",
            0
        ) * 2
    )

    # ========================================================
    # FAILED COMMANDS
    # ========================================================

    score += (
        attacker.get(
            "failed_commands",
            0
        ) * 1
    )

    # ========================================================
    # BEHAVIOUR COMBINATIONS
    # ========================================================

    # Credential discovery + privilege escalation
    if (
        categories.get(
            "CREDENTIAL ENUM",
            0
        ) > 0
        and
        categories.get(
            "PRIV ESC",
            0
        ) > 0
    ):
        score += 5

    # Download + permission modification
    # Often indicates retrieval followed by preparation
    # of a downloaded file.
    if (
        categories.get(
            "DOWNLOAD",
            0
        ) > 0
        and
        categories.get(
            "PERMISSION",
            0
        ) > 0
    ):
        score += 5

    # Download + shell activity
    if (
        categories.get(
            "DOWNLOAD",
            0
        ) > 0
        and
        categories.get(
            "SHELL",
            0
        ) > 0
    ):
        score += 4

    # Network enumeration + download
    if (
        categories.get(
            "NETWORK ENUM",
            0
        ) > 0
        and
        categories.get(
            "DOWNLOAD",
            0
        ) > 0
    ):
        score += 3

    # Privilege escalation + permission modification
    if (
        categories.get(
            "PRIV ESC",
            0
        ) > 0
        and
        categories.get(
            "PERMISSION",
            0
        ) > 0
    ):
        score += 5

    # ========================================================
    # REPEATED ACTIVITY
    # ========================================================

    total_commands = attacker.get(
        "commands",
        0
    )

    # Sustained activity is more suspicious than a
    # single reconnaissance command.
    if total_commands >= 10:
        score += 3

    if total_commands >= 25:
        score += 5

    if total_commands >= 50:
        score += 8

    # ========================================================
    # MULTIPLE ATTACK CATEGORIES
    # ========================================================

    active_categories = sum(
        1
        for category, count in categories.items()
        if count > 0
        and category != "OTHER"
    )

    if active_categories >= 3:
        score += 2

    if active_categories >= 5:
        score += 4

    if active_categories >= 7:
        score += 6

    # ========================================================
    # SEVERITY
    # ========================================================

    if score >= 40:
        return "CRITICAL"

    if score >= 20:
        return "HIGH"

    if score >= 10:
        return "MEDIUM"

    return "LOW"

# ============================================================
# ALERT ENGINE
# ============================================================

def alert(attacker, reason):

    severity = calculate_severity(attacker)
    color = severity_color(severity)

    now = datetime.now().strftime("%H:%M:%S")

    categories = attacker.get(
        "categories",
        {}
    )

    # --------------------------------------------------------
    # BUILD ANALYST REASONS
    # --------------------------------------------------------

    reasons = []

    if categories.get("CREDENTIAL ENUM", 0) > 0:
        reasons.append(
            "Credential enumeration detected"
        )

    if categories.get("DOWNLOAD", 0) > 0:
        reasons.append(
            "Payload/download activity detected"
        )

    if categories.get("PERMISSION", 0) > 0:
        reasons.append(
            "Permission modification detected"
        )

    if categories.get("PRIV ESC", 0) > 0:
        reasons.append(
            "Privilege escalation activity detected"
        )

    if categories.get("NETWORK ENUM", 0) > 0:
        reasons.append(
            "Network reconnaissance detected"
        )

    if categories.get("FILE ENUM", 0) > 0:
        reasons.append(
            "File enumeration detected"
        )

    if categories.get("RECON", 0) > 0:
        reasons.append(
            "System reconnaissance detected"
        )

    if categories.get("SHELL", 0) > 0:
        reasons.append(
            "Shell activity detected"
        )

    if attacker.get("failed_logins", 0) > 0:
        reasons.append(
            f"{attacker['failed_logins']} failed login attempt(s)"
        )

    if attacker.get("successful_logins", 0) > 0:
        reasons.append(
            f"{attacker['successful_logins']} successful honeypot login(s)"
        )

    if attacker.get("failed_commands", 0) > 0:
        reasons.append(
            f"{attacker['failed_commands']} failed command(s)"
        )

    # If nothing specific was detected, use the triggering reason.
    if not reasons:
        reasons.append(reason)

    # --------------------------------------------------------
    # ATTACKER INFORMATION
    # --------------------------------------------------------

    ip = attacker.get(
        "ip",
        "UNKNOWN"
    )

    mac = attacker.get(
        "mac",
        "-"
    )

    country = attacker.get(
        "country",
        "UNKNOWN"
    )

    city = attacker.get(
        "city",
        "UNKNOWN"
    )

    isp = attacker.get(
        "isp",
        "UNKNOWN"
    )

    connections = attacker.get(
        "connections",
        0
    )

    logins = attacker.get(
        "successful_logins",
        0
    )

    failed_logins = attacker.get(
        "failed_logins",
        0
    )

    command_count = attacker.get(
        "commands",
        0
    )

    failed_commands = attacker.get(
        "failed_commands",
        0
    )

    # --------------------------------------------------------
    # ALERT HEADER
    # --------------------------------------------------------

    print()

    print(
        f"{color}"
        f"╔{'═' * (WIDTH - 2)}╗"
        f"{RESET}"
    )

    title = f"🚨 {severity} SECURITY ALERT"

    print(
        f"{color}"
        f"║ {title:<{WIDTH - 3}}║"
        f"{RESET}"
    )

    print(
        f"{color}"
        f"╠{'═' * (WIDTH - 2)}╣"
        f"{RESET}"
    )

    # --------------------------------------------------------
    # INCIDENT INFORMATION
    # --------------------------------------------------------

    lines = [

        f"Time        : {now}",

        f"Attacker IP : {ip}",

        f"MAC Address : {mac}",

        f"Network     : {country}",

        f"Location    : {city}",

        f"ISP         : {isp}",

        f"Connections : {connections}",

        f"Logins      : {logins}",

        f"Failed logins: {failed_logins}",

        f"Commands    : {command_count}",

        f"Failed cmds : {failed_commands}"
    ]

    for line in lines:

        print(
            f"{color}"
            f"║ {line:<{WIDTH - 3}}║"
            f"{RESET}"
        )

    # --------------------------------------------------------
    # DETECTED BEHAVIOUR
    # --------------------------------------------------------

    print(
        f"{color}"
        f"╠{'═' * (WIDTH - 2)}╣"
        f"{RESET}"
    )

    print(
        f"{color}"
        f"║ {'DETECTED BEHAVIOUR':<{WIDTH - 3}}║"
        f"{RESET}"
    )

    for category, count in categories.most_common():

        if count <= 0:
            continue

        text = f"• {category}: {count}"

        print(
            f"{color}"
            f"║ {text:<{WIDTH - 3}}║"
            f"{RESET}"
        )

    # --------------------------------------------------------
    # ANALYST ASSESSMENT
    # --------------------------------------------------------

    print(
        f"{color}"
        f"╠{'═' * (WIDTH - 2)}╣"
        f"{RESET}"
    )

    print(
        f"{color}"
        f"║ {'ANALYST ASSESSMENT':<{WIDTH - 3}}║"
        f"{RESET}"
    )

    for item in reasons[:8]:

        text = f"• {item}"

        print(
            f"{color}"
            f"║ {text:<{WIDTH - 3}}║"
            f"{RESET}"
        )

    # --------------------------------------------------------
    # ORIGINAL TRIGGER
    # --------------------------------------------------------

    print(
        f"{color}"
        f"╠{'═' * (WIDTH - 2)}╣"
        f"{RESET}"
    )

    trigger = f"Trigger: {reason}"

    print(
        f"{color}"
        f"║ {trigger[:WIDTH - 3]:<{WIDTH - 3}}║"
        f"{RESET}"
    )

    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------

    print(
        f"{color}"
        f"╚{'═' * (WIDTH - 2)}╝"
        f"{RESET}"
    )

    print()

# ============================================================
# TIMELINE
# ============================================================

def add_timeline(
    event_type,
    ip,
    command="",
    category="",
    username=""
):

    entry = {

        "time":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "event":
            event_type,

        "ip":
            ip,

        "username":
            username,

        "category":
            category,

        "command":
            command
    }

    timeline.append(entry)

    if len(timeline) > MAX_TIMELINE:
        del timeline[
            :-MAX_TIMELINE
        ]


# ============================================================
# SAVE HISTORY
# ============================================================

def serialize_attacker(attacker):

    return {

        "ip":
            attacker["ip"],

        "network":
            attacker["network"],

        "country":
            attacker["country"],

        "region":
            attacker["region"],

        "city":
            attacker["city"],

        "isp":
            attacker["isp"],

        "latitude":
            attacker["latitude"],

        "longitude":
            attacker["longitude"],

        "connections":
            attacker["connections"],

        "successful_logins":
            attacker["successful_logins"],

        "failed_logins":
            attacker["failed_logins"],

        "commands":
            attacker["commands"],

        "failed_commands":
            attacker["failed_commands"],

        "categories":
            dict(attacker["categories"]),

        "commands_seen":
            dict(attacker["commands_seen"]),

        "mitre":
            dict(attacker["mitre"]),

        "severity":
            calculate_severity(attacker),

        "active":
            attacker["active"],

        "first_seen":
            attacker["first_seen"],

        "last_seen":
            attacker["last_seen"]
    }


def save_history():

    try:

        data = {

            "saved_at":
                datetime.now().isoformat(),

            "statistics": {

                "connections":
                    connections,

                "successful_logins":
                    successful_logins,

                "failed_logins":
                    failed_logins,

                "commands":
                    commands,

                "failed_commands":
                    failed_commands
            },

            "attack_categories":
                dict(attack_categories),

            "top_commands":
                dict(top_commands),

            "mitre_techniques":
                dict(mitre_techniques),

            "attackers": {

                ip:
                serialize_attacker(attacker)

                for ip, attacker
                in attackers.items()
            },

            "timeline":
                timeline
        }

        with open(
            HISTORY,
            "w"
        ) as f:

            json.dump(
                data,
                f,
                indent=2
            )

    except Exception:
        pass


# ============================================================
# DASHBOARD
# ============================================================

def draw_dashboard():

    clear_screen()

    print(
        CYAN
        + "╔"
        + border()
        + "╗"
        + RESET
    )

    print(
        CYAN
        + box(
            "COWRIE SOC MONITOR v3"
        )
        + RESET
    )

    print(
        CYAN
        + "╚"
        + border()
        + "╝"
        + RESET
    )

    print()

    print(
        f"{WHITE}"
        f"CONNECTIONS: {connections:<6}"
        f"LOGINS: {successful_logins:<6}"
        f"COMMANDS: {commands}"
        f"{RESET}"
    )

    print()

    # --------------------------------------------------------
    # ACTIVE THREATS
    # --------------------------------------------------------

    print(
        MAGENTA
        + "ACTIVE THREATS"
        + RESET
    )

    active = [

        attacker

        for attacker
        in attackers.values()

        if attacker["active"]
    ]

    if active:

        for attacker in active:

            severity = calculate_severity(
                attacker
            )

            color = severity_color(
                severity
            )

            print(
                f"{attacker['ip']:<18}"
                f"{color}{severity:<10}"
                f"{RESET}"
                f"{attacker['connections']:<6}"
                f"{attacker['commands']:<7}"
            )

    else:

        print(
            GRAY
            + "No active attackers"
            + RESET
        )

    print()

    # --------------------------------------------------------
    # ATTACKERS
    # --------------------------------------------------------

    print(
        CYAN
        + "ATTACKERS"
        + RESET
    )

    for attacker in list(
        attackers.values()
    )[-6:]:

        severity = calculate_severity(
            attacker
        )

        status = (
            "ACTIVE"
            if attacker["active"]
            else "CLOSED"
        )

        color = severity_color(
            severity
        )

        print(
            f"{attacker['ip']:<18}"
            f"{color}{severity:<10}"
            f"{RESET}"
            f"{attacker['connections']:<5}"
            f"{attacker['successful_logins']:<5}"
            f"{attacker['commands']:<6}"
            f"{status}"
        )

    print()

    # --------------------------------------------------------
    # ATTACK TYPES
    # --------------------------------------------------------

    print(
        BLUE
        + "ATTACK TYPES"
        + RESET
    )

    top_categories = (
        attack_categories
        .most_common(7)
    )

    if top_categories:

        maximum = max(
            count
            for _, count
            in top_categories
        )

        for category, count in top_categories:

            length = max(
                1,
                int(
                    count
                    / maximum
                    * 30
                )
            )

            bar = "█" * length

            print(
                f"{category:<18}"
                f"{bar:<30}"
                f"{count}"
            )

    else:

        print(
            "No attack activity"
        )

    print()

    # --------------------------------------------------------
    # TOP COMMANDS
    # --------------------------------------------------------

    print(
        BLUE
        + "TOP COMMANDS"
        + RESET
    )

    for command, count in (
        top_commands
        .most_common(10)
    ):

        display = command

        if len(display) > 45:
            display = (
                display[:42]
                + "..."
            )

        print(
            f"{display:<48}"
            f"{count}"
        )

    print()

    # --------------------------------------------------------
    # MITRE
    # --------------------------------------------------------

    print(
        YELLOW
        + "MITRE ATT&CK"
        + RESET
    )

    for technique, count in (
        mitre_techniques
        .most_common(6)
    ):

        print(
            f"{technique:<12}"
            f"{count}"
        )

    print()

    print(
        f"Failed logins   : "
        f"{failed_logins}"
    )

    print(
        f"Failed commands : "
        f"{failed_commands}"
    )

    print(
        f"Tracked attackers: "
        f"{len(attackers)}"
    )

    print()

    print(
        GRAY
        + "Press Ctrl+C to stop and generate report."
        + RESET
    )


# ============================================================
# DETAILED ATTACKER ANALYSIS
# ============================================================

def attacker_analysis(attacker):

    lines = []

    severity = calculate_severity(
        attacker
    )

    lines.append(
        f"IP             : "
        f"{attacker['ip']}"
    )

    lines.append(
        f"Network        : "
        f"{attacker['network']}"
    )

    lines.append(
        f"Country        : "
        f"{attacker['country']}"
    )

    lines.append(
        f"Region         : "
        f"{attacker['region']}"
    )

    lines.append(
        f"City           : "
        f"{attacker['city']}"
    )

    lines.append(
        f"ISP            : "
        f"{attacker['isp']}"
    )

    lines.append(
        f"Coordinates    : "
        f"{attacker['latitude']}, "
        f"{attacker['longitude']}"
    )

    lines.append(
        f"Severity       : "
        f"{severity}"
    )

    lines.append(
        f"Status         : "
        f"{'ACTIVE' if attacker['active'] else 'CLOSED'}"
    )

    lines.append(
        f"Connections    : "
        f"{attacker['connections']}"
    )

    lines.append(
        f"Successful logins: "
        f"{attacker['successful_logins']}"
    )

    lines.append(
        f"Failed logins  : "
        f"{attacker['failed_logins']}"
    )

    lines.append(
        f"Commands       : "
        f"{attacker['commands']}"
    )

    lines.append(
        f"Failed commands: "
        f"{attacker['failed_commands']}"
    )

    lines.append(
        f"First seen     : "
        f"{attacker['first_seen']}"
    )

    lines.append(
        f"Last seen      : "
        f"{attacker['last_seen']}"
    )

    return lines


# ============================================================
# ANALYST RECOMMENDATIONS
# ============================================================

def recommendations():

    notes = []

    if failed_logins:

        notes.append(
            "Review failed authentication "
            "attempts for credential guessing."
        )

    if successful_logins:

        notes.append(
            "Successful honeypot logins were "
            "observed. Review credentials used."
        )

    if attack_categories.get(
        "NETWORK ENUM"
    ):

        notes.append(
            "Network discovery activity was "
            "observed. Review ip/ss/netstat/"
            "nmap/ping commands."
        )

    if attack_categories.get(
        "FILE ENUM"
    ):

        notes.append(
            "File and directory discovery "
            "activity was observed."
        )

    if attack_categories.get(
        "DOWNLOAD"
    ):

        notes.append(
            "Download activity was observed. "
            "Review wget/curl commands."
        )

    if attack_categories.get(
        "PRIV ESC"
    ):

        notes.append(
            "Privilege escalation behavior "
            "was observed."
        )

    if attack_categories.get(
        "PERMISSION"
    ):

        notes.append(
            "Permission modification commands "
            "were observed."
        )

    if not notes:

        notes.append(
            "No significant suspicious behavior "
            "was detected."
        )

    return notes



def detailed_incident_analysis():

    analysis = {
        "overall_assessment": "",
        "attack_chain": [],
        "critical_findings": [],
        "attackers": [],
        "recommended_response": []
    }

    # --------------------------------------------------------
    # OVERALL ASSESSMENT
    # --------------------------------------------------------

    highest = "LOW"

    severity_order = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3
    }

    for attacker in attackers.values():

        severity = calculate_severity(attacker)

        if severity_order[severity] > severity_order[highest]:
            highest = severity

    if highest == "CRITICAL":
        analysis["overall_assessment"] = (
            "Critical malicious activity was observed. "
            "The activity contains one or more high-risk "
            "behaviours such as payload retrieval, privilege "
            "escalation, permission modification, credential "
            "discovery, or sustained attacker activity."
        )

    elif highest == "HIGH":
        analysis["overall_assessment"] = (
            "High-risk suspicious activity was observed. "
            "The attacker demonstrated behaviour beyond "
            "basic reconnaissance and should be investigated."
        )

    elif highest == "MEDIUM":
        analysis["overall_assessment"] = (
            "Moderately suspicious activity was observed. "
            "The attacker performed multiple discovery or "
            "interaction activities that warrant review."
        )

    else:
        analysis["overall_assessment"] = (
            "Low-level activity was observed with no strong "
            "indication of advanced compromise behaviour."
        )

    # --------------------------------------------------------
    # ATTACK CHAIN
    # --------------------------------------------------------

    chain = []

    category_order = [
        ("RECON", "Initial reconnaissance"),
        ("FILE ENUM", "File and directory enumeration"),
        ("NETWORK ENUM", "Network discovery"),
        ("CREDENTIAL ENUM", "Credential discovery"),
        ("DOWNLOAD", "Payload/download activity"),
        ("SHELL", "Shell execution"),
        ("PRIV ESC", "Privilege escalation"),
        ("PERMISSION", "Permission modification")
    ]

    for category, description in category_order:

        if attack_categories.get(category, 0) > 0:

            chain.append({
                "stage": category,
                "description": description,
                "observations": attack_categories[category]
            })

    analysis["attack_chain"] = chain

    # --------------------------------------------------------
    # CRITICAL FINDINGS
    # --------------------------------------------------------

    if successful_logins:
        analysis["critical_findings"].append(
            f"{successful_logins} successful honeypot login(s) "
            "were recorded."
        )

    if failed_logins:
        analysis["critical_findings"].append(
            f"{failed_logins} failed login attempt(s) "
            "were recorded."
        )

    if attack_categories.get("DOWNLOAD", 0):
        analysis["critical_findings"].append(
            "Download/retrieval behaviour was observed. "
            "Review URLs and retrieved payloads."
        )

    if attack_categories.get("PRIV ESC", 0):
        analysis["critical_findings"].append(
            "Privilege escalation activity was observed."
        )

    if attack_categories.get("PERMISSION", 0):
        analysis["critical_findings"].append(
            "Permission modification activity was observed."
        )

    if attack_categories.get("CREDENTIAL ENUM", 0):
        analysis["critical_findings"].append(
            "Credential or account enumeration was observed."
        )

    if commands >= 25:
        analysis["critical_findings"].append(
            f"Sustained attacker activity was observed: "
            f"{commands} commands recorded."
        )

    if not analysis["critical_findings"]:
        analysis["critical_findings"].append(
            "No high-confidence critical findings were identified."
        )

    # --------------------------------------------------------
    # PER-ATTACKER ANALYSIS
    # --------------------------------------------------------

    for attacker in attackers.values():

        severity = calculate_severity(attacker)

        categories = attacker.get(
            "categories",
            {}
        )

        commands_seen = attacker.get(
            "commands_seen",
            {}
        )

        behaviour = []

        for category, count in categories.items():

            if count > 0 and category != "OTHER":

                behaviour.append({
                    "category": category,
                    "count": count
                })

        suspicious_commands = []

        high_risk_categories = {
            "DOWNLOAD",
            "PRIV ESC",
            "PERMISSION",
            "CREDENTIAL ENUM",
            "SHELL"
        }

        for command, count in commands_seen.items():

            category = classify_command(command)

            if category in high_risk_categories:

                suspicious_commands.append({
                    "command": command,
                    "count": count,
                    "category": category
                })

        suspicious_commands.sort(
            key=lambda x: x["count"],
            reverse=True
        )

        attacker_assessment = []

        if categories.get("RECON", 0):
            attacker_assessment.append(
                "Performed host reconnaissance."
            )

        if categories.get("FILE ENUM", 0):
            attacker_assessment.append(
                "Enumerated files or directories."
            )

        if categories.get("NETWORK ENUM", 0):
            attacker_assessment.append(
                "Performed network discovery."
            )

        if categories.get("CREDENTIAL ENUM", 0):
            attacker_assessment.append(
                "Attempted credential/account discovery."
            )

        if categories.get("DOWNLOAD", 0):
            attacker_assessment.append(
                "Attempted to retrieve external content."
            )

        if categories.get("SHELL", 0):
            attacker_assessment.append(
                "Executed shell-related activity."
            )

        if categories.get("PRIV ESC", 0):
            attacker_assessment.append(
                "Attempted privilege escalation."
            )

        if categories.get("PERMISSION", 0):
            attacker_assessment.append(
                "Modified file permissions or ownership."
            )

        analysis["attackers"].append({

            "ip": attacker.get("ip", ""),

            "severity": severity,

            "risk_score": calculate_risk_score(
                attacker
            ) if "calculate_risk_score" in globals()
            else None,

            "network": attacker.get(
                "network",
                "UNKNOWN"
            ),

            "location": {
                "country": attacker.get(
                    "country",
                    "UNKNOWN"
                ),
                "region": attacker.get(
                    "region",
                    "UNKNOWN"
                ),
                "city": attacker.get(
                    "city",
                    "UNKNOWN"
                ),
                "isp": attacker.get(
                    "isp",
                    "UNKNOWN"
                )
            },

            "connections": attacker.get(
                "connections",
                0
            ),

            "successful_logins": attacker.get(
                "successful_logins",
                0
            ),

            "failed_logins": attacker.get(
                "failed_logins",
                0
            ),

            "commands": attacker.get(
                "commands",
                0
            ),

            "failed_commands": attacker.get(
                "failed_commands",
                0
            ),

            "behaviour": behaviour,

            "suspicious_commands":
                suspicious_commands,

            "assessment":
                attacker_assessment
        })

    # --------------------------------------------------------
    # RESPONSE PRIORITY
    # --------------------------------------------------------

    if highest == "CRITICAL":
        analysis["recommended_response"].extend([
            "Immediately investigate the attacker activity.",
            "Review all download URLs and retrieved payloads.",
            "Review privilege escalation and permission changes.",
            "Preserve Cowrie logs and generated incident reports.",
            "Correlate attacker IPs with other security telemetry."
        ])

    elif highest == "HIGH":
        analysis["recommended_response"].extend([
            "Investigate the highest-severity attacker.",
            "Review suspicious commands and downloaded content.",
            "Check for privilege escalation or credential discovery.",
            "Preserve relevant logs for further investigation."
        ])

    else:
        analysis["recommended_response"].extend([
            "Continue monitoring the attacker activity.",
            "Review repeated reconnaissance and enumeration.",
            "Retain the generated incident report for correlation."
        ])

    return analysis


# ============================================================
# INCIDENT REPORT
# ============================================================

def generate_report():

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    txt_path = os.path.join(
        REPORT_DIR,
        f"cowrie_incident_{timestamp}.txt"
    )

    json_path = os.path.join(
        REPORT_DIR,
        f"cowrie_incident_{timestamp}.json"
    )

    highest = "LOW"

    order = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3
    }

    for attacker in attackers.values():

        severity = calculate_severity(
            attacker
        )

        if order[severity] > order[highest]:
            highest = severity

    # --------------------------------------------------------
    # DETAILED ANALYSIS
    # --------------------------------------------------------

    detailed_analysis = detailed_incident_analysis()

    # --------------------------------------------------------
    # JSON REPORT
    # --------------------------------------------------------

    json_data = {

        "report_generated":
            datetime.now().isoformat(),

        "summary": {

            "highest_severity":
                highest,

            "connections":
                connections,

            "successful_logins":
                successful_logins,

            "failed_logins":
                failed_logins,

            "commands":
                commands,

            "failed_commands":
                failed_commands,

            "tracked_attackers":
                len(attackers)
        },

        "attack_categories":
            dict(attack_categories),

        "top_commands":
            dict(
                top_commands
                .most_common(20)
            ),

        "mitre_attack":
            dict(mitre_techniques),

        "attackers": {

            ip:
            serialize_attacker(attacker)

            for ip, attacker
            in attackers.items()
        },

        "timeline":
            timeline,

        "recommendations":
            recommendations(),

        "detailed_analysis":
            detailed_analysis
    }

    try:

        with open(
            json_path,
            "w"
        ) as f:

            json.dump(
                json_data,
                f,
                indent=2
            )

    except Exception:
        pass

    # --------------------------------------------------------
    # TEXT REPORT
    # --------------------------------------------------------

    report = []

    report.append(
        "=" * 80
    )

    report.append(
        "COWRIE SOC INCIDENT REPORT"
    )

    report.append(
        "=" * 80
    )

    report.append(
        f"Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    report.append("")

    report.append(
        "EXECUTIVE SUMMARY"
    )

    report.append(
        "-" * 80
    )

    report.append(
        f"Highest severity : {highest}"
    )

    report.append(
        f"Connections      : {connections}"
    )

    report.append(
        f"Successful logins: {successful_logins}"
    )

    report.append(
        f"Failed logins    : {failed_logins}"
    )

    report.append(
        f"Commands         : {commands}"
    )

    report.append(
        f"Failed commands  : {failed_commands}"
    )

    report.append(
        f"Attackers tracked: {len(attackers)}"
    )

    report.append("")

    # --------------------------------------------------------
    # ATTACKER PROFILES
    # --------------------------------------------------------

    report.append(
        "ATTACKER PROFILES"
    )

    report.append(
        "-" * 80
    )

    if attackers:

        for attacker in attackers.values():

            report.extend(
                attacker_analysis(
                    attacker
                )
            )

            report.append("")

    else:

        report.append(
            "No attackers recorded."
        )

    # --------------------------------------------------------
    # ATTACK CATEGORIES
    # --------------------------------------------------------

    report.append(
        "ATTACK CATEGORIES"
    )

    report.append(
        "-" * 80
    )

    for category, count in (
        attack_categories
        .most_common()
    ):

        report.append(
            f"{category:<25} {count}"
        )

    report.append("")

    # --------------------------------------------------------
    # TOP COMMANDS
    # --------------------------------------------------------

    report.append(
        "TOP COMMANDS"
    )

    report.append(
        "-" * 80
    )

    for command, count in (
        top_commands
        .most_common(20)
    ):

        report.append(
            f"{command:<50} {count}"
        )

    report.append("")

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    report.append(
        "MITRE ATT&CK MAPPING"
    )

    report.append(
        "-" * 80
    )

    if mitre_techniques:

        for technique, count in (
            mitre_techniques
            .most_common()
        ):

            report.append(
                f"{technique:<15} "
                f"{count} observation(s)"
            )

    else:

        report.append(
            "No mapped techniques."
        )

    report.append("")

    # --------------------------------------------------------
    # ATTACK REPLAY
    # --------------------------------------------------------

    report.append(
        "ATTACK REPLAY / TIMELINE"
    )

    report.append(
        "-" * 80
    )

    if timeline:

        for event in timeline:

            line = (
                f"{event['time']} | "
                f"{event['event']:<20} | "
                f"{event['ip']:<18}"
            )

            if event["category"]:

                line += (
                    f" | "
                    f"{event['category']:<18}"
                )

            if event["command"]:

                line += (
                    f" | "
                    f"{event['command']}"
                )

            report.append(line)

    else:

        report.append(
            "No events recorded."
        )

    report.append("")

    # --------------------------------------------------------
    # DETAILED INCIDENT ANALYSIS
    # --------------------------------------------------------

    report.append(
        "DETAILED INCIDENT ANALYSIS"
    )

    report.append(
        "-" * 80
    )

    report.append(
        "OVERALL ASSESSMENT"
    )

    report.append(
        detailed_analysis["overall_assessment"]
    )

    report.append("")

    report.append(
        "ATTACK CHAIN"
    )

    report.append(
        "-" * 80
    )

    if detailed_analysis["attack_chain"]:

        for stage in detailed_analysis["attack_chain"]:

            report.append(
                f"{stage['stage']:<20} "
                f"{stage['observations']} observation(s) "
                f"- {stage['description']}"
            )

    else:

        report.append(
            "No attack chain identified."
        )

    report.append("")

    report.append(
        "CRITICAL FINDINGS"
    )

    report.append(
        "-" * 80
    )

    for finding in detailed_analysis["critical_findings"]:

        report.append(
            "- " + finding
        )

    report.append("")

    report.append(
        "ATTACKER RISK ANALYSIS"
    )

    report.append(
        "-" * 80
    )

    for attacker in detailed_analysis["attackers"]:

        report.append(
            f"IP: {attacker['ip']}"
        )

        report.append(
            f"Severity: {attacker['severity']}"
        )

        report.append(
            f"Connections: {attacker['connections']}"
        )

        report.append(
            f"Successful logins: "
            f"{attacker['successful_logins']}"
        )

        report.append(
            f"Failed logins: "
            f"{attacker['failed_logins']}"
        )

        report.append(
            f"Commands: {attacker['commands']}"
        )

        report.append(
            f"Failed commands: "
            f"{attacker['failed_commands']}"
        )

        if attacker["behaviour"]:

            report.append(
                "Observed behaviour:"
            )

            for behaviour in attacker["behaviour"]:

                report.append(
                    f"  - "
                    f"{behaviour['category']}: "
                    f"{behaviour['count']}"
                )

        if attacker["suspicious_commands"]:

            report.append(
                "High-risk commands:"
            )

            for item in attacker["suspicious_commands"]:

                report.append(
                    f"  - "
                    f"[{item['category']}] "
                    f"{item['command']} "
                    f"(seen {item['count']} time(s))"
                )

        if attacker["assessment"]:

            report.append(
                "Assessment:"
            )

            for item in attacker["assessment"]:

                report.append(
                    f"  - {item}"
                )

        report.append("")

    report.append(
        "RECOMMENDED RESPONSE"
    )

    report.append(
        "-" * 80
    )

    for action in detailed_analysis["recommended_response"]:

        report.append(
            "- " + action
        )

    report.append("")

    # --------------------------------------------------------
    # ANALYST NOTES
    # --------------------------------------------------------

    report.append(
        "ANALYST NOTES / RECOMMENDATIONS"
    )

    report.append(
        "-" * 80
    )

    for note in recommendations():

        report.append(
            "- " + note
        )

    report.append("")

    report.append(
        "=" * 80
    )

    report.append(
        "END OF REPORT"
    )

    report.append(
        "=" * 80
    )

    try:

        with open(
            txt_path,
            "w"
        ) as f:

            f.write(
                "\n".join(report)
            )

    except Exception:
        pass

    print()

    print(
        GREEN
        + "[+] Incident report generated:"
        + RESET
    )

    print(
        "    Text : "
        + txt_path
    )

    print(
        "    JSON : "
        + json_path
    )


# ============================================================
# EVENT PROCESSING
# ============================================================

def process_event(event):

    global connections
    global successful_logins
    global failed_logins
    global commands
    global failed_commands

    event_id = event.get(
        "eventid",
        ""
    )

    ip = event.get(
        "src_ip",
        ""
    )

    session = event.get(
        "session",
        ""
    )

    username = event.get(
        "username",
        ""
    )

    # --------------------------------------------------------
    # NEW CONNECTION
    # --------------------------------------------------------

    if event_id == "cowrie.session.connect":

        connections += 1

        if ip:

            attacker = create_attacker(
                ip
            )

            attacker["connections"] += 1

            attacker["active"] = True

            attacker["last_seen"] = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            if session:

                sessions[session] = ip

            add_timeline(
                "NEW CONNECTION",
                ip
            )

            print()

            print(
                CYAN
                + "=" * WIDTH
                + RESET
            )

            print(
                CYAN
                + f"[{datetime.now().strftime('%H:%M:%S')}] "
                + "NEW CONNECTION"
                + RESET
            )

            print(
                f"Source IP   : {ip}"
            )

            print(
                f"Network     : "
                f"{attacker['network']}"
            )

            print(
                f"Country     : "
                f"{attacker['country']}"
            )

            print(
                f"Region      : "
                f"{attacker['region']}"
            )

            print(
                f"City        : "
                f"{attacker['city']}"
            )

            print(
                f"ISP         : "
                f"{attacker['isp']}"
            )

            print(
                f"Coordinates : "
                f"{attacker['latitude']}, "
                f"{attacker['longitude']}"
            )

            print(
                CYAN
                + "=" * WIDTH
                + RESET
            )

    # --------------------------------------------------------
    # LOGIN SUCCESS
    # --------------------------------------------------------

    elif event_id == "cowrie.login.success":

        successful_logins += 1

        if ip:

            attacker = create_attacker(
                ip
            )

            attacker[
                "successful_logins"
            ] += 1

            attacker["active"] = True

            attacker["last_seen"] = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            add_timeline(
                "LOGIN SUCCESS",
                ip,
                username=username
            )

            print()

            print(
                GREEN
                + "[+] LOGIN SUCCESS"
                + RESET
            )

            print(
                f"    IP       : {ip}"
            )

            print(
                f"    Username : "
                f"{username or 'unknown'}"
            )

            if calculate_severity(
                attacker
            ) in (
                "HIGH",
                "CRITICAL"
            ):

                alert(
                    attacker,
                    "Successful honeypot login"
                )

    # --------------------------------------------------------
    # LOGIN FAILED
    # --------------------------------------------------------

    elif event_id == "cowrie.login.failed":

        failed_logins += 1

        if ip:

            attacker = create_attacker(
                ip
            )

            attacker[
                "failed_logins"
            ] += 1

            attacker["last_seen"] = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            add_timeline(
                "LOGIN FAILED",
                ip,
                username=username
            )

            print()

            print(
                RED
                + "[FAILED] LOGIN"
                + RESET
                + f" | {ip}"
            )

            if attacker[
                "failed_logins"
            ] >= 3:

                alert(
                    attacker,
                    "Repeated failed authentication attempts"
                )

    # --------------------------------------------------------
    # COMMAND INPUT
    # --------------------------------------------------------

    elif event_id == "cowrie.command.input":

        command = event.get(
            "input",
            ""
        ).strip()

        if command:

            commands += 1

            category = classify_command(
                command
            )

            attack_categories[
                category
            ] += 1

            top_commands[
                command
            ] += 1

            mappings = map_mitre(
                command
            )

            for technique, name in mappings:

                mitre_techniques[
                    technique
                ] += 1

            if ip:

                attacker = create_attacker(
                    ip
                )

                attacker[
                    "commands"
                ] += 1

                attacker[
                    "categories"
                ][category] += 1

                attacker[
                    "commands_seen"
                ][command] += 1

                attacker["active"] = True

                attacker["last_seen"] = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                for technique, name in mappings:

                    attacker[
                        "mitre"
                    ][
                        technique
                    ] += 1

                add_timeline(
                    "COMMAND",
                    ip,
                    command,
                    category,
                    username
                )

                print()

                print(
                    f"{YELLOW}[COMMAND]{RESET} "
                    f"{datetime.now().strftime('%H:%M:%S')} | "
                    f"{ip:<18} | "
                    f"{category:<18} | "
                    f"{command}"
                )

                # High-risk command alerts
                if category in (
                    "DOWNLOAD",
                    "PRIV ESC",
                    "PERMISSION",
                    "CREDENTIAL ENUM"
                ):

                    alert(
                        attacker,
                        f"{category}: {command}"
                    )

    # --------------------------------------------------------
    # FAILED COMMAND
    # --------------------------------------------------------

    elif event_id == "cowrie.command.failed":

        failed_commands += 1

        command = event.get(
            "input",
            ""
        ).strip()

        if ip:

            attacker = create_attacker(
                ip
            )

            attacker[
                "failed_commands"
            ] += 1

            attacker["last_seen"] = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            add_timeline(
                "COMMAND FAILED",
                ip,
                command
            )

            print()

            print(
                RED
                + "[FAILED]"
                + RESET
                + f" {ip:<18} | "
                f"{command}"
            )

    # --------------------------------------------------------
    # SESSION CLOSED
    # --------------------------------------------------------

    elif event_id == "cowrie.session.closed":

        attacker_ip = ""

        if session in sessions:

            attacker_ip = sessions[
                session
            ]

            del sessions[
                session
            ]

        if attacker_ip:

            if attacker_ip in attackers:

                attacker = attackers[
                    attacker_ip
                ]

                # Only mark closed when this attacker
                # has no remaining active session.
                if attacker_ip not in sessions.values():

                    attacker[
                        "active"
                    ] = False

                attacker[
                    "last_seen"
                ] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            add_timeline(
                "SESSION CLOSED",
                attacker_ip
            )

            print()

            print(
                GRAY
                + "[*] SESSION CLOSED"
                + RESET
                + f" | {attacker_ip}"
            )

    save_history()


# ============================================================
# MAIN
# ============================================================

def main():

    print()

    print(
        CYAN
        + "Starting Cowrie SOC Monitor v3..."
        + RESET
    )

    time.sleep(1)

    if not os.path.exists(LOG):

        print()

        print(
            RED
            + "ERROR: Cowrie log not found:"
            + RESET
        )

        print(LOG)

        return

    print()

    print(
        f"Watching: {LOG}"
    )

    print()

    print(
        GREEN
        + "[+] Monitor is running."
        + RESET
    )

    print(
        YELLOW
        + "[+] Waiting for Cowrie activity..."
        + RESET
    )

    print()

    with open(
        LOG,
        "r"
    ) as f:

        # Start from the current end of the log.
        # Old events are not replayed.
        f.seek(
            0,
            os.SEEK_END
        )

        while True:

            line = f.readline()

            if not line:

                time.sleep(
                    REFRESH_DELAY
                )

                continue

            try:

                event = json.loads(
                    line
                )

                process_event(
                    event
                )

            except json.JSONDecodeError:

                continue

            except Exception as error:

                print(
                    RED
                    + "[!] Event processing error: "
                    + RESET
                    + str(error)
                )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()

        print(
            YELLOW
            + "\nStopping Cowrie SOC Monitor..."
            + RESET
        )

        save_history()

        generate_report()

        print()

        print(
            GREEN
            + "[+] Monitor stopped cleanly."
            + RESET
        )

        print()
