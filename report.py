#!/usr/bin/env python3

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime


# ============================================================
# COWRIE SOC ATTACK REPORT GENERATOR
# ============================================================

HISTORY_FILE = "soc_history.json"
COWRIE_LOG = "var/log/cowrie/cowrie.json"

REPORT_DIR = "reports"


# ============================================================
# TERMINAL COLORS
# ============================================================

RESET = "\033[0m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"


# ============================================================
# DISPLAY HELPERS
# ============================================================

WIDTH = 78


def clear_screen():
    print("\033[2J\033[H", end="")


def line(char="="):
    return char * WIDTH


def title(text):
    print()
    print(line("="))
    print(
        f"{text.center(WIDTH)}"
    )
    print(line("="))


def section(text):
    print()
    print(
        f"{CYAN}{line("-")}{RESET}"
    )
    print(
        f"{CYAN}{text.center(WIDTH)}{RESET}"
    )
    print(
        f"{CYAN}{line("-")}{RESET}"
    )


def safe(value, default="UNKNOWN"):
    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    return value


# ============================================================
# FILE LOADING
# ============================================================

def load_json_file(path):

    if not os.path.exists(path):
        return {}

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            f"{RED}[!] Could not read {path}: "
            f"{error}{RESET}"
        )

        return {}


def load_cowrie_events():

    events = []

    if not os.path.exists(COWRIE_LOG):

        return events

    try:

        with open(
            COWRIE_LOG,
            "r",
            encoding="utf-8"
        ) as file:

            for line_data in file:

                line_data = line_data.strip()

                if not line_data:
                    continue

                try:

                    event = json.loads(
                        line_data
                    )

                    if isinstance(
                        event,
                        dict
                    ):

                        events.append(event)

                except json.JSONDecodeError:

                    continue

    except Exception as error:

        print(
            f"{YELLOW}[!] Could not read Cowrie log: "
            f"{error}{RESET}"
        )

    return events


# ============================================================
# IP HELPERS
# ============================================================

def is_private_ip(ip):

    if not ip:
        return True

    prefixes = (
        "10.",
        "127.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
    )

    return ip.startswith(prefixes)


def network_type(ip):

    if not ip:
        return "UNKNOWN"

    if is_private_ip(ip):
        return "PRIVATE / LOCAL"

    return "PUBLIC INTERNET"


# ============================================================
# COMMAND CLASSIFICATION
# ============================================================

def classify_command(command):

    if not command:
        return "OTHER"

    cmd = command.lower().strip()

    # --------------------------------------------------------
    # RECONNAISSANCE
    # --------------------------------------------------------

    recon = (
        "whoami",
        "id",
        "uname",
        "hostname",
        "pwd",
        "date",
        "uptime",
        "env",
        "printenv",
    )

    if (
        cmd in recon
        or cmd.startswith("uname ")
        or cmd.startswith("hostname ")
    ):

        return "RECON"


    # --------------------------------------------------------
    # FILE ENUMERATION
    # --------------------------------------------------------

    file_enum = (
        "ls",
        "ll",
        "dir",
        "find",
        "locate",
        "tree",
        "cat",
        "head",
        "tail",
    )

    if (
        cmd in file_enum
        or cmd.startswith("ls ")
        or cmd.startswith("find ")
        or cmd.startswith("cat ")
        or cmd.startswith("locate ")
    ):

        return "FILE ENUM"


    # --------------------------------------------------------
    # NETWORK ENUMERATION
    # --------------------------------------------------------

    network = (
        "ifconfig",
        "ip",
        "ip a",
        "ip addr",
        "ip route",
        "netstat",
        "ss",
        "route",
        "arp",
        "ping",
        "nslookup",
        "dig",
    )

    if (
        cmd in network
        or cmd.startswith("ip ")
        or cmd.startswith("ping ")
        or cmd.startswith("netstat ")
        or cmd.startswith("ss ")
    ):

        return "NETWORK ENUM"


    # --------------------------------------------------------
    # PRIVILEGE ESCALATION
    # --------------------------------------------------------

    if (
        cmd == "sudo"
        or cmd.startswith("sudo ")
        or cmd == "su"
        or cmd.startswith("su ")
    ):

        return "PRIV ESC"


    # --------------------------------------------------------
    # DOWNLOAD / RETRIEVAL
    # --------------------------------------------------------

    if (
        cmd.startswith("wget ")
        or cmd == "wget"
        or cmd.startswith("curl ")
        or cmd == "curl"
        or cmd.startswith("ftp ")
        or cmd == "ftp"
    ):

        return "DOWNLOAD"


    # --------------------------------------------------------
    # PERMISSIONS
    # --------------------------------------------------------

    if (
        cmd.startswith("chmod ")
        or cmd == "chmod"
        or cmd.startswith("chown ")
        or cmd == "chown"
        or cmd.startswith("chgrp ")
        or cmd == "chgrp"
    ):

        return "PERMISSION"


    # --------------------------------------------------------
    # FILE MANIPULATION
    # --------------------------------------------------------

    manipulation = (
        "cp",
        "mv",
        "rm",
        "mkdir",
        "touch",
        "rmdir",
    )

    if (
        cmd in manipulation
        or cmd.startswith("cp ")
        or cmd.startswith("mv ")
        or cmd.startswith("rm ")
        or cmd.startswith("mkdir ")
        or cmd.startswith("touch ")
    ):

        return "FILE MANIP"


    # --------------------------------------------------------
    # SHELL
    # --------------------------------------------------------

    shell_commands = (
        "bash",
        "sh",
        "zsh",
        "dash",
        "python",
        "python3",
        "perl",
        "ruby",
    )

    if (
        cmd in shell_commands
        or cmd.startswith("bash ")
        or cmd.startswith("sh ")
        or cmd.startswith("python ")
        or cmd.startswith("python3 ")
    ):

        return "SHELL"


    # --------------------------------------------------------
    # CREDENTIAL ENUMERATION
    # --------------------------------------------------------

    credential_commands = (
        "passwd",
        "history",
        "last",
        "w",
        "who",
        "users",
    )

    if cmd in credential_commands:

        return "CREDENTIAL ENUM"


    # --------------------------------------------------------
    # EXIT / SESSION
    # --------------------------------------------------------

    if cmd in (
        "exit",
        "logout",
        "quit",
    ):

        return "SESSION"


    return "OTHER"


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(attacker):

    score = 0

    categories = attacker.get(
        "categories",
        {}
    )

    score += categories.get(
        "RECON",
        0
    ) * 1

    score += categories.get(
        "FILE ENUM",
        0
    ) * 1

    score += categories.get(
        "NETWORK ENUM",
        0
    ) * 2

    score += categories.get(
        "DOWNLOAD",
        0
    ) * 3

    score += categories.get(
        "CREDENTIAL ENUM",
        0
    ) * 4

    score += categories.get(
        "PRIV ESC",
        0
    ) * 5

    score += categories.get(
        "PERMISSION",
        0
    ) * 4

    score += categories.get(
        "FILE MANIP",
        0
    ) * 4

    score += categories.get(
        "SHELL",
        0
    ) * 4

    score += attacker.get(
        "failed_commands",
        0
    ) * 1

    score += attacker.get(
        "failed_logins",
        0
    ) * 2

    if score >= 15:
        return "CRITICAL"

    if score >= 8:
        return "HIGH"

    if score >= 4:
        return "MEDIUM"

    return "LOW"


def severity_color(severity):

    if severity == "CRITICAL":
        return RED

    if severity == "HIGH":
        return YELLOW

    if severity == "MEDIUM":
        return MAGENTA

    return GREEN


# ============================================================
# BUILD ATTACKER DATABASE FROM COWRIE EVENTS
# ============================================================

def build_attackers(events):

    attackers = {}

    sessions = {}

    for event in events:

        event_id = event.get(
            "eventid",
            ""
        )

        ip = safe(
            event.get(
                "src_ip"
            ),
            ""
        )

        session = safe(
            event.get(
                "session"
            ),
            ""
        )

        if not ip:
            continue


        # ----------------------------------------------------
        # CREATE ATTACKER
        # ----------------------------------------------------

        if ip not in attackers:

            attackers[ip] = {

                "ip": ip,

                "network_type":
                    network_type(ip),

                "mac": "-",

                "country":
                    "LOCAL NETWORK"
                    if is_private_ip(ip)
                    else "UNKNOWN",

                "region":
                    "Private IP"
                    if is_private_ip(ip)
                    else "UNKNOWN",

                "city":
                    "Local"
                    if is_private_ip(ip)
                    else "UNKNOWN",

                "isp":
                    "Local Network"
                    if is_private_ip(ip)
                    else "UNKNOWN",

                "connections": 0,

                "successful_logins": 0,

                "failed_logins": 0,

                "commands": 0,

                "failed_commands": 0,

                "categories": Counter(),

                "commands_seen": Counter(),

                "usernames": Counter(),

                "passwords": Counter(),

                "sessions": set(),

                "timeline": [],

                "active": False,

                "first_seen": None,

                "last_seen": None,
            }


        attacker = attackers[ip]


        # ----------------------------------------------------
        # TIMESTAMP
        # ----------------------------------------------------

        timestamp = event.get(
            "timestamp",
            ""
        )

        if timestamp:

            try:

                clean_timestamp = (
                    timestamp
                    .replace(
                        "Z",
                        ""
                    )
                )

                dt = datetime.fromisoformat(
                    clean_timestamp
                )

                readable_time = (
                    dt.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

            except Exception:

                readable_time = timestamp

        else:

            readable_time = "UNKNOWN"


        if not attacker["first_seen"]:

            attacker[
                "first_seen"
            ] = readable_time

        attacker[
            "last_seen"
        ] = readable_time


        if session:

            attacker[
                "sessions"
            ].add(session)


        # ----------------------------------------------------
        # SESSION CONNECT
        # ----------------------------------------------------

        if event_id == "cowrie.session.connect":

            attacker[
                "connections"
            ] += 1

            attacker[
                "active"
            ] = True

            if session:

                sessions[
                    session
                ] = ip

            attacker[
                "timeline"
            ].append({

                "time": readable_time,

                "type": "CONNECTION",

                "details":
                    "New SSH connection",

            })


        # ----------------------------------------------------
        # LOGIN SUCCESS
        # ----------------------------------------------------

        elif event_id == "cowrie.login.success":

            attacker[
                "successful_logins"
            ] += 1

            username = safe(
                event.get(
                    "username"
                ),
                "-"
            )

            password = safe(
                event.get(
                    "password"
                ),
                "-"
            )

            attacker[
                "usernames"
            ][username] += 1

            attacker[
                "passwords"
            ][password] += 1

            attacker[
                "active"
            ] = True

            attacker[
                "timeline"
            ].append({

                "time": readable_time,

                "type":
                    "LOGIN SUCCESS",

                "details":
                    f"Username={username}",

            })


        # ----------------------------------------------------
        # LOGIN FAILED
        # ----------------------------------------------------

        elif event_id == "cowrie.login.failed":

            attacker[
                "failed_logins"
            ] += 1

            username = safe(
                event.get(
                    "username"
                ),
                "-"
            )

            password = safe(
                event.get(
                    "password"
                ),
                "-"
            )

            attacker[
                "usernames"
            ][username] += 1

            attacker[
                "passwords"
            ][password] += 1

            attacker[
                "timeline"
            ].append({

                "time": readable_time,

                "type":
                    "LOGIN FAILED",

                "details":
                    f"Username={username}",

            })


        # ----------------------------------------------------
        # COMMAND
        # ----------------------------------------------------

        elif event_id == "cowrie.command.input":

            command = safe(
                event.get(
                    "input"
                ),
                ""
            )

            if command:

                category = (
                    classify_command(
                        command
                    )
                )

                attacker[
                    "commands"
                ] += 1

                attacker[
                    "commands_seen"
                ][command] += 1

                attacker[
                    "categories"
                ][category] += 1

                attacker[
                    "active"
                ] = True

                attacker[
                    "timeline"
                ].append({

                    "time": readable_time,

                    "type":
                        "COMMAND",

                    "details":
                        f"[{category}] "
                        f"{command}",

                })


        # ----------------------------------------------------
        # FAILED COMMAND
        # ----------------------------------------------------

        elif event_id == "cowrie.command.failed":

            attacker[
                "failed_commands"
            ] += 1

            command = safe(
                event.get(
                    "input"
                ),
                ""
            )

            attacker[
                "timeline"
            ].append({

                "time": readable_time,

                "type":
                    "FAILED COMMAND",

                "details":
                    command,

            })


        # ----------------------------------------------------
        # SESSION CLOSED
        # ----------------------------------------------------

        elif event_id == "cowrie.session.closed":

            attacker[
                "active"
            ] = False

            attacker[
                "timeline"
            ].append({

                "time": readable_time,

                "type":
                    "SESSION CLOSED",

                "details":
                    "SSH session closed",

            })


    return attackers


# ============================================================
# GLOBAL EVENT STATISTICS
# ============================================================

def analyze_events(events):

    statistics = {

        "connections": 0,

        "successful_logins": 0,

        "failed_logins": 0,

        "commands": 0,

        "failed_commands": 0,

        "command_counter": Counter(),

        "category_counter": Counter(),

        "username_counter": Counter(),

        "password_counter": Counter(),

        "source_ips": Counter(),

        "sessions": set(),

        "timeline": [],

    }


    for event in events:

        event_id = event.get(
            "eventid",
            ""
        )

        ip = safe(
            event.get(
                "src_ip"
            ),
            "-"
        )

        session = safe(
            event.get(
                "session"
            ),
            ""
        )

        timestamp = safe(
            event.get(
                "timestamp"
            ),
            "-"
        )


        if session:

            statistics[
                "sessions"
            ].add(session)


        # ----------------------------------------------------
        # CONNECTION
        # ----------------------------------------------------

        if event_id == "cowrie.session.connect":

            statistics[
                "connections"
            ] += 1

            statistics[
                "source_ips"
            ][ip] += 1

            statistics[
                "timeline"
            ].append({

                "timestamp": timestamp,

                "ip": ip,

                "type":
                    "CONNECTION",

                "details":
                    "New SSH connection",

            })


        # ----------------------------------------------------
        # LOGIN SUCCESS
        # ----------------------------------------------------

        elif event_id == "cowrie.login.success":

            statistics[
                "successful_logins"
            ] += 1

            username = safe(
                event.get(
                    "username"
                ),
                "-"
            )

            password = safe(
                event.get(
                    "password"
                ),
                "-"
            )

            statistics[
                "username_counter"
            ][username] += 1

            statistics[
                "password_counter"
            ][password] += 1

            statistics[
                "timeline"
            ].append({

                "timestamp": timestamp,

                "ip": ip,

                "type":
                    "LOGIN SUCCESS",

                "details":
                    f"Username={username}",

            })


        # ----------------------------------------------------
        # LOGIN FAILED
        # ----------------------------------------------------

        elif event_id == "cowrie.login.failed":

            statistics[
                "failed_logins"
            ] += 1

            username = safe(
                event.get(
                    "username"
                ),
                "-"
            )

            password = safe(
                event.get(
                    "password"
                ),
                "-"
            )

            statistics[
                "username_counter"
            ][username] += 1

            statistics[
                "password_counter"
            ][password] += 1

            statistics[
                "timeline"
            ].append({

                "timestamp": timestamp,

                "ip": ip,

                "type":
                    "LOGIN FAILED",

                "details":
                    f"Username={username}",

            })


        # ----------------------------------------------------
        # COMMAND
        # ----------------------------------------------------

        elif event_id == "cowrie.command.input":

            command = safe(
                event.get(
                    "input"
                ),
                ""
            )

            if command:

                statistics[
                    "commands"
                ] += 1

                statistics[
                    "command_counter"
                ][command] += 1

                category = (
                    classify_command(
                        command
                    )
                )

                statistics[
                    "category_counter"
                ][category] += 1


        # ----------------------------------------------------
        # FAILED COMMAND
        # ----------------------------------------------------

        elif event_id == "cowrie.command.failed":

            statistics[
                "failed_commands"
            ] += 1


    return statistics


# ============================================================
# RISK ANALYSIS
# ============================================================

def overall_risk(
    statistics,
    attackers
):

    score = 0

    score += (
        statistics[
            "successful_logins"
        ] * 3
    )

    score += (
        statistics[
            "failed_logins"
        ] * 2
    )

    score += (
        statistics[
            "failed_commands"
        ]
    )

    score += (
        statistics[
            "category_counter"
        ].get(
            "NETWORK ENUM",
            0
        ) * 2
    )

    score += (
        statistics[
            "category_counter"
        ].get(
            "DOWNLOAD",
            0
        ) * 3
    )

    score += (
        statistics[
            "category_counter"
        ].get(
            "CREDENTIAL ENUM",
            0
        ) * 4
    )

    score += (
        statistics[
            "category_counter"
        ].get(
            "PRIV ESC",
            0
        ) * 5
    )

    score += (
        statistics[
            "category_counter"
        ].get(
            "PERMISSION",
            0
        ) * 4
    )

    score += (
        statistics[
            "category_counter"
        ].get(
            "SHELL",
            0
        ) * 4
    )

    if score >= 40:
        return "CRITICAL", score

    if score >= 25:
        return "HIGH", score

    if score >= 10:
        return "MEDIUM", score

    return "LOW", score


# ============================================================
# RECOMMENDATIONS
# ============================================================

def generate_recommendations(
    statistics,
    attackers
):

    recommendations = []


    if statistics[
        "failed_logins"
    ] > 0:

        recommendations.append(
            "Review failed authentication "
            "attempts and identify repeated "
            "credential guessing."
        )


    if statistics[
        "successful_logins"
    ] > 0:

        recommendations.append(
            "Investigate successful honeypot "
            "logins and record the credentials "
            "used by the attacker."
        )


    if statistics[
        "category_counter"
    ].get(
        "NETWORK ENUM",
        0
    ) > 0:

        recommendations.append(
            "Network enumeration was observed. "
            "Review commands such as ip, "
            "ifconfig, ss and netstat."
        )


    if statistics[
        "category_counter"
    ].get(
        "DOWNLOAD",
        0
    ) > 0:

        recommendations.append(
            "Download/retrieval activity was "
            "observed. Review wget/curl "
            "commands for attempted payload "
            "retrieval."
        )


    if statistics[
        "category_counter"
    ].get(
        "PRIV ESC",
        0
    ) > 0:

        recommendations.append(
            "Privilege-escalation behaviour was "
            "observed. Review sudo/su activity."
        )


    if statistics[
        "category_counter"
    ].get(
        "PERMISSION",
        0
    ) > 0:

        recommendations.append(
            "Permission modification commands "
            "were observed. Review chmod/chown "
            "activity."
        )


    if statistics[
        "category_counter"
    ].get(
        "SHELL",
        0
    ) > 0:

        recommendations.append(
            "Shell/interpreter execution was "
            "observed. Review bash, sh, Python "
            "and similar commands."
        )


    if len(attackers) > 1:

        recommendations.append(
            "Multiple source IP addresses were "
            "observed. Analyze attackers "
            "individually."
        )


    if not recommendations:

        recommendations.append(
            "No major high-risk behaviour was "
            "identified from the recorded "
            "events."
        )


    return recommendations


# ============================================================
# TEXT REPORT
# ============================================================

def create_text_report(
    history,
    statistics,
    attackers,
    risk,
    score
):

    lines = []


    def add(text=""):

        lines.append(text)


    add("=" * WIDTH)

    add(
        "COWRIE SOC ATTACK ANALYSIS REPORT"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()

    add(
        "Generated: "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    add()


    # --------------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------------

    add("=" * WIDTH)

    add(
        "EXECUTIVE SUMMARY"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()

    add(
        f"Overall Risk Level : {risk}"
    )

    add(
        f"Risk Score         : {score}"
    )

    add(
        f"Unique Attackers   : {len(attackers)}"
    )

    add(
        f"Connections        : "
        f"{statistics['connections']}"
    )

    add(
        f"Successful Logins  : "
        f"{statistics['successful_logins']}"
    )

    add(
        f"Failed Logins      : "
        f"{statistics['failed_logins']}"
    )

    add(
        f"Commands           : "
        f"{statistics['commands']}"
    )

    add(
        f"Failed Commands    : "
        f"{statistics['failed_commands']}"
    )

    add()


    # --------------------------------------------------------
    # ATTACKER ANALYSIS
    # --------------------------------------------------------

    add("=" * WIDTH)

    add(
        "ATTACKER ANALYSIS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()


    if attackers:

        for ip, attacker in attackers.items():

            severity = calculate_severity(
                attacker
            )

            add(
                f"IP ADDRESS : {ip}"
            )

            add(
                f"NETWORK    : "
                f"{attacker['network_type']}"
            )

            add(
                f"MAC        : "
                f"{attacker['mac']}"
            )

            add(
                f"LOCATION   : "
                f"{attacker['city']}, "
                f"{attacker['region']}, "
                f"{attacker['country']}"
            )

            add(
                f"ISP        : "
                f"{attacker['isp']}"
            )

            add(
                f"SEVERITY   : {severity}"
            )

            add(
                f"CONNECTIONS: "
                f"{attacker['connections']}"
            )

            add(
                f"SUCCESSFUL LOGINS: "
                f"{attacker['successful_logins']}"
            )

            add(
                f"FAILED LOGINS    : "
                f"{attacker['failed_logins']}"
            )

            add(
                f"COMMANDS         : "
                f"{attacker['commands']}"
            )

            add(
                f"FAILED COMMANDS  : "
                f"{attacker['failed_commands']}"
            )

            add(
                f"FIRST SEEN       : "
                f"{safe(attacker['first_seen'])}"
            )

            add(
                f"LAST SEEN        : "
                f"{safe(attacker['last_seen'])}"
            )

            add()

            add(
                "Attack categories:"
            )

            for category, count in (
                attacker[
                    "categories"
                ].most_common()
            ):

                add(
                    f"  {category:<20}"
                    f"{count}"
                )

            add()

            add(
                "Usernames observed:"
            )

            for username, count in (
                attacker[
                    "usernames"
                ].most_common(10)
            ):

                add(
                    f"  {username:<25}"
                    f"{count}"
                )

            add()

            add(
                "Passwords observed:"
            )

            for password, count in (
                attacker[
                    "passwords"
                ].most_common(10)
            ):

                add(
                    f"  {password:<25}"
                    f"{count}"
                )

            add()

            add(
                "Top commands:"
            )

            for command, count in (
                attacker[
                    "commands_seen"
                ].most_common(10)
            ):

                add(
                    f"  {command:<35}"
                    f"{count}"
                )

            add()

            add(
                "-" * WIDTH
            )

            add()


    else:

        add(
            "No attackers recorded."
        )


    # --------------------------------------------------------
    # GLOBAL ATTACK CATEGORIES
    # --------------------------------------------------------

    add("=" * WIDTH)

    add(
        "ATTACK CATEGORY ANALYSIS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()


    for category, count in (
        statistics[
            "category_counter"
        ].most_common()
    ):

        add(
            f"{category:<25}"
            f"{count}"
        )


    # --------------------------------------------------------
    # TOP COMMANDS
    # --------------------------------------------------------

    add()

    add("=" * WIDTH)

    add(
        "TOP COMMANDS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()


    for command, count in (
        statistics[
            "command_counter"
        ].most_common(20)
    ):

        add(
            f"{command:<40}"
            f"{count}"
        )


    # --------------------------------------------------------
    # CREDENTIAL ANALYSIS
    # --------------------------------------------------------

    add()

    add("=" * WIDTH)

    add(
        "CREDENTIAL ANALYSIS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()

    add(
        "Usernames observed:"
    )

    for username, count in (
        statistics[
            "username_counter"
        ].most_common(20)
    ):

        add(
            f"  {username:<30}"
            f"{count}"
        )


    add()

    add(
        "Passwords observed:"
    )

    for password, count in (
        statistics[
            "password_counter"
        ].most_common(20)
    ):

        add(
            f"  {password:<30}"
            f"{count}"
        )


    # --------------------------------------------------------
    # SOURCE IP ANALYSIS
    # --------------------------------------------------------

    add()

    add("=" * WIDTH)

    add(
        "SOURCE IP ANALYSIS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()


    for ip, count in (
        statistics[
            "source_ips"
        ].most_common()
    ):

        add(
            f"{ip:<25}"
            f"{network_type(ip):<20}"
            f"{count} connections"
        )


    # --------------------------------------------------------
    # SESSION ANALYSIS
    # --------------------------------------------------------

    add()

    add("=" * WIDTH)

    add(
        "SESSION ANALYSIS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()

    add(
        f"Unique SSH sessions: "
        f"{len(statistics['sessions'])}"
    )


    # --------------------------------------------------------
    # TIMELINE
    # --------------------------------------------------------

    add()

    add("=" * WIDTH)

    add(
        "ATTACK TIMELINE"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()


    for event in statistics[
        "timeline"
    ][-100:]:

        add(
            f"{event['timestamp']} | "
            f"{event['ip']:<16} | "
            f"{event['type']:<16} | "
            f"{event['details']}"
        )


    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    add()

    add("=" * WIDTH)

    add(
        "SECURITY RECOMMENDATIONS"
        .center(WIDTH)
    )

    add("=" * WIDTH)

    add()


    recommendations = (
        generate_recommendations(
            statistics,
            attackers
        )
    )


    for number, recommendation in enumerate(
        recommendations,
        start=1
    ):

        add(
            f"{number}. "
            f"{recommendation}"
        )


    add()

    add("=" * WIDTH)

    add(
        "END OF REPORT"
        .center(WIDTH)
    )

    add("=" * WIDTH)


    return "\n".join(lines)


# ============================================================
# JSON REPORT
# ============================================================

def create_json_report(
    history,
    statistics,
    attackers,
    risk,
    score
):

    attacker_output = {}


    for ip, attacker in attackers.items():

        attacker_output[ip] = {

            "ip":
                attacker["ip"],

            "network_type":
                attacker["network_type"],

            "mac":
                attacker["mac"],

            "country":
                attacker["country"],

            "region":
                attacker["region"],

            "city":
                attacker["city"],

            "isp":
                attacker["isp"],

            "severity":
                calculate_severity(
                    attacker
                ),

            "connections":
                attacker["connections"],

            "successful_logins":
                attacker[
                    "successful_logins"
                ],

            "failed_logins":
                attacker[
                    "failed_logins"
                ],

            "commands":
                attacker["commands"],

            "failed_commands":
                attacker[
                    "failed_commands"
                ],

            "categories":
                dict(
                    attacker[
                        "categories"
                    ]
                ),

            "top_commands":
                dict(
                    attacker[
                        "commands_seen"
                    ].most_common(20)
                ),

            "usernames":
                dict(
                    attacker[
                        "usernames"
                    ]
                ),

            "passwords":
                dict(
                    attacker[
                        "passwords"
                    ]
                ),

            "sessions":
                list(
                    attacker[
                        "sessions"
                    ]
                ),

            "first_seen":
                attacker["first_seen"],

            "last_seen":
                attacker["last_seen"],

            "timeline":
                attacker["timeline"],
        }


    return {

        "generated_at":
            datetime.now().isoformat(),

        "overall_risk":
            risk,

        "risk_score":
            score,

        "statistics": {

            "connections":
                statistics[
                    "connections"
                ],

            "successful_logins":
                statistics[
                    "successful_logins"
                ],

            "failed_logins":
                statistics[
                    "failed_logins"
                ],

            "commands":
                statistics[
                    "commands"
                ],

            "failed_commands":
                statistics[
                    "failed_commands"
                ],

            "unique_attackers":
                len(attackers),

            "unique_sessions":
                len(
                    statistics[
                        "sessions"
                    ]
                ),

        },

        "attack_categories":
            dict(
                statistics[
                    "category_counter"
                ]
            ),

        "top_commands":
            dict(
                statistics[
                    "command_counter"
                ].most_common(20)
            ),

        "usernames":
            dict(
                statistics[
                    "username_counter"
                ]
            ),

        "passwords":
            dict(
                statistics[
                    "password_counter"
                ]
            ),

        "source_ips":
            dict(
                statistics[
                    "source_ips"
                ]
            ),

        "attackers":
            attacker_output,

        "recommendations":
            generate_recommendations(
                statistics,
                attackers
            ),
    }


# ============================================================
# SAVE REPORTS
# ============================================================

def save_reports(
    text_report,
    json_report
):

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    text_path = os.path.join(
        REPORT_DIR,
        f"cowrie_report_{timestamp}.txt"
    )

    json_path = os.path.join(
        REPORT_DIR,
        f"cowrie_report_{timestamp}.json"
    )


    try:

        with open(
            text_path,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                text_report
            )


        with open(
            json_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                json_report,
                file,
                indent=4,
                default=str
            )


        return text_path, json_path


    except Exception as error:

        print(
            f"{RED}[!] Could not save report: "
            f"{error}{RESET}"
        )

        return None, None


# ============================================================
# TERMINAL SUMMARY
# ============================================================

def print_terminal_report(
    statistics,
    attackers,
    risk,
    score
):

    clear_screen()

    print()

    print(
        f"{BLUE}{line("=")}{RESET}"
    )

    print(
        f"{CYAN}"
        f"{'COWRIE SOC ATTACK REPORT'.center(WIDTH)}"
        f"{RESET}"
    )

    print(
        f"{BLUE}{line("=")}{RESET}"
    )

    print()

    risk_colour = (
        severity_color(
            risk
        )
    )

    print(
        f"Overall Risk : "
        f"{risk_colour}{risk}{RESET}"
    )

    print(
        f"Risk Score   : {score}"
    )

    print()

    print(
        f"{WHITE}"
        "---------------- OVERALL STATISTICS ----------------"
        f"{RESET}"
    )

    print(
        f"Connections       : "
        f"{statistics['connections']}"
    )

    print(
        f"Successful logins : "
        f"{statistics['successful_logins']}"
    )

    print(
        f"Failed logins     : "
        f"{statistics['failed_logins']}"
    )

    print(
        f"Commands          : "
        f"{statistics['commands']}"
    )

    print(
        f"Failed commands   : "
        f"{statistics['failed_commands']}"
    )

    print(
        f"Unique attackers  : "
        f"{len(attackers)}"
    )

    print(
        f"Unique sessions   : "
        f"{len(statistics['sessions'])}"
    )


    # --------------------------------------------------------
    # ATTACKERS
    # --------------------------------------------------------

    print()

    print(
        f"{WHITE}"
        "---------------- ATTACKERS ----------------"
        f"{RESET}"
    )


    if attackers:

        for ip, attacker in attackers.items():

            severity = (
                calculate_severity(
                    attacker
                )
            )

            colour = (
                severity_color(
                    severity
                )
            )

            status = (
                "ACTIVE"
                if attacker["active"]
                else "CLOSED"
            )

            print()

            print(
                f"IP       : {ip}"
            )

            print(
                f"Network  : "
                f"{attacker['network_type']}"
            )

            print(
                f"Location : "
                f"{attacker['city']}, "
                f"{attacker['country']}"
            )

            print(
                f"Severity : "
                f"{colour}{severity}{RESET}"
            )

            print(
                f"Status   : {status}"
            )

            print(
                f"Connections : "
                f"{attacker['connections']}"
            )

            print(
                f"Logins     : "
                f"{attacker['successful_logins']}"
            )

            print(
                f"Failed logins : "
                f"{attacker['failed_logins']}"
            )

            print(
                f"Commands   : "
                f"{attacker['commands']}"
            )

            print(
                f"Failed commands : "
                f"{attacker['failed_commands']}"
            )


    # --------------------------------------------------------
    # ATTACK TYPES
    # --------------------------------------------------------

    print()

    print(
        f"{WHITE}"
        "---------------- ATTACK TYPES ----------------"
        f"{RESET}"
    )


    if statistics[
        "category_counter"
    ]:

        for category, count in (
            statistics[
                "category_counter"
            ].most_common()
        ):

            print(
                f"{category:<22}"
                f"{count}"
            )

    else:

        print(
            "No attack categories recorded."
        )


    # --------------------------------------------------------
    # TOP COMMANDS
    # --------------------------------------------------------

    print()

    print(
        f"{WHITE}"
        "---------------- TOP COMMANDS ----------------"
        f"{RESET}"
    )


    if statistics[
        "command_counter"
    ]:

        for command, count in (
            statistics[
                "command_counter"
            ].most_common(10)
        ):

            print(
                f"{command:<35}"
                f"{count}"
            )

    else:

        print(
            "No commands recorded."
        )


    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    print()

    print(
        f"{WHITE}"
        "---------------- ANALYST NOTES ----------------"
        f"{RESET}"
    )


    for recommendation in (
        generate_recommendations(
            statistics,
            attackers
        )
    ):

        print(
            f"- {recommendation}"
        )


    print()


# ============================================================
# MAIN
# ============================================================

def main():

    print()

    print(
        f"{CYAN}"
        "Generating Cowrie SOC report..."
        f"{RESET}"
    )

    print()


    # --------------------------------------------------------
    # LOAD HISTORY
    # --------------------------------------------------------

    history = load_json_file(
        HISTORY_FILE
    )


    # --------------------------------------------------------
    # LOAD COWRIE EVENTS
    # --------------------------------------------------------

    events = load_cowrie_events()


    if not events:

        print(
            f"{YELLOW}"
            "[!] No Cowrie events found."
            f"{RESET}"
        )

        print()

        print(
            f"Expected log:"
        )

        print(
            f"  {COWRIE_LOG}"
        )

        print()

        print(
            "Make sure Cowrie has recorded "
            "at least one event."
        )

        return


    # --------------------------------------------------------
    # ANALYZE
    # --------------------------------------------------------

    statistics = analyze_events(
        events
    )

    attackers = build_attackers(
        events
    )


    risk, score = overall_risk(
        statistics,
        attackers
    )


    # --------------------------------------------------------
    # CREATE REPORT
    # --------------------------------------------------------

    text_report = create_text_report(
        history,
        statistics,
        attackers,
        risk,
        score
    )


    json_report = create_json_report(
        history,
        statistics,
        attackers,
        risk,
        score
    )


    # --------------------------------------------------------
    # TERMINAL OUTPUT
    # --------------------------------------------------------

    print_terminal_report(
        statistics,
        attackers,
        risk,
        score
    )


    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

    text_path, json_path = (
        save_reports(
            text_report,
            json_report
        )
    )


    print(
        f"{GREEN}"
        "------------------------------------------------"
        f"{RESET}"
    )

    if text_path:

        print(
            f"{GREEN}[+] Text report:"
            f"{RESET} {text_path}"
        )

    if json_path:

        print(
            f"{GREEN}[+] JSON report:"
            f"{RESET} {json_path}"
        )

    print(
        f"{GREEN}"
        "------------------------------------------------"
        f"{RESET}"
    )

    print()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()

        print(
            f"{YELLOW}"
            "Report generation cancelled."
            f"{RESET}"
        )

        print()

    except Exception as error:

        print()

        print(
            f"{RED}"
            "[!] Unexpected error:"
            f"{RESET}"
        )

        print(
            f"{error}"
        )

        print()

        sys.exit(1)
