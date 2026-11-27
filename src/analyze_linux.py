
#!/usr/bin/env python3
"""
Linux System Log Analyzer
Operating Systems Final Project

Usage:
    python3 analyze_linux.py Linux.log

Outputs:
    linux_analysis/
        summary.txt
        parsed_logs.csv
        process_frequency.csv
        event_frequency.csv
        template_frequency.csv
        hourly_frequency.csv
        daily_frequency.csv
        keyword_frequency.csv
        anomaly_windows.csv
        unparsed_logs.csv
"""

import argparse
import csv
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ============================================================
# 1. Configuration
# ============================================================

LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:\[]+?)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3,
    "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9,
    "Oct": 10, "Nov": 11, "Dec": 12
}

KEYWORDS = [
    "error",
    "failed",
    "failure",
    "warning",
    "alert",
    "authentication",
    "password",
    "session",
    "timeout",
    "denied",
    "refused",
    "invalid"
]

# Heuristic threshold: not a ground-truth anomaly label.
ANOMALY_THRESHOLD = 20
ANOMALY_WINDOW_SECONDS = 60


# ============================================================
# 2. Parse Linux Log
# ============================================================

def parse_log(line, line_number):
    match = LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    month = MONTHS.get(data["month"])

    if month is None:
        return None

    day = int(data["day"])
    time_string = data["time"]

    # Linux.log does not necessarily contain a year.
    # Keep the original timestamp rather than inventing one.
    timestamp = (
        f"{data['month']} {day:02d} {time_string}"
    )

    return {
        "line_number": line_number,
        "timestamp": timestamp,
        "month": month,
        "day": day,
        "time": time_string,
        "host": data["host"],
        "process": data["process"].strip(),
        "pid": data["pid"] or "",
        "message": data["message"],
        "raw": line
    }


# ============================================================
# 3. Normalize Event Templates
# ============================================================

def normalize_message(message):
    text = message

    # IP addresses
    text = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "<IP>",
        text
    )

    # UUID
    text = re.sub(
        r"\b[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}\b",
        "<UUID>",
        text
    )

    # Hexadecimal values
    text = re.sub(
        r"\b0x[0-9a-fA-F]+\b",
        "<HEX>",
        text
    )

    # Common authentication usernames
    text = re.sub(
        r"\b(for (?:invalid user |user )?)"
        r"([A-Za-z_][A-Za-z0-9_.-]*)"
        r"(?=\s+from\b)",
        r"\1<USER>",
        text,
        flags=re.IGNORECASE
    )

    # Standalone numbers
    text = re.sub(
        r"\b\d+\b",
        "<NUM>",
        text
    )

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


# ============================================================
# 4. Event Classification
# ============================================================

def classify_event(process, message):
    p = process.lower()
    m = message.lower()

    if "sshd" in p:
        if "failed password" in m:
            return "SSH Failed Password"

        if "accepted password" in m:
            return "SSH Accepted Password"

        if "accepted publickey" in m:
            return "SSH Accepted Public Key"

        if "authentication failure" in m:
            return "SSH Authentication Failure"

        if "session opened" in m:
            return "SSH Session Opened"

        if "session closed" in m:
            return "SSH Session Closed"

        return "SSH Other"

    if "ftpd" in p or "vsftpd" in p:
        return "FTP Activity"

    if p == "kernel":
        if any(
            word in m
            for word in ["error", "failed", "warning", "oops", "panic"]
        ):
            return "Kernel Error/Warning"

        return "Kernel Activity"

    if "cron" in p:
        return "Scheduled Task"

    if "sudo" in p:
        return "Privilege Activity"

    if "authentication failure" in m:
        return "Authentication Failure"

    if "session opened" in m:
        return "Session Opened"

    if "session closed" in m:
        return "Session Closed"

    if "error" in m or "failed" in m:
        return "Other Error/Failure"

    return "Other System Activity"


# ============================================================
# 5. CSV Export
# ============================================================

def write_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def export_counter(path, counter, key_name):
    rows = [
        (key, count)
        for key, count in counter.most_common()
    ]

    write_csv(path, [key_name, "count"], rows)


# ============================================================
# 6. Anomaly Detection
# ============================================================

def detect_anomalies(records):
    """
    Detect minutes containing many selected failure events.

    This is an exploratory heuristic, not a validated detector.
    """

    windows = defaultdict(list)

    for record in records:
        event = record["event"]

        if event not in {
            "SSH Failed Password",
            "SSH Authentication Failure",
            "Kernel Error/Warning",
            "Authentication Failure",
            "Other Error/Failure"
        }:
            continue

        # Month/day/hour/minute, no assumed year.
        minute = (
            f"{record['month']:02d}-"
            f"{record['day']:02d} "
            f"{record['time'][:5]}"
        )

        windows[minute].append(record)

    anomalies = []

    for minute, events in sorted(windows.items()):
        count = len(events)

        if count >= ANOMALY_THRESHOLD:
            event_counts = Counter(
                item["event"] for item in events
            )

            anomalies.append((
                minute,
                count,
                "; ".join(
                    f"{name}: {n}"
                    for name, n in event_counts.most_common()
                ),
                events[0]["line_number"],
                events[-1]["line_number"]
            ))

    return anomalies


# ============================================================
# 7. Main Analysis
# ============================================================

def analyze(input_path, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    process_counts = Counter()
    event_counts = Counter()
    template_counts = Counter()
    keyword_counts = Counter()
    hourly_counts = Counter()
    daily_counts = Counter()
    host_counts = Counter()

    records = []
    unparsed = []

    total_lines = 0

    with open(
        input_path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        for line_number, raw_line in enumerate(f, start=1):
            total_lines += 1
            line = raw_line.rstrip("\r\n")

            record = parse_log(line, line_number)

            if record is None:
                unparsed.append((line_number, line))
                continue

            process = record["process"]
            message = record["message"]

            event = classify_event(process, message)
            template = normalize_message(message)

            record["event"] = event
            record["template"] = template

            records.append(record)

            process_counts[process] += 1
            event_counts[event] += 1
            template_counts[(process, template)] += 1
            host_counts[record["host"]] += 1

            hour = (
                f"{record['month']:02d}-"
                f"{record['day']:02d} "
                f"{record['time'][:2]}:00"
            )

            day = (
                f"{record['month']:02d}-"
                f"{record['day']:02d}"
            )

            hourly_counts[hour] += 1
            daily_counts[day] += 1

            message_lower = message.lower()

            for keyword in KEYWORDS:
                if keyword in message_lower:
                    keyword_counts[keyword] += 1

    # --------------------------------------------------------
    # Export parsed records
    # --------------------------------------------------------

    write_csv(
        output_dir / "parsed_logs.csv",
        [
            "line_number",
            "timestamp",
            "host",
            "process",
            "pid",
            "event",
            "template",
            "message"
        ],
        [
            (
                r["line_number"],
                r["timestamp"],
                r["host"],
                r["process"],
                r["pid"],
                r["event"],
                r["template"],
                r["message"]
            )
            for r in records
        ]
    )

    export_counter(
        output_dir / "process_frequency.csv",
        process_counts,
        "process"
    )

    export_counter(
        output_dir / "event_frequency.csv",
        event_counts,
        "event"
    )

    write_csv(
        output_dir / "template_frequency.csv",
        ["process", "template", "count"],
        [
            (process, template, count)
            for (process, template), count
            in template_counts.most_common()
        ]
    )

    write_csv(
        output_dir / "hourly_frequency.csv",
        ["hour", "count"],
        sorted(hourly_counts.items())
    )

    write_csv(
        output_dir / "daily_frequency.csv",
        ["day", "count"],
        sorted(daily_counts.items())
    )

    write_csv(
        output_dir / "keyword_frequency.csv",
        ["keyword", "count"],
        [
            (keyword, keyword_counts[keyword])
            for keyword in KEYWORDS
        ]
    )

    write_csv(
        output_dir / "unparsed_logs.csv",
        ["line_number", "raw"],
        unparsed
    )

    anomalies = detect_anomalies(records)

    write_csv(
        output_dir / "anomaly_windows.csv",
        [
            "minute",
            "failure_event_count",
            "event_breakdown",
            "first_line",
            "last_line"
        ],
        anomalies
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    parsed_count = len(records)

    parse_rate = (
        parsed_count / total_lines * 100
        if total_lines else 0
    )

    summary = [
        "LINUX SYSTEM LOG ANALYSIS",
        "=" * 55,
        f"Input file: {input_path.name}",
        f"Total lines: {total_lines:,}",
        f"Parsed lines: {parsed_count:,}",
        f"Unparsed lines: {len(unparsed):,}",
        f"Parse success rate: {parse_rate:.2f}%",
        f"Unique processes: {len(process_counts):,}",
        f"Unique exact messages: "
        f"{len(set(r['message'] for r in records)):,}",
        f"Unique process-template pairs: "
        f"{len(template_counts):,}",
        f"Detected anomaly windows: {len(anomalies):,}",
        "",
        "TOP 10 PROCESSES",
        "-" * 55
    ]

    for name, count in process_counts.most_common(10):
        summary.append(f"{name}: {count:,}")

    summary += [
        "",
        "EVENT CLASSIFICATION",
        "-" * 55
    ]

    for name, count in event_counts.most_common():
        summary.append(f"{name}: {count:,}")

    summary += [
        "",
        "KEYWORD COUNTS",
        "-" * 55
    ]

    for keyword in KEYWORDS:
        summary.append(
            f"{keyword}: {keyword_counts[keyword]:,}"
        )

    summary += [
        "",
        "NOTES",
        "-" * 55,
        "1. Linux timestamps may not contain a year.",
        "2. Template normalization is heuristic.",
        "3. Keyword counts may overlap.",
        "4. Event categories are rule-based.",
        "5. Anomaly windows are not ground-truth labels.",
        "6. Unparsed lines are retained separately."
    ]

    summary_text = "\n".join(summary)

    (output_dir / "summary.txt").write_text(
        summary_text,
        encoding="utf-8"
    )

    print(summary_text)

    print()
    print(f"Analysis completed: {output_dir.resolve()}")


# ============================================================
# 8. Entry Point
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Linux system logs."
    )

    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to Linux.log"
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("linux_analysis"),
        help="Output directory"
    )

    args = parser.parse_args()

    if not args.logfile.is_file():
        parser.error(
            f"File not found: {args.logfile}"
        )

    analyze(args.logfile, args.output)


if __name__ == "__main__":
    main()
