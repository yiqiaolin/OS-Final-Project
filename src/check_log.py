
from collections import Counter

# 儲存所有日誌
logs = []

# 獨立計數器
total_lines = 0
parsed_lines = 0
special_lines = 0

# 程序出現次數
process_counts = Counter()

# 讀取整份日誌
with open("Linux_processed.log", "r", encoding="utf-8") as file:

    for line_number, line in enumerate(file, start=1):
        total_lines += 1

        # 將 Header 與 Message 分開
        parts = line.split(": ", 1)

        # 特殊格式：找不到 ": "
        if len(parts) != 2:
            special_lines += 1

            log = {
                "line_number": line_number,
                "timestamp": None,
                "hostname": None,
                "process": None,
                "message": line.rstrip("\n"),
                "status": "special"
            }

            logs.append(log)
            continue

        # 解析 Header
        header = parts[0]
        fields = header.split()

        # 特殊格式：Header 欄位不足
        if len(fields) < 5:
            special_lines += 1

            log = {
                "line_number": line_number,
                "timestamp": None,
                "hostname": None,
                "process": None,
                "message": line.rstrip("\n"),
                "status": "special"
            }

            logs.append(log)
            continue

        # 一般格式日誌
        process_name = fields[4].split("[", 1)[0]

        log = {
            "line_number": line_number,
            "timestamp": " ".join(fields[:3]),
            "hostname": fields[3],
            "process": process_name,
            "message": parts[1].rstrip("\n"),
            "status": "parsed"
        }

        logs.append(log)
        parsed_lines += 1

        # 統計程序頻率
        process_counts[process_name] += 1


# ===================================
# 統計與驗證
# ===================================

print("===== Dataset Summary =====")
print("Total:", total_lines)
print("Parsed:", parsed_lines)
print("Special:", special_lines)
print("Stored:", len(logs))

print()
print("Complete:", total_lines == parsed_lines + special_lines)
print("All stored:", len(logs) == total_lines)

print()
print("===== Top 10 Processes =====")

for name, count in process_counts.most_common(10):
    print(name, count)

print()
print("===== Special Records =====")

for log in logs:
    if log["status"] == "special":
        print(
            f"Line {log['line_number']}: "
            f"{log['message'][:100]}"
        )

# ===================================
# 月份分布初步調查
# ===================================

month_counts = Counter()

for log in logs:
    if log["status"] == "parsed":
        month = log["timestamp"].split()[0]
    else:
        month = log["message"].split()[0]

    month_counts[month] += 1

print("\n===== Monthly Distribution =====")

for month, count in month_counts.items():
    print(month, count)

print("Total:", sum(month_counts.values()))


# ===================================
# 常見訊息統計
# ===================================

message_counts = Counter()

for log in logs:
    if log["status"] == "parsed":
        message_counts[log["message"]] += 1

print("\n===== Top 10 Messages =====")

for message, count in message_counts.most_common(10):
    print(f"{count} | {message[:120]}")

print("\nUnique Messages:", len(message_counts))


# ===================================
# 低頻率訊息調查
# ===================================

once_messages = sum(
    1 for count in message_counts.values()
    if count == 1
)

print("\n===== Rare Message Summary =====")
print("Unique messages:", len(message_counts))
print("Messages appearing once:", once_messages)
print(
    "Percentage:",
    round(once_messages / len(message_counts) * 100, 2),
    "%"
)


# ===================================
# 候選事件關鍵字統計
# ===================================

keywords = [
    "error",
    "failed",
    "warning",
    "alert",
    "authentication",
    "password",
    "session"
]

keyword_counts = Counter()

for log in logs:
    message = log["message"].lower()

    for keyword in keywords:
        if keyword in message:
            keyword_counts[keyword] += 1

print("\n===== Keyword Summary =====")

for keyword in keywords:
    print(keyword, keyword_counts[keyword])
