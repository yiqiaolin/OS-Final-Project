import csv
import re
from collections import Counter
from datetime import datetime

MONTH_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"
}

def parse_time_info(ts):
    parts = ts.split()
    if len(parts) < 3:
        return "unknown", "unknown", "unknown", None
    mm = MONTH_MAP.get(parts[0], "00")
    dd = parts[1].zfill(2)
    hh = parts[2][:2]
    hh_mm = parts[2][:5]
    # 補上虛擬年份 2005 以計算相鄰兩筆事件的秒數差
    try:
        dt = datetime.strptime(f"2005-{mm}-{dd} {parts[2]}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        dt = None
    return f"{mm}-{dd}", hh, f"{mm}-{dd} {hh_mm}", dt

# 1. 讀取全組共用的 anomaly_windows.csv
anomaly_windows = []
with open("anomaly_windows.csv", "r", encoding="utf-8", errors="ignore") as f:
    for row in csv.DictReader(f):
        anomaly_windows.append(row)
anomaly_minute_set = {w["minute"] for w in anomaly_windows}

# 2. 讀取 parsed_logs.csv 並精準分類
all_logs = []
minute_total_counts = Counter()

ssh_logs = []
ssh_by_date = Counter()
ssh_by_hour = Counter()
ssh_by_minute = Counter()

oom_logs = []
oom_by_date = Counter()
oom_by_hour = Counter()
oom_by_minute = Counter()
oom_killed_procs = Counter()

with open("parsed_logs.csv", "r", encoding="utf-8", errors="ignore") as f:
    for row in csv.DictReader(f):
        date_str, hour_str, minute_str, dt = parse_time_info(row["timestamp"])
        row["date_str"] = date_str
        row["hour_str"] = hour_str
        row["minute_str"] = minute_str
        row["dt"] = dt
        all_logs.append(row)
        minute_total_counts[minute_str] += 1

        event = row["event"]
        msg_lower = row["message"].lower()

        # 成員 3：SSH 驗證失敗
        if event == "SSH Authentication Failure":
            ssh_logs.append(row)
            ssh_by_date[date_str] += 1
            ssh_by_hour[hour_str] += 1
            ssh_by_minute[minute_str] += 1

        # 成員 4：純粹 OOM 記憶體不足事件
        if "out of memory" in msg_lower or "killed process" in msg_lower:
            oom_logs.append(row)
            oom_by_date[date_str] += 1
            oom_by_hour[hour_str] += 1
            oom_by_minute[minute_str] += 1
            m = re.search(r"killed process\s+\d+\s*\(([^)]+)\)", msg_lower)
            if m:
                oom_killed_procs[m.group(1)] += 1

# 計算相鄰事件時間間隔（證明短時間重複/連續發生）
def calc_burst_intervals(logs, threshold_sec=10):
    valid_dts = [r["dt"] for r in logs if r["dt"] is not None]
    short_gaps = 0
    zero_sec_gaps = 0
    for i in range(1, len(valid_dts)):
        diff = (valid_dts[i] - valid_dts[i - 1]).total_seconds()
        if 0 <= diff <= threshold_sec:
            short_gaps += 1
        if diff == 0:
            zero_sec_gaps += 1
    return len(valid_dts) - 1, short_gaps, zero_sec_gaps

ssh_pairs, ssh_le10s, ssh_0s = calc_burst_intervals(ssh_logs, 10)
oom_pairs, oom_le60s, oom_le10s = calc_burst_intervals(oom_logs, 60)
_, oom_le10s_only, _ = calc_burst_intervals(oom_logs, 10)

# 整理輸出報告文字
out = []
out.append("=======================================================")
out.append("【一】全組既有異常時間視窗 (anomaly_windows.csv 共 14 個)")
out.append("=======================================================")
for w in anomaly_windows:
    out.append(f"  {w['minute']} | 事件數: {w['failure_event_count']} | {w['event_breakdown']} (行 {w['first_line']}~{w['last_line']})")

out.append("\n=======================================================")
out.append("【二】成員 3：SSH 驗證失敗深度分析")
out.append("=======================================================")
out.append(f"SSH 驗證失敗總筆數: {len(ssh_logs)} 筆 (涵蓋 {len(ssh_by_date)} 天 / {len(ssh_by_minute)} 個活躍分鐘)")
out.append(f"相鄰兩筆失敗間隔 <= 10 秒: {ssh_le10s}/{ssh_pairs} 次 ({ssh_le10s/ssh_pairs*100:.2f}%)，其中同秒(0秒)連續發生: {ssh_0s} 次")
out.append("\n--- SSH 失敗次數 Top 5 日期 ---")
for d, c in ssh_by_date.most_common(5):
    out.append(f"  日期 {d}: {c} 筆 ({c/len(ssh_logs)*100:.2f}%)")

out.append("\n--- SSH 失敗次數 24 小時分布 (00時 ~ 23時) ---")
for h in [f"{i:02d}" for i in range(24)]:
    c = ssh_by_hour[h]
    out.append(f"  {h}:00 -> {c:4d} 筆 ({c/len(ssh_logs)*100:5.2f}%)")

out.append("\n--- SSH 單分鐘最高密度 Top 5 時間窗 ---")
for m, c in ssh_by_minute.most_common(5):
    in_aw = "[在 anomaly_windows 內]" if m in anomaly_minute_set else ""
    out.append(f"  分鐘 {m}: {c} 筆 {in_aw}")

out.append("\n=======================================================")
out.append("【三】成員 4：純 OOM 記憶體不足事件分析")
out.append("=======================================================")
out.append(f"純 OOM 事件總筆數: {len(oom_logs)} 筆 (涵蓋 {len(oom_by_date)} 天 / {len(oom_by_minute)} 個活躍分鐘)")
out.append(f"相鄰兩筆 OOM 間隔 <= 60 秒: {oom_le60s}/{oom_pairs} 次 ({oom_le60s/oom_pairs*100:.2f}%)；<= 10 秒: {oom_le10s_only} 次 ({oom_le10s_only/oom_pairs*100:.2f}%)")
out.append("\n--- OOM 發生日期分布 ---")
for d, c in oom_by_date.most_common():
    out.append(f"  日期 {d}: {c} 筆 ({c/len(oom_logs)*100:.2f}%)")

out.append("\n--- 受 OOM Killer 終止的程序統計 ---")
for proc, c in oom_killed_procs.most_common():
    out.append(f"  程序 {proc:10s}: {c:4d} 次 ({c/len(oom_logs)*100:5.2f}%)")

out.append("\n--- OOM 單分鐘最高密度 Top 5 時間窗 ---")
for m, c in oom_by_minute.most_common(5):
    out.append(f"  分鐘 {m}: {c} 筆")

out.append("\n=======================================================")
out.append("【四】SSH vs. 純 OOM 時間集中度量化比較表")
out.append("=======================================================")
def get_stats(name, total_n, by_date, by_minute):
    active_mins = len(by_minute)
    top1_m, top1_c = by_minute.most_common(1)[0]
    top5_c = sum(c for _, c in by_minute.most_common(5))
    top10_c = sum(c for _, c in by_minute.most_common(10))
    in_aw = sum(c for m, c in by_minute.items() if m in anomaly_minute_set)
    out.append(f"[{name}]")
    out.append(f"  總事件數: {total_n} 筆 | 活躍天數: {len(by_date)} 天 | 活躍分鐘數: {active_mins} 分鐘")
    out.append(f"  平均每活躍分鐘事件數: {total_n/active_mins:.2f} 筆/分")
    out.append(f"  單一最高峰分鐘 ({top1_m}): {top1_c} 筆 (佔 {top1_c/total_n*100:.2f}%)")
    out.append(f"  前 5 高峰分鐘累計: {top5_c} 筆 (佔 {top5_c/total_n*100:.2f}%)")
    out.append(f"  前 10 高峰分鐘累計: {top10_c} 筆 (佔 {top10_c/total_n*100:.2f}%)")
    out.append(f"  落入全組 14 個 anomaly_windows: {in_aw} 筆 ({in_aw/total_n*100:.2f}%)")
    return top5_c/total_n*100, top10_c/total_n*100, in_aw/total_n*100

ssh_t5, ssh_t10, ssh_aw_pct = get_stats("SSH 驗證失敗", len(ssh_logs), ssh_by_date, ssh_by_minute)
oom_t5, oom_t10, oom_aw_pct = get_stats("OOM 記憶體不足", len(oom_logs), oom_by_date, oom_by_minute)

out.append("\n=======================================================")
out.append("【五】代表性原始日誌片段（可直接貼入報告）")
out.append("=======================================================")
out.append("--- 案例 A：SSH 暴力破解突發視窗 (02-05 18:17，行 24459~24464) ---")
for r in all_logs:
    if 24459 <= int(r["line_number"]) <= 24464:
        out.append(f"  行 {r['line_number']}: {r['timestamp']} {r['process']}: {r['message']}")

out.append("\n--- 案例 B：OOM 連續終止多類程序片段 (Dec 05 11:05~11:06，行 20175~20181) ---")
for r in all_logs:
    if 20175 <= int(r["line_number"]) <= 20181:
        out.append(f"  行 {r['line_number']}: {r['timestamp']} {r['process']}: {r['message']}")

report_text = "\n".join(out)
print(report_text)
with open("rq2_results.txt", "w", encoding="utf-8") as f:
    f.write(report_text)

# 3. 自動產生 3 張 SVG 圖表（可用瀏覽器直接開啟）
# 圖 1：SSH 驗證失敗 24 小時分布圖
hours = [f"{i:02d}" for i in range(24)]
h_vals = [ssh_by_hour[h] for h in hours]
max_h = max(h_vals) or 1
svg1 = [
    '<svg xmlns="http://www.w3.org/2000/svg" width="860" height="420" style="background:#ffffff;font-family:Arial,sans-serif;">',
    '<text x="430" y="32" text-anchor="middle" font-size="18" font-weight="bold" fill="#1f2937">Figure 1: Hourly Distribution of SSH Authentication Failures (N = ' + str(len(ssh_logs)) + ')</text>',
    '<line x1="70" y1="355" x2="830" y2="355" stroke="#374151" stroke-width="1.5"/>',
    '<line x1="70" y1="65" x2="70" y2="355" stroke="#374151" stroke-width="1.5"/>',
    '<text x="22" y="210" text-anchor="middle" font-size="13" fill="#374151" transform="rotate(-90 22,210)">Event Count (logs)</text>',
    '<text x="450" y="402" text-anchor="middle" font-size="13" fill="#374151">Hour of Day (00:00 - 23:59)</text>'
]
for idx, (h, val) in enumerate(zip(hours, h_vals)):
    bar_h = (val / max_h) * 265
    x = 76 + idx * 31.4
    y = 355 - bar_h
    svg1.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="21" height="{bar_h:.1f}" fill="#2563eb" rx="2"/>')
    if val > 0:
        svg1.append(f'<text x="{x+10.5:.1f}" y="{y-5:.1f}" text-anchor="middle" font-size="10" fill="#1e3a8a">{val}</text>')
    svg1.append(f'<text x="{x+10.5:.1f}" y="373" text-anchor="middle" font-size="11" fill="#374151">{h}</text>')
svg1.append('</svg>')
with open("fig1_ssh_hourly.svg", "w", encoding="utf-8") as f:
    f.write("\n".join(svg1))

# 圖 2：受 OOM Killer 終止的程序排名圖
top_procs = oom_killed_procs.most_common(8)
max_p = top_procs[0][1] if top_procs else 1
svg2 = [
    '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="380" style="background:#ffffff;font-family:Arial,sans-serif;">',
    '<text x="410" y="32" text-anchor="middle" font-size="18" font-weight="bold" fill="#1f2937">Figure 2: Processes Terminated by Linux OOM Killer (Total Kills = ' + str(len(oom_logs)) + ')</text>',
    '<line x1="140" y1="60" x2="140" y2="330" stroke="#374151" stroke-width="1.5"/>',
    '<line x1="140" y1="330" x2="770" y2="330" stroke="#374151" stroke-width="1.5"/>',
    '<text x="455" y="365" text-anchor="middle" font-size="13" fill="#374151">Terminated Process Count (events)</text>'
]
row_step = 260 / max(len(top_procs), 1)
for idx, (proc, cnt) in enumerate(top_procs):
    bar_w = (cnt / max_p) * 540
    y = 68 + idx * row_step
    bh = min(24, row_step * 0.65)
    svg2.append(f'<text x="130" y="{y + bh*0.72:.1f}" text-anchor="end" font-size="13" font-weight="bold" fill="#1f2937">{proc}</text>')
    svg2.append(f'<rect x="140" y="{y:.1f}" width="{bar_w:.1f}" height="{bh:.1f}" fill="#dc2626" rx="3"/>')
    svg2.append(f'<text x="{148 + bar_w:.1f}" y="{y + bh*0.72:.1f}" font-size="12" fill="#7f1d1d">{cnt} ({cnt/len(oom_logs)*100:.1f}%)</text>')
svg2.append('</svg>')
with open("fig2_oom_processes.svg", "w", encoding="utf-8") as f:
    f.write("\n".join(svg2))

# 圖 3：SSH vs OOM 時間集中度指標比較圖
metrics = ["Top 5 Peak Mins (%)", "Top 10 Peak Mins (%)", "In Anomaly Windows (%)"]
ssh_m = [ssh_t5, ssh_t10, ssh_aw_pct]
oom_m = [oom_t5, oom_t10, oom_aw_pct]
max_m = max(ssh_m + oom_m + [10])
svg3 = [
    '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="400" style="background:#ffffff;font-family:Arial,sans-serif;">',
    '<text x="410" y="32" text-anchor="middle" font-size="18" font-weight="bold" fill="#1f2937">Figure 3: Temporal Concentration Comparison (SSH Auth Failure vs. OOM)</text>',
    '<rect x="540" y="52" width="16" height="16" fill="#2563eb"/><text x="562" y="65" font-size="12" fill="#1f2937">SSH Auth Failure</text>',
    '<rect x="685" y="52" width="16" height="16" fill="#dc2626"/><text x="707" y="65" font-size="12" fill="#1f2937">OOM Events</text>',
    '<line x1="80" y1="335" x2="770" y2="335" stroke="#374151" stroke-width="1.5"/>',
    '<line x1="80" y1="80" x2="80" y2="335" stroke="#374151" stroke-width="1.5"/>',
    '<text x="25" y="210" text-anchor="middle" font-size="13" fill="#374151" transform="rotate(-90 25,210)">Percentage of Category Events (%)</text>'
]
for idx, (label, sv, ov) in enumerate(zip(metrics, ssh_m, oom_m)):
    cx = 195 + idx * 220
    sh = (sv / max_m) * 230
    oh = (ov / max_m) * 230
    svg3.append(f'<rect x="{cx-48}" y="{335-sh:.1f}" width="42" height="{sh:.1f}" fill="#2563eb" rx="2"/>')
    svg3.append(f'<text x="{cx-27}" y="{329-sh:.1f}" text-anchor="middle" font-size="11" font-weight="bold" fill="#1e3a8a">{sv:.2f}%</text>')
    svg3.append(f'<rect x="{cx+6}" y="{335-oh:.1f}" width="42" height="{oh:.1f}" fill="#dc2626" rx="2"/>')
    svg3.append(f'<text x="{cx+27}" y="{329-oh:.1f}" text-anchor="middle" font-size="11" font-weight="bold" fill="#7f1d1d">{ov:.2f}%</text>')
    svg3.append(f'<text x="{cx}" y="358" text-anchor="middle" font-size="12" font-weight="bold" fill="#374151">{label}</text>')
svg3.append('</svg>')
with open("fig3_ssh_vs_oom_concentration.svg", "w", encoding="utf-8") as f:
    f.write("\n".join(svg3))

print("\n[完成] 已同步輸出 rq2_results.txt 以及 3 張圖表 (fig1_ssh_hourly.svg, fig2_oom_processes.svg, fig3_ssh_vs_oom_concentration.svg)")