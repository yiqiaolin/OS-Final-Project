import csv

print("=== summary.txt 內容 ===")
with open("summary.txt", "r", encoding="utf-8", errors="ignore") as f:
    print(f.read())

for filename in ["parsed_logs.csv", "anomaly_windows.csv"]:
    print(f"\n=== {filename} 欄位與前 3 筆 ===")
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for i in range(4):
            row = next(reader, None)
            if row is not None:
                print(row)