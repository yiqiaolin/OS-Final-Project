# Linux System Log Analyzer：CSV 資料說明

> **文件目的**：說明本專案產生／整理的十份 CSV 檔案，讓沒有參與程式開發的組員也能理解每份資料的用途、欄位意義、資料格式與閱讀方式。 

---

## 目錄

1. [整體概覽](#1-整體概覽)
2. [先理解幾個共通概念](#2-先理解幾個共通概念)
3. [parsed_logs.csv：解析後的完整日誌](#3-parsed_logscsv解析後的完整日誌)
4. [process_frequency.csv：程序出現次數統計](#4-process_frequencycsv程序出現次數統計)
5. [event_frequency.csv：事件類型次數統計](#5-event_frequencycsv事件類型次數統計)
6. [template_frequency.csv：訊息模板出現次數統計](#6-template_frequencycsv訊息模板出現次數統計)
7. [hourly_frequency.csv：每小時日誌數量](#7-hourly_frequencycsv每小時日誌數量)
8. [daily_frequency.csv：每日日誌數量](#8-daily_frequencycsv每日日誌數量)
9. [keyword_frequency.csv：關鍵字出現次數統計](#9-keyword_frequencycsv關鍵字出現次數統計)
10. [anomaly_windows.csv：符合條件的異常候選時間區段](#10-anomaly_windowscsv符合條件的異常候選時間區段)
11. [unparsed_logs.csv：未成功解析的原始日誌](#11-unparsed_logscsv未成功解析的原始日誌)
12. [invalid_utf8_logs.csv：含有無效 UTF-8 位元組的日誌](#12-invalid_utf8_logscsv含有無效-utf-8-位元組的日誌)
13. [十份 CSV 之間的關係](#13-十份-csv-之間的關係)
14. [閱讀與使用時的注意事項](#14-閱讀與使用時的注意事項)

---

## 1. 整體概覽

本次實際核對的資料夾包含十份 CSV。它們不是十份完全獨立的原始資料，而是從 Linux 系統日誌整理出的不同形式資料：

- 有些檔案保留**每一筆日誌的詳細內容**，例如 `parsed_logs.csv`。
- 有些檔案將資料依照程序、事件或訊息模板**分組計數**，例如 `process_frequency.csv`。
- 有些檔案將日誌依照日期或小時**整理成時間統計**，例如 `daily_frequency.csv`。
- 有些檔案保留**未能正常處理的資料**，例如 `unparsed_logs.csv` 和 `invalid_utf8_logs.csv`。
- `anomaly_windows.csv` 則整理符合程式設定門檻的分鐘區段。

### 1.1 實際檔案清單

下表的「資料筆數」不包含 CSV 第一列的欄位標題。

| 檔案 | 實際資料筆數 | 實際欄位數 | 主要用途 |
|---|---:|---:|---|
| `parsed_logs.csv` | 25,549 | 8 | 保存成功解析後的日誌紀錄 |
| `process_frequency.csv` | 72 | 2 | 統計各程序出現次數 |
| `event_frequency.csv` | 13 | 2 | 統計各事件類型出現次數 |
| `template_frequency.csv` | 1,148 | 3 | 統計各程序的訊息模板出現次數 |
| `hourly_frequency.csv` | 1,124 | 2 | 統計每個小時的日誌數量 |
| `daily_frequency.csv` | 263 | 2 | 統計每天的日誌數量 |
| `keyword_frequency.csv` | 12 | 2 | 統計指定關鍵字出現次數 |
| `anomaly_windows.csv` | 14 | 5 | 保存符合門檻的分鐘區段 |
| `unparsed_logs.csv` | 18 | 2 | 保存未成功解析的原始日誌 |
| `invalid_utf8_logs.csv` | 20 | 6 | 保存含無效 UTF-8 位元組的日誌資訊 |

### 1.2 這些筆數代表什麼？

`parsed_logs.csv` 有 25,549 筆，`unparsed_logs.csv` 有 18 筆，兩者相加為 25,567 筆。這與原始 Linux 日誌的總行數相符。

但要注意，`invalid_utf8_logs.csv` 是另一份針對無效編碼內容整理的資料，**不能直接把它的 20 筆再加到 25,567 筆上**。它可能是在原始日誌中另外挑出的特定紀錄，不代表額外新增了 20 行原始日誌。

---

## 2. 先理解幾個共通概念

### 2.1 Log（日誌）

Log 是系統或服務在運作時留下的文字紀錄。每一筆紀錄通常描述某個時間點發生的事情，例如：

- 某個程序啟動。
- 使用者登入或登入失敗。
- 系統核心（Kernel）記錄記憶體相關訊息。
- FTP 或 SSH 服務收到連線。
- 某項服務發生錯誤。

日誌的原始內容通常是一整行文字。程式會嘗試從文字中辨識時間、主機、程序與訊息內容。

### 2.2 Process（程序）

Process 指正在執行的程式或服務。日誌中的程序名稱可以幫助我們知道是哪個系統元件留下紀錄。

例如：

- `kernel`：Linux 核心相關訊息。
- `sshd`：SSH 遠端登入服務。
- `ftpd`：FTP 服務。
- `cron`：排程工作相關程序。

注意：CSV 中的 `process` 是日誌解析程式擷取出的程序欄位，不等同於完整的作業系統程序資訊。

### 2.3 PID（Process ID，程序識別碼）

PID 是作業系統用來識別程序的數字。同一個程序在執行期間會有自己的 PID。

例如 `sshd[1234]` 中的 `1234` 就是 PID。

並不是每一筆日誌都有 PID，因此空白不一定代表資料錯誤。

### 2.4 Event（事件類型）

Event 是程式依照程序名稱與訊息內容，將日誌歸類後得到的事件名稱。

例如，程序是 `sshd`，訊息包含 `failed password` 時，程式會將它歸類為 `SSH Failed Password`。

這是程式依規則做出的分類，不是原始日誌本來就一定具有的欄位。

### 2.5 Template（訊息模板）

同一類事件可能在不同時間、不同使用者或不同 IP 發生，因此原始訊息會有一些變動。

例如：

```text
Failed password for root from 192.168.1.10
Failed password for root from 192.168.1.20
```

如果直接比較完整文字，這兩行會被視為不同訊息。但它們的結構其實相似。

程式會將部分動態資訊替換成占位符，形成訊息模板，例如：

```text
Failed password for root from <IP>
```

因此，Template 讓我們可以把「內容略有差異、但結構相似」的日誌歸在一起統計。

### 2.6 Count（次數）

`count` 通常代表某個項目在資料中出現的次數。

例如：

| process | count |
|---|---:|
| kernel | 13670 |

代表在這份程序統計資料中，`kernel` 被計算到 13,670 次。

`count` 是數量，不是百分比，也不是錯誤嚴重程度。

---

## 3. parsed_logs.csv：解析後的完整日誌

<small>定位：主要的結構化日誌資料。</small>

### 3.1 這份檔案的用途

`parsed_logs.csv` 保存成功通過日誌格式解析的紀錄。它將原本一整行的文字拆成多個欄位，讓後續程式可以依照時間、程序、事件或訊息內容進行整理。

這份檔案有 **25,549 筆資料、8 個欄位**，是十份 CSV 中最適合用來查看單筆日誌細節的資料。

### 3.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `line_number` | 原始行號 | 這筆紀錄在原始 Linux 日誌中的行號 |
| `timestamp` | 時間戳記 | 日誌中的月份、日期與時間 |
| `host` | 主機名稱 | 留下這筆日誌的主機名稱 |
| `process` | 程序名稱 | 留下這筆日誌的程序或服務名稱 |
| `pid` | 程序識別碼 | 程序的 PID；沒有 PID 時為空白 |
| `event` | 事件類型 | 程式根據程序與訊息內容分類出的事件 |
| `template` | 訊息模板 | 將訊息中的部分動態值替換後的標準化文字 |
| `message` | 原始訊息內容 | 從原始日誌中擷取出的訊息文字 |

### 3.3 實際資料範例

以下是實際檔案開頭的紀錄（以 Markdown 表格呈現）：

| line_number | timestamp | host | process | pid | event | template | message |
|---:|---|---|---|---|---|---|---|
| 1 | Jun 09 06:06:20 | combo | syslogd 1.4.1 | 空白 | Other System Activity | restart. | restart. |
| 2 | Jun 09 06:06:20 | combo | syslog | 空白 | Other System Activity | syslogd startup succeeded | syslogd startup succeeded |
| 3 | Jun 09 06:06:20 | combo | syslog | 空白 | Other System Activity | klogd startup succeeded | klogd startup succeeded |

### 3.4 欄位補充說明

**`line_number`**

這個欄位很重要，因為它保留了紀錄在原始檔案中的位置。若要回頭查看原始日誌，可以利用行號定位。

**`timestamp`**

實際格式例如：

```text
Jun 09 06:06:20
```

格式為：

```text
月份 日期 時:分:秒
```

目前資料沒有在這個欄位中包含年份，因此不能只靠這個欄位還原完整日期時間。

**`host`**

本次資料中可以看到 `combo` 這個主機名稱。它代表日誌中記錄的主機欄位。

**`process`**

這個欄位會保留程式解析出的程序文字。不同日誌格式可能讓程序名稱呈現方式不同，例如 `sshd(pam_unix)` 或 `kernel`。

**`pid`**

實際資料中有 **14,507 筆 PID 空白**。這表示這些紀錄沒有提供可由目前解析規則擷取的 PID。閱讀時不要把空白直接當成錯誤。

**`event`**

這是分類後的結果，例如 `Other System Activity`、`Kernel Activity`、`SSH Authentication Failure`。分類名稱由程式規則決定。

**`template` 與 `message`**

兩者差異如下：

- `message`：保留擷取出的訊息原文。
- `template`：將部分動態資訊正規化後的訊息格式。

實際資料中，`template` 和 `message` 各有 **93 筆空白**。這些紀錄仍然存在於 `parsed_logs.csv`，只是訊息欄位沒有內容。

### 3.5 什麼時候使用？

- 想查看某一筆日誌的完整欄位。
- 想知道某事件發生的時間、程序與訊息。
- 想透過 `line_number` 回到原始日誌。
- 想以 `event`、`process` 或 `template` 篩選紀錄。

---

## 4. process_frequency.csv：程序出現次數統計

<small>定位：依程序名稱彙整的次數表。</small>

### 4.1 這份檔案的用途

這份檔案統計每一種程序在成功解析的日誌中出現幾次。

實際有 **72 筆資料、2 個欄位**。

它不保留每筆日誌的時間與訊息細節，而是將相同程序的紀錄合併計數。

### 4.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `process` | 程序名稱 | 日誌中擷取出的程序名稱 |
| `count` | 出現次數 | 該程序在成功解析紀錄中出現的次數 |

### 4.3 實際資料範例

| process | count |
|---|---:|
| kernel | 13670 |
| sshd(pam_unix) | 4996 |
| ftpd | 3453 |

例如第一列表示，程序名稱為 `kernel` 的紀錄共有 13,670 筆。

### 4.4 如何理解？

假設 `process_frequency.csv` 中有：

```csv
process,count
kernel,13670
ftpd,3453
```

代表程式將所有成功解析的日誌依照 `process` 分組，再計算每組有幾筆。

這份資料適合用來快速了解哪些程序在日誌中出現得比較頻繁。

### 4.5 什麼時候使用？

- 比較不同程序的日誌數量。
- 找出出現次數較多的程序。
- 製作程序出現次數的長條圖。

---

## 5. event_frequency.csv：事件類型次數統計

<small>定位：依程式分類結果彙整的次數表。</small>

### 5.1 這份檔案的用途

這份檔案統計每一種 `event` 分類出現幾次。

實際有 **13 筆資料、2 個欄位**。

與 `process_frequency.csv` 不同，這份檔案不是依照程序名稱分組，而是依照程式判定的事件類型分組。

### 5.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `event` | 事件類型 | 程式依照程序與訊息內容分類後的名稱 |
| `count` | 出現次數 | 該事件類型出現的紀錄數量 |

### 5.3 實際資料範例

| event | count |
|---|---:|
| Kernel Activity | 13654 |
| SSH Authentication Failure | 3934 |
| FTP Activity | 3453 |

例如：

- `Kernel Activity`：被程式分類為一般 Kernel 活動的紀錄，共 13,654 筆。
- `SSH Authentication Failure`：被程式分類為 SSH 驗證失敗的紀錄，共 3,934 筆。
- `FTP Activity`：被程式分類為 FTP 活動的紀錄，共 3,453 筆。

### 5.4 Event 是如何產生的？

目前可取得的分析程式會依照 `process` 與 `message` 的內容執行規則分類。例如：

- 程序包含 `sshd`，且訊息包含 `failed password`，會分類為 `SSH Failed Password`。
- 程序為 `kernel`，且訊息包含 `error`、`failed`、`warning`、`oops` 或 `panic` 等字詞，會分類為 `Kernel Error/Warning`。
- 程序包含 `ftpd` 或 `vsftpd`，會分類為 `FTP Activity`。
- 其他未符合前述規則的紀錄，會依照程式中的預設規則歸入其他類別。

因此，`event` 是程式分類的結果，不是原始日誌的固定欄位。

### 5.5 什麼時候使用？

- 比較不同事件類型的出現次數。
- 查看程式分類後，各類事件的數量分布。
- 製作事件類型的長條圖或圓餅圖。

---

## 6. template_frequency.csv：訊息模板出現次數統計

<small>定位：依程序與標準化訊息模板彙整的次數表。</small>

### 6.1 這份檔案的用途

這份檔案統計每個程序產生的各種訊息模板出現幾次。

實際有 **1,148 筆資料、3 個欄位**。

它比 `process_frequency.csv` 更細：不只知道是哪個程序，也能知道該程序最常出現哪些訊息格式。

### 6.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `process` | 程序名稱 | 產生該訊息的程序 |
| `template` | 訊息模板 | 將部分動態資訊替換後的標準化訊息 |
| `count` | 出現次數 | 該程序與訊息模板組合出現的次數 |

### 6.3 實際資料範例

| process | template | count |
|---|---|---:|
| kernel | Out of Memory: Killed process `<NUM>` (httpd). | 8903 |
| sshd(pam_unix) | authentication failure; logname= uid=`<NUM>` euid=`<NUM>` tty=NODEVssh ruser= rhost=`<IP>` user=root | 1597 |
| kernel | Out of Memory: Killed process `<NUM>` (python). | 1153 |

第一列表示：

- 程序是 `kernel`。
- 訊息模板是 `Out of Memory: Killed process <NUM> (httpd).`
- 這個程序與模板的組合共出現 8,903 次。

### 6.4 為什麼需要 Template？

假設原始日誌有以下兩筆：

```text
authentication failure from 192.168.1.10
authentication failure from 192.168.1.20
```

如果直接使用原始訊息，兩筆文字會因為 IP 不同而不完全相同。

經過正規化後，可能得到：

```text
authentication failure from <IP>
```

這樣就能把結構相同的訊息合併統計。

目前程式的正規化規則會處理部分常見動態值，例如：

- IPv4 位址 → `<IP>`
- UUID → `<UUID>`
- 十六進位數值 → `<HEX>`
- 部分使用者名稱 → `<USER>`
- 獨立數字 → `<NUM>`

注意：這些替換是程式依照特定規則執行的，不代表所有可能的動態內容都一定會被辨識。

### 6.5 實際資料中的空白

本次檔案有 **2 筆 `template` 空白**，分別對應：

| process | template | count |
|---|---|---:|
| kernel | 空白 | 89 |
| squid | 空白 | 4 |

因此，使用這份檔案時要留意空白模板的存在，不要直接將它當成一般文字模板解讀。

### 6.6 什麼時候使用？

- 找出某個程序最常出現的訊息格式。
- 比較不同訊息模板的出現次數。
- 尋找重複發生的訊息模式。
- 製作 Top N 訊息模板統計圖表。

---

## 7. hourly_frequency.csv：每小時日誌數量

<small>定位：依日期與小時統計日誌筆數。</small>

### 7.1 這份檔案的用途

這份檔案將成功解析的日誌依照「日期＋小時」分組，計算每個小時共有幾筆日誌。

實際有 **1,124 筆資料、2 個欄位**。

### 7.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `hour` | 日期與小時 | 格式為 `MM-DD HH:00` |
| `count` | 日誌數量 | 該日期該小時內的日誌筆數 |

### 7.3 實際資料範例

| hour | count |
|---|---:|
| 01-01 04:00 | 8 |
| 01-02 04:00 | 5 |
| 01-03 04:00 | 5 |

例如 `01-01 04:00` 代表 1 月 1 日凌晨 4 點這個小時區間，統計到 8 筆日誌。

### 7.4 時間格式要注意什麼？

`hour` 的格式是：

```text
MM-DD HH:00
```

例如：

```text
06-13 11:00
```

代表 6 月 13 日 11:00 至 11:59 這個小時區間。

這個欄位沒有年份，也沒有分鐘與秒數。它是小時統計標籤，不是單筆事件的精確時間。

### 7.5 什麼時候使用？

- 觀察不同日期與小時的日誌數量。
- 製作時間序列圖。
- 查看某些時段的日誌數量是否較多。

---

## 8. daily_frequency.csv：每日日誌數量

<small>定位：依日期統計日誌筆數。</small>

### 8.1 這份檔案的用途

這份檔案將成功解析的日誌依照日期分組，計算每天共有幾筆日誌。

實際有 **263 筆資料、2 個欄位**。

與 `hourly_frequency.csv` 相比，這份資料不區分一天中的小時，只保留日期總量。

### 8.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `day` | 日期 | 格式為 `MM-DD` |
| `count` | 日誌數量 | 該日期內的日誌筆數 |

### 8.3 實際資料範例

| day | count |
|---|---:|
| 01-01 | 8 |
| 01-02 | 5 |
| 01-03 | 5 |

例如 `01-01` 的 `count` 為 8，表示 1 月 1 日共有 8 筆成功解析的日誌。

### 8.4 與 hourly_frequency.csv 的差異

| 比較項目 | daily_frequency.csv | hourly_frequency.csv |
|---|---|---|
| 統計單位 | 每天 | 每個日期中的每小時 |
| 時間欄位 | `day` | `hour` |
| 時間精細程度 | 較粗 | 較細 |
| 主要用途 | 比較每日總量 | 觀察小時層級變化 |

### 8.5 什麼時候使用？

- 比較不同日期的日誌總量。
- 製作每日數量折線圖。
- 觀察日誌數量隨日期的變化。

---

## 9. keyword_frequency.csv：關鍵字出現次數統計

<small>定位：依預先指定的關鍵字統計訊息內容。</small>

### 9.1 這份檔案的用途

這份檔案統計程式預先設定的關鍵字，在成功解析日誌的 `message` 欄位中出現的次數。

實際有 **12 筆資料、2 個欄位**。

### 9.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `keyword` | 關鍵字 | 程式預先設定要搜尋的文字 |
| `count` | 出現次數 | 該關鍵字在訊息中被計數的次數 |

### 9.3 程式設定的 12 個關鍵字

目前可取得的程式碼中，關鍵字清單如下：

| keyword | 中文意思 |
|---|---|
| `error` | 錯誤 |
| `failed` | 失敗 |
| `failure` | 失敗／故障 |
| `warning` | 警告 |
| `alert` | 警示 |
| `authentication` | 身分驗證 |
| `password` | 密碼 |
| `session` | 工作階段 |
| `timeout` | 逾時 |
| `denied` | 拒絕 |
| `refused` | 拒絕／拒收 |
| `invalid` | 無效 |

### 9.4 實際資料範例

| keyword | count |
|---|---:|
| error | 21 |
| failed | 116 |
| failure | 4044 |

例如 `failure` 的 `count` 為 4,044，代表程式在訊息文字中計數到 4,044 次 `failure` 關鍵字符合結果。

### 9.5 計數方式與限制

程式會先將訊息轉成小寫，再逐一檢查每個關鍵字是否存在於訊息中。

因此：

- `ERROR` 與 `error` 不會因大小寫不同而被區分。
- 這裡統計的是關鍵字在訊息中被找到的次數。
- 同一筆訊息可能同時包含多個關鍵字，因此各關鍵字的 `count` 不應直接相加後視為日誌總筆數。
- 這個統計不代表每一筆包含該字的日誌都是真正的系統故障。

### 9.6 什麼時候使用？

- 查看指定關鍵字在日誌訊息中的出現次數。
- 比較不同關鍵字的數量。
- 製作關鍵字次數長條圖。

---

## 10. anomaly_windows.csv：符合條件的異常候選時間區段

<small>定位：保存每分鐘指定事件數量達到門檻的時間區段。</small>

### 10.1 這份檔案的用途

這份檔案保存程式依照特定條件挑選出的分鐘區段。

實際有 **14 筆資料、5 個欄位**。

程式不是將所有日誌都放進這份檔案，而是先挑選指定的事件類型，再依照分鐘分組，最後只保留事件數量達到門檻的分鐘。

### 10.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `minute` | 分鐘區段 | 格式為 `MM-DD HH:MM` |
| `failure_event_count` | 指定事件數量 | 該分鐘內被納入統計的指定事件總數 |
| `event_breakdown` | 事件類型明細 | 列出該分鐘各事件類型的數量 |
| `first_line` | 第一筆原始行號 | 該分鐘區段中第一筆符合條件事件的原始行號 |
| `last_line` | 最後一筆原始行號 | 該分鐘區段中最後一筆符合條件事件的原始行號 |

### 10.3 實際資料範例

| minute | failure_event_count | event_breakdown | first_line | last_line |
|---|---:|---|---:|---:|
| 02-05 18:17 | 20 | SSH Authentication Failure: 20 | 24459 | 24478 |
| 02-15 14:10 | 21 | SSH Authentication Failure: 21 | 24958 | 24978 |
| 06-11 09:46 | 20 | SSH Authentication Failure: 20 | 710 | 729 |

例如第一筆資料表示：

- 時間區段是 2 月 5 日 18:17 這一分鐘。
- 該分鐘共有 20 筆被納入統計的事件。
- 這 20 筆都被分類為 `SSH Authentication Failure`。
- 這些事件在原始檔案中的行號範圍是 24459 至 24478。

### 10.4 程式如何挑選資料？

目前可取得的程式碼設定：

```python
ANOMALY_THRESHOLD = 20
ANOMALY_WINDOW_SECONDS = 60
```

程式會納入以下事件類型：

- `SSH Failed Password`
- `SSH Authentication Failure`
- `Kernel Error/Warning`
- `Authentication Failure`
- `Other Error/Failure`

接著以月份、日期、時與分鐘組成分組標籤，統計每分鐘的指定事件數量。若該分鐘的數量 **大於或等於 20**，就輸出到 `anomaly_windows.csv`。

### 10.5 重要限制

這份檔案的名稱雖然是 `anomaly_windows`，但它代表的是**符合程式設定門檻的候選時間區段**，不是已經證實的系統故障。

此外：

- `minute` 沒有年份。
- 目前程式將時間分組到分鐘。
- 門檻 20 是程式設定的啟發式條件。
- `event_breakdown` 是事件類型數量摘要，不是完整日誌內容。
- 若要查看實際事件，應利用 `first_line`、`last_line` 回到原始日誌，或在 `parsed_logs.csv` 中依行號查找。

### 10.6 什麼時候使用？

- 查看哪些分鐘區段達到程式設定的事件數量門檻。
- 查看該分鐘包含哪些被納入統計的事件類型。
- 透過原始行號回查詳細日誌。

---

## 11. unparsed_logs.csv：未成功解析的原始日誌

<small>定位：保留不符合目前解析格式的原始資料。</small>

### 11.1 這份檔案的用途

並非所有原始日誌都能符合程式設定的格式規則。

當某一行無法被 `parse_log()` 成功解析時，程式會將它的原始行號與原始文字保存到這份 CSV。

實際有 **18 筆資料、2 個欄位**。

### 11.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `line_number` | 原始行號 | 該行在原始 Linux 日誌中的位置 |
| `raw` | 原始內容 | 未成功解析的原始日誌文字 |

### 11.3 實際資料範例

| line_number | raw |
|---:|---|
| 5836 | Sep 28 09:08:56 combo last message repeated 2 times |
| 5891 | Sep 28 09:09:19 combo exiting on signal 15 |
| 7412 | Oct 25 10:06:52 combo last message repeated 14 times |

### 11.4 為什麼會有未解析資料？

目前的解析程式使用固定的正規表示式，預期日誌具有月份、日期、時間、主機、程序與訊息等結構。

如果某一行的格式不符合這個規則，`parse_log()` 就會回傳 `None`，該行因此被保存到 `unparsed_logs.csv`。

例如：

```text
Sep 28 09:08:56 combo last message repeated 2 times
```

這一行沒有符合目前解析程式預期的完整程序欄位格式，因此被保留在未解析資料中。

### 11.5 什麼時候使用？

- 檢查哪些原始日誌沒有成功解析。
- 了解解析程式目前無法處理的格式。
- 透過 `line_number` 回到原始日誌查看上下文。

---

## 12. invalid_utf8_logs.csv：含有無效 UTF-8 位元組的日誌

<small>定位：保存含有無效 UTF-8 位元組的日誌及其相關資訊。</small>

### 12.1 這份檔案的用途

這份檔案整理出含有無效 UTF-8 位元組的日誌紀錄。

實際有 **20 筆資料、6 個欄位**。

它與 `unparsed_logs.csv` 不同：

- `unparsed_logs.csv` 的判斷依據是日誌是否符合目前的文字解析格式。
- `invalid_utf8_logs.csv` 的欄位則明確記錄無效位元組相關資訊。

**目前可取得的 `Linux System Log Analyzer` 程式碼沒有包含產生 `invalid_utf8_logs.csv` 的程式段落。** 因此以下欄位說明以實際 CSV 的欄位名稱與內容為準，不推測其完整產生流程。

### 12.2 實際欄位

| 欄位名稱 | 中文名稱 | 說明 |
|---|---|---|
| `line_number` | 原始行號 | 該紀錄在原始日誌中的位置 |
| `timestamp` | 時間戳記 | 日誌紀錄中的月份、日期與時間 |
| `process` | 程序名稱 | 日誌中記錄的程序名稱 |
| `message` | 訊息內容 | 日誌中的訊息文字；可能包含無效位元組的轉義表示 |
| `invalid_bytes` | 無效位元組 | 被記錄下來的無效位元組內容 |
| `invalid_byte_count` | 無效位元組數量 | 該筆紀錄記錄的無效位元組數量 |

### 12.3 實際資料範例

第一筆資料的主要欄位如下：

| 欄位 | 實際值 |
|---|---|
| `line_number` | 868 |
| `timestamp` | Jun 13 11:55:04 |
| `process` | rpc.statd[1636] |
| `invalid_bytes` | `\xf7 \xff \xbf \xf7 \xff \xbf \xf7 \xff \xbf \xf7 \xff \xbf` |
| `invalid_byte_count` | 12 |

`message` 欄位保留了較長的訊息文字，包含上述位元組的轉義表示，以及其他可見字元。

### 12.4 如何理解 invalid_bytes？

UTF-8 是常見的文字編碼方式。程式讀取文字檔時，如果某些位元組序列不符合 UTF-8 編碼規則，就可能被視為無效編碼內容。

這份 CSV 將相關位元組以類似下列形式呈現：

```text
\xf7
\xff
\xbf
```

這些是位元組的十六進位轉義表示，不是一般的英文單字。

### 12.5 實際資料觀察

本次提供的檔案有 20 筆資料，且這 20 筆的 `invalid_byte_count` 都是 12。

這只代表目前這份 CSV 的實際內容如此，不應推論所有無效 UTF-8 日誌都一定有 12 個無效位元組。

### 12.6 什麼時候使用？

- 查看哪些日誌含有無效 UTF-8 位元組。
- 檢查無效位元組的表示內容。
- 透過原始行號回查日誌。
- 區分文字編碼問題與一般格式解析問題。

---

## 13. 十份 CSV 之間的關係

十份 CSV 可以依照資料用途分成四個部分。

### 13.1 詳細紀錄

`parsed_logs.csv` 保存成功解析後的逐筆日誌，是多數統計資料的重要來源。

### 13.2 分組統計

以下五份檔案將成功解析的日誌依照不同欄位分組計數：

| 檔案 | 分組依據 | 統計內容 |
|---|---|---|
| `process_frequency.csv` | `process` | 各程序出現次數 |
| `event_frequency.csv` | `event` | 各事件類型出現次數 |
| `template_frequency.csv` | `process` + `template` | 各程序的訊息模板出現次數 |
| `hourly_frequency.csv` | 日期 + 小時 | 每小時日誌數量 |
| `daily_frequency.csv` | 日期 | 每日日誌數量 |
| `keyword_frequency.csv` | 預先指定的關鍵字 | 各關鍵字被找到的次數 |

### 13.3 特定條件整理

`anomaly_windows.csv` 從成功解析的紀錄中，挑選指定事件類型並依分鐘統計，只輸出達到門檻的區段。

### 13.4 資料品質與特殊內容

| 檔案 | 保存內容 |
|---|---|
| `unparsed_logs.csv` | 未符合目前解析格式的原始日誌 |
| `invalid_utf8_logs.csv` | 含無效 UTF-8 位元組的日誌資訊 |

### 13.5 簡化資料流程圖

```text
                 原始 Linux 日誌
                        |
                        v
                 逐行讀取與解析
                        |
             +----------+----------+
             |                     |
             v                     v
        成功解析                未成功解析
             |                     |
             v                     v
      parsed_logs.csv       unparsed_logs.csv
             |
             +-----------------------------+
             |             |               |
             v             v               v
        程序統計        事件統計         模板統計
             |             |               |
             v             v               v
    process_frequency  event_frequency  template_frequency
             |
             +-----------------------------+
             |             |               |
             v             v               v
         每日統計       每小時統計       關鍵字統計
             |             |               |
             v             v               v
     daily_frequency  hourly_frequency  keyword_frequency

             指定事件與分鐘門檻
                        |
                        v
               anomaly_windows.csv

       無效 UTF-8 位元組相關資料
                        |
                        v
              invalid_utf8_logs.csv
```

> 注意：上圖是依照目前可取得的程式碼與實際 CSV 欄位整理的概念關係圖。`invalid_utf8_logs.csv` 的完整產生流程目前沒有對應程式碼可供核對，因此只標示其資料用途，不將它強行接入主解析流程。

---

## 14. 閱讀與使用時的注意事項

### 14.1 空白欄位不一定代表錯誤

例如：

- `parsed_logs.csv` 的 `pid` 有大量空白，因為不是每筆日誌都有 PID。
- `parsed_logs.csv` 的 `message` 與 `template` 各有 93 筆空白。
- `template_frequency.csv` 有 2 筆空白模板。

使用資料時應先確認空白的意義，不要直接刪除或當成零。

### 14.2 時間欄位沒有年份

目前 `timestamp`、`day`、`hour` 與 `minute` 都沒有完整年份資訊。

例如：

```text
Jun 13 11:55:04
06-13
06-13 11:00
06-13 11:55
```

這些欄位可以用來辨識月、日與時間，但不能單獨還原完整的年月日。

### 14.3 Event 是規則分類，不是原始標籤

`event_frequency.csv` 與 `parsed_logs.csv` 的 `event` 欄位，是分析程式根據程序名稱與訊息文字分類出的結果。

理解事件名稱時，應搭配分類規則與原始 `message` 一起閱讀。

### 14.4 Template 不等於原始訊息

`template` 會把部分動態資訊替換成占位符；若要查看實際訊息內容，應使用 `message`。

### 14.5 Anomaly 不代表已確認故障

`anomaly_windows.csv` 只表示指定事件在某分鐘內達到程式設定的數量門檻。它是候選區段，不應直接描述為已確認的系統故障。

### 14.6 Unparsed 與 Invalid UTF-8 不要混為一談

兩份檔案處理的概念不同：

- `unparsed_logs.csv`：未符合目前程式的日誌格式解析規則。
- `invalid_utf8_logs.csv`：記錄無效 UTF-8 位元組相關資訊。

一筆日誌是否符合文字格式，與它是否含有無效編碼，是不同層面的問題。

### 14.7 程式碼與實際檔案的核對界線

目前取得的 `Linux System Log Analyzer` 程式碼可確認 `parsed_logs.csv`、各項頻率統計、`anomaly_windows.csv` 與 `unparsed_logs.csv` 的輸出欄位及主要產生邏輯。

但目前程式碼中沒有 `invalid_utf8_logs.csv` 的輸出段落。因此，本文件對該檔案僅依實際 CSV 欄位與資料內容說明，不推測其產生程式或完整處理步驟。

---

## 結語

這十份 CSV 分別從逐筆日誌、程序統計、事件分類、訊息模板、時間分布、關鍵字、候選異常區段與資料品質等角度，整理 Linux 系統日誌。

初次閱讀時，建議先看 `parsed_logs.csv`，理解一筆日誌被拆成哪些欄位；再看 `process_frequency.csv`、`event_frequency.csv` 與 `template_frequency.csv`，理解如何將逐筆資料彙整成統計；最後閱讀時間統計與特殊資料檔案。

只要先掌握每份 CSV 的欄位、統計單位與資料限制，就能正確理解這十份資料各自保存了什麼資訊，以及它們之間的關係。
