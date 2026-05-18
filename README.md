# ANUBIS >

**Author:** ZetaOrioniss\
**Version:** 1.0

**ANUBIS** is an interactive Python console for web directory enumeration during CTF sessions and authorized penetration tests. Configure once, run instantly — with automatic recursive pivoting, real-time progress, and structured result saving. No external dependencies, pure stdlib.


![screenshot](https://github.com/ZetaOrioniss/Anubis/blob/main/assets/example.png)

---

## 1. Why ANUBIS?

Directory enumeration is a core step of every web pentest and CTF. Existing tools are powerful but often require installation, configuration files, or offer no interactive workflow. Anubis fixes that:

* **Metasploit-style console** — set your options, run, get results. Full `Tab` auto-completion on every command and key.
* **Automatic recursive pivoting** — when a directory hit is found, Anubis automatically scans inside it, up to a configurable depth. No manual re-runs needed.
* **Thread-optimized engine** — a tunable worker pool with per-thread delay and timeout controls lets you go fast without hammering the server or your machine.
* **Real-time progress bar** — request rate, ETA, hit count, and current URL all inline, no terminal spam.
* **Persistent results** — every scan saves a `.json` and a `.txt` file automatically, named after the target and timestamp.
* **Zero dependencies** — pure Python 3 stdlib. Works on any machine with Python 3.10+.

---

## 2. Installation & Dependencies

### Prerequisites

Python 3.10 or later — no external libraries required.

### Installation

```bash
git clone https://github.com/ZetaOrioniss/anubis.git
cd Anubis
chmod +x Anubis.py
```

### Launch

```bash
./Anubis.py
```

### Recommended wordlists (not included)

```bash
# Kali / Debian
sudo apt install seclists dirb

# Common paths
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/dirb/wordlists/common.txt
```

---

## 3. Usage Guide 🖥️

### Prompt

```
Anubis ● (10.10.11.25) >     ← scan running
Anubis ○ (-) >               ← idle
```

The `●` / `○` indicator updates live. The target hostname is shown in the prompt at all times.

---

## 4. Command Reference

### ⚙️ Configuration

| Command | Description |
|---|---|
| `set target <url>` | Base URL to enumerate (http:// added automatically if missing) |
| `set wordlist <path>` | Path to wordlist — Tab completion navigates the filesystem |
| `set threads <n>` | Number of concurrent worker threads (default: **20**, max: 200) |
| `set timeout <s>` | Per-request timeout in seconds (default: **6**) |
| `set delay <s>` | Pause between requests per thread in seconds (default: **0**) |
| `set extensions <a,b,…>` | File extensions to probe alongside each word (e.g. `php,html,txt`) |
| `set status <codes>` | HTTP codes considered as hits (default: `200,204,301,302,307,308,401,403`) |
| `set recursive <true\|false>` | Auto-pivot into discovered directories (default: **true**) |
| `set depth <n>` | Maximum recursion depth (default: **3**, max: 10) |
| `set useragent <ua>` | Custom User-Agent string |
| `show options` | Display all current settings |

### 🚀 Running

| Command | Description |
|---|---|
| `run` / `start` | Start the scan in the background (non-blocking) |
| `wait` | Block the console until the current scan finishes |
| `stop` | Gracefully interrupt the running scan |
| `status` | Show whether a scan is currently active |

### 📊 Results

| Command | Description |
|---|---|
| `results` | Display the hit table from the most recent scan |
| `history` | List all saved result files in `~/.Anubis/results/` |

### 🔧 Other

| Command | Description |
|---|---|
| `clear` | Clear the screen |
| `help` | Show the full command reference |
| `exit` / `quit` | Exit (stops any running scan first) |

---

## 5. Workflow Examples

### Basic HTB / CTF scan

```
Anubis ○ (-) > set target http://10.10.11.25
  target => http://10.10.11.25

Anubis ○ (10.10.11.25) > set wordlist /usr/share/dirb/wordlists/common.txt
  wordlist => /usr/share/dirb/wordlists/common.txt  (4614 words)

Anubis ○ (10.10.11.25) > run
```

### Add file extensions

```
Anubis ○ (10.10.11.25) > set extensions php,html,txt
  extensions => php, html, txt

Anubis ○ (10.10.11.25) > run
```

Each word in the wordlist will probe `word`, `word.php`, `word.html`, and `word.txt`.

### Slow and stealthy — avoid WAF / rate limiting

```
Anubis ○ (10.10.11.25) > set threads 5
Anubis ○ (10.10.11.25) > set delay 0.2
Anubis ○ (10.10.11.25) > set timeout 10
Anubis ○ (10.10.11.25) > run
```

### Aggressive scan on a local lab

```
Anubis ○ (192.168.1.100) > set threads 80
Anubis ○ (192.168.1.100) > set delay 0
Anubis ○ (192.168.1.100) > set depth 5
Anubis ○ (192.168.1.100) > run
```

### Custom hit codes — include 500 for error-based discovery

```
Anubis ○ (10.10.11.25) > set status 200,204,301,302,307,401,403,500
Anubis ○ (10.10.11.25) > run
```

### Review results after a scan

```
Anubis ○ (10.10.11.25) > results

  ══════════════════════════════════════════════════════════════════════════════════
    RESULTS — 7 hits
  ══════════════════════════════════════════════════════════════════════════════════
  [200]      1842 B  http://10.10.11.25/index.php
  [301]       312 B  http://10.10.11.25/admin  -> http://10.10.11.25/admin/
  [200]      4201 B  http://10.10.11.25/admin/login.php
  [403]       279 B  http://10.10.11.25/admin/config
  [200]      2910 B  http://10.10.11.25/admin/dashboard.php
  [301]       312 B  http://10.10.11.25/uploads  -> http://10.10.11.25/uploads/
  [200]       891 B  http://10.10.11.25/uploads/shell.php
  ══════════════════════════════════════════════════════════════════════════════════
```

---

## 6. Recursive Pivoting

When `recursive` is enabled (default), Anubis automatically pivots into any directory-like hit:

- A hit is eligible for pivoting if its status is **2xx or 3xx** and the URL has **no file extension**.
- After completing a scan pass, all newly discovered directories are queued and scanned in turn, using the same wordlist.
- The `depth` setting limits how deep the recursion goes (default: 3).

```
  SCANNING  http://10.10.11.25         depth 0 — 4614 URLs
  [301] http://10.10.11.25/admin

  ↪ Pivoting into: http://10.10.11.25/admin
  SCANNING  http://10.10.11.25/admin   depth 1 — 4614 URLs
  [200] http://10.10.11.25/admin/login.php
  [403] http://10.10.11.25/admin/config

  ↪ Pivoting into: http://10.10.11.25/admin/config
  SCANNING  http://10.10.11.25/admin/config   depth 2 — 4614 URLs
  ...
```

To disable: `set recursive false`

---

## 7. Thread & Performance Model

Anubis uses a `queue.Queue` + daemon thread worker pool. All workers pull URLs from a shared queue — no thread gets starved, no URL is scanned twice.

| Setting | Effect |
|---|---|
| `threads` | Number of parallel HTTP workers. **20** is a safe default for remote targets. Go up to 80+ on local labs. |
| `delay` | Sleep added after each request inside a worker. Use `0.1`–`0.5` against rate-limited or fragile servers. |
| `timeout` | How long a worker waits before giving up on a request. Increase for slow VPN connections. |

Scans run **non-blocking** — the console stays responsive while scanning. Use `wait` to block, `stop` to abort.

---

## 8. Result Files

Every scan automatically writes two files to `~/.Anubis/results/`:

| Format | Content |
|---|---|
| `.txt` | Plain text, one hit per line, written in real time during the scan |
| `.json` | Structured data with status, size, redirect, and elapsed time per hit |

Files are named `<target>_<timestamp>` for easy identification:

```
~/.Anubis/results/
  http_10_10_11_25_20250518_143201.txt
  http_10_10_11_25_20250518_143201.json
  http_192_168_1_100_20250517_091422.txt
  http_192_168_1_100_20250517_091422.json
```

Use `history` to list all saved scans, and `results` to display the latest hit table.

---

## 9. Status Colour Reference

| Colour | Family | Meaning |
|---|---|---|
| 🟢 Green | 2xx | Success — content found |
| 🔵 Cyan | 3xx | Redirect — likely a directory |
| 🟡 Yellow | 4xx | Client error — often 401 (auth required) or 403 (forbidden but exists) |
| 🔴 Red | 5xx | Server error — useful for error-based discovery |

---

> ⚠️ **Disclaimer**: This tool is strictly intended for educational and professional use within the framework of authorized penetration testing. The author declines all responsibility for any illegal use.
