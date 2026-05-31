
<div align="center">

```
   ▄████████ ███▄▄▄▄   ███    █▄  ▀█████████▄   ▄█     ▄████████ 
  ███    ███ ███▀▀▀██▄ ███    ███   ███    ███ ███    ███    ███ 
  ███    ███ ███   ███ ███    ███   ███    ███ ███▌   ███    █▀  
  ███    ███ ███   ███ ███    ███  ▄███▄▄▄██▀  ███▌   ███        
▀███████████ ███   ███ ███    ███ ▀▀███▀▀▀██▄  ███▌ ▀███████████ 
  ███    ███ ███   ███ ███    ███   ███    ██▄ ███           ███ 
  ███    ███ ███   ███ ███    ███   ███    ███ ███     ▄█    ███ 
  ███    █▀   ▀█   █▀  ████████▀  ▄█████████▀  █▀    ▄████████▀  
```

**Web directory enumeration console — CTF Edition**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square&logo=linux)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v1.1-cyan?style=flat-square)](https://github.com/youruser/anubis)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/youruser/anubis/pulls)

[Features](#-features) · [Why Anubis?](#-why-anubis) · [Install](#-installation) · [Usage](#-usage) · [Commands](#-commands) · [Recursive scanning](#-recursive-scanning) · [Results](#-results--export) · [FAQ](#-faq)

</div>

---

## What is Anubis?

**Anubis** is an interactive terminal console for web directory and file enumeration, built for penetration testers and CTF players. It combines the familiar `msfconsole`-style workflow with a real-time progress bar, automatic recursive pivoting, and clean result export — all in a single Python file with zero external dependencies.

Think `gobuster` or `feroxbuster`, but interactive: configure your scan in a persistent session, fire it off with `run`, and watch results stream in live while the progress bar tracks throughput and ETA.

![screenshot](https://github.com/ZetaOrioniss/Anubis/blob/main/assets/example.png)

```
Anubis ● (10.10.11.25) > run

  ────────────────────────────────────────────────────────────────────────────
  SCANNING  http://10.10.11.25
  4641 URLs  ·  20 threads  ·  timeout 6s  ·  delay 0s
  ────────────────────────────────────────────────────────────────────────────

  [200]  http://10.10.11.25/admin        128 B   42ms
  [301]  http://10.10.11.25/uploads  →  http://10.10.11.25/uploads/
  [403]  http://10.10.11.25/server-status    512 B   18ms
  ██████████████░░░░░░░░░░░░░░░░  46.2%  1841/4641  +3  312 r/s  ETA 9s

  ↪  Pivoting into:  http://10.10.11.25/uploads

  [200]  http://10.10.11.25/uploads/shell.php    1024 B   55ms
```

---

## ✨ Features

| | Feature | Detail |
|---|---|---|
| 🖥️ | **Interactive REPL console** | Persistent session — configure once, run multiple scans |
| ⚡ | **Multithreaded engine** | Up to 200 concurrent workers, configurable per scan |
| 📊 | **Real-time progress bar** | Live throughput, request rate (r/s), ETA, and current URL — all on one line |
| 🔀 | **Recursive auto-pivot** | Automatically dives into discovered directories up to a configurable depth |
| 🧩 | **Extension fuzzing** | Append any combination of extensions per word (`php`, `html`, `bak`, `txt`…) |
| 🎯 | **Custom status codes** | Define exactly which HTTP codes count as hits |
| ⏱️ | **Per-thread delay** | Rate limiting built in — useful for slow or IDS-protected targets |
| 📁 | **File path completion** | Tab-complete wordlist paths directly in the console |
| 📤 | **Auto-export** | Every scan saves a `.json` and `.txt` result file to `~/.anubis/results/` automatically |
| 🕓 | **Scan history** | Browse all past scan results with the `history` command |
| 🛑 | **Non-blocking scans** | `run` launches a background thread — keep using the console while the scan runs |
| ⌨️ | **Tab completion** | All commands, keys, and file paths autocomplete |
| ⬆️ | **Command history** | Navigate previous commands with arrow keys |
| 📦 | **Zero dependencies** | Pure Python standard library — nothing to install |

---

## 💡 Why Anubis?

Tools like `gobuster`, `ffuf`, and `feroxbuster` are excellent — but they're one-shot CLI commands. Every time you want to tweak a parameter, you re-type the whole command. Every time you find a subdirectory worth exploring, you open a new terminal and run the tool again manually.

**Anubis changes that workflow.** You open one console, set your target and wordlist, and everything else follows:

- Discovered directories are **automatically re-scanned** without any intervention
- Results are **saved to disk immediately** as hits come in — nothing is lost if you Ctrl+C
- You can **keep typing commands** while a scan runs in the background
- A single `results` command shows everything from the last scan in a clean table

### Compared to alternatives

| | Anubis | gobuster | ffuf | feroxbuster |
|---|:---:|:---:|:---:|:---:|
| Interactive console | ✅ | ❌ | ❌ | ❌ |
| Auto recursive pivot | ✅ | ❌ | ❌ | ✅ |
| Non-blocking scan | ✅ | ❌ | ❌ | ❌ |
| Live progress bar | ✅ | ✅ | ✅ | ✅ |
| Auto result export | ✅ | manual | manual | ✅ |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| Tab completion on paths | ✅ | ❌ | ❌ | ❌ |
| Scan history | ✅ | ❌ | ❌ | ❌ |

---

## 📦 Installation

No pip, no virtualenv, no setup. Python 3.10+ is the only requirement.

```bash
git clone https://github.com/youruser/anubis.git
cd anubis
chmod +x anubis.py
```

**Optional — install system-wide:**

```bash
sudo cp anubis.py /usr/local/bin/anubis
```

Then just run:

```bash
anubis
```

---

## 🚀 Usage

```bash
python3 anubis.py
```

### Typical CTF workflow

```
Anubis ○ (-) > set target http://10.10.11.25
Anubis ○ (10.10.11.25) > set wordlist /usr/share/wordlists/dirb/common.txt
Anubis ○ (10.10.11.25) > set extensions php,html,txt
Anubis ○ (10.10.11.25) > set threads 30
Anubis ○ (10.10.11.25) > run

  # Scan starts in background — results stream live
  # Discovered directories are automatically re-scanned
  # Ctrl+C to stop, or type any command while it runs

Anubis ● (10.10.11.25) > status
  ● Scan running on http://10.10.11.25

Anubis ● (10.10.11.25) > wait      # block until finished

Anubis ○ (10.10.11.25) > results   # summary table of all hits
Anubis ○ (10.10.11.25) > history   # list all past scans
```

### Wordlist tips

Any plain text wordlist works — one word per line, `#` lines are ignored. Common sources:

```bash
# Kali / Parrot
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt

# macOS with SecLists
/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt
```

---

## 📋 Commands

### Configuration

| Command | Description | Default |
|---|---|---|
| `set target <url>` | Target base URL — `http://` prepended if missing | — |
| `set wordlist <path>` | Path to wordlist — Tab-complete supported | — |
| `set threads <n>` | Concurrent worker threads (1–200) | `20` |
| `set timeout <s>` | Per-request timeout in seconds | `6` |
| `set delay <s>` | Delay per thread between requests | `0` |
| `set extensions <a,b>` | Extensions to append per word (e.g. `php,html,bak`) | none |
| `set status <codes>` | Comma-separated HTTP codes counted as hits | `200,204,301,302,307,308,401,403` |
| `set recursive <true\|false>` | Auto-pivot into discovered directories | `true` |
| `set depth <n>` | Maximum recursion depth (1–10) | `3` |
| `set useragent <ua>` | Custom User-Agent header | `Mozilla/5.0 (anubis/1.0)` |
| `show options` | Display all current settings | — |

### Running

| Command | Description |
|---|---|
| `run` / `start` | Start the scan in the background |
| `wait` | Block the prompt until the scan finishes (Ctrl+C to abort) |
| `stop` | Gracefully stop the running scan |
| `status` | Show whether a scan is currently running |

### Results

| Command | Description |
|---|---|
| `results` | Display a table of hits from the most recent scan |
| `history` | List all saved scan result files in `~/.anubis/results/` |

### Other

| Command | Description |
|---|---|
| `clear` | Clear the screen |
| `help` | Show the full command reference |
| `exit` / `quit` | Stop any running scan and exit |

---

## 🔀 Recursive Scanning

When `recursive` is enabled (default), Anubis automatically pivots into any discovered directory-like URL that returns a 2xx or 3xx response — no manual re-running required.

```
[301]  http://10.10.11.25/uploads  →  http://10.10.11.25/uploads/

  ↪  Pivoting into:  http://10.10.11.25/uploads

  [200]  http://10.10.11.25/uploads/config.php     ...
  [200]  http://10.10.11.25/uploads/shell.php       ...
```

Control recursion with:

```
set recursive false    # disable entirely
set depth 2            # limit to 2 levels deep (default: 3)
```

---

## 📤 Results & Export

Every scan automatically writes two files to `~/.anubis/results/`:

| Format | Content |
|---|---|
| `.json` | Structured — URL, status, size, redirect, elapsed ms, timestamp |
| `.txt` | Plain text — one hit per line, easy to grep |

Filenames are timestamped and include the target hostname:

```
~/.anubis/results/
  http_10.10.11.25_20241105_143022.json
  http_10.10.11.25_20241105_143022.txt
```

Files are written **incrementally as hits arrive** — results are never lost even if you interrupt the scan.

View the most recent scan inside the console:

```
Anubis ○ (10.10.11.25) > results

  ════════════════════════════════════════════════════════════════
  RESULTS  —  7 hits
  ════════════════════════════════════════════════════════════════
  STATUS      SIZE      TIME    URL
  [200]       128 B     42ms    http://10.10.11.25/admin
  [301]         0 B      8ms    http://10.10.11.25/uploads  → /uploads/
  [403]       512 B     18ms    http://10.10.11.25/server-status
  ...
```

---

## 🎯 The Progress Bar

The live progress bar shows everything you need at a glance, on a single line that never interferes with hit output above it:

```
  ██████████████░░░░░░░░░░░░░░░░  46.2%  1841/4641  +3  312 r/s  ETA 9s  /admin
  └── fill ──────────────────────  pct    done/total  hits  speed    eta  current
```

- **Fill** — proportional to completion, green filled / grey empty
- **Hits** — `+N` count of discovered URLs so far
- **Speed** — live requests per second
- **ETA** — estimated time to completion
- **Current** — path currently being tested

---

## ❓ FAQ

**Does it work against HTTPS targets?**
Yes. Just use `https://` in the target URL. Certificate validation follows Python's default behaviour (system CA bundle). Self-signed certs on CTF boxes may cause errors — this will be configurable in a future release.

**What happens if I Ctrl+C during a scan?**
The scan is gracefully stopped and all hits recorded so far are already saved to disk. You return to the prompt immediately.

**Can I run multiple scans?**
One scan at a time per console session. Use `stop` to abort the current one before starting another, or open a second terminal.

**What if the target has rate limiting or a WAF?**
Use `set delay <seconds>` to add a pause between requests per thread, and lower `set threads` to reduce concurrency. Combined, these give you fine-grained control over request rate.

**Why is the prompt showing `●` instead of `○`?**
`●` means a scan is currently running in the background. You can still use all commands — `status`, `help`, `set`, etc. — while it runs.

**Where are results stored?**
All results are saved to `~/.anubis/results/` automatically. Use `history` to browse them or open them directly with any text editor or `jq`.

---

## ⚠️ Disclaimer

This tool is intended **for authorized penetration testing, CTF competitions, and educational purposes only**.

Never use Anubis against systems you do not own or have explicit written permission to test. Unauthorized web scanning may be illegal in your jurisdiction. The author is not responsible for any misuse.

---

<div align="center">

Built for the terminal &nbsp;•&nbsp; Made with ❤️ for the security community &nbsp;•&nbsp; by [@ZetaOrioniss](https://github.com/ZetaOrioniss)

</div>
