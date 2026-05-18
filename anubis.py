#!/usr/bin/env python3

import os
import re
import sys
import time
import shlex
import readline
import threading
import queue
import urllib.request
import urllib.error
import urllib.parse
import http.client
import socket
import json
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict


# ─────────────────────────────────────────────
#  Colours
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    END    = "\033[0m"

    @staticmethod
    def r(s):    return f"{C.RED}{s}{C.END}"
    @staticmethod
    def g(s):    return f"{C.GREEN}{s}{C.END}"
    @staticmethod
    def y(s):    return f"{C.YELLOW}{s}{C.END}"
    @staticmethod
    def b(s):    return f"{C.BLUE}{s}{C.END}"
    @staticmethod
    def c(s):    return f"{C.CYAN}{s}{C.END}"
    @staticmethod
    def m(s):    return f"{C.MAGENTA}{s}{C.END}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.END}"
    @staticmethod
    def dim(s):  return f"{C.DIM}{s}{C.END}"


# ─────────────────────────────────────────────
#  Constants & defaults
# ─────────────────────────────────────────────

OUTPUT_DIR   = Path(os.path.expanduser("~/.anubis/results"))
DEFAULT_THREADS    = 20
DEFAULT_TIMEOUT    = 6        # seconds per request
DEFAULT_DELAY      = 0.0      # seconds between requests per thread
DEFAULT_EXTENSIONS = []
DEFAULT_STATUS_OK  = {200, 204, 301, 302, 307, 308, 401, 403}
USER_AGENT   = "Mozilla/5.0 (anubis/1.0; CTF-scanner)"

# Colour map per HTTP status family
STATUS_COLOR = {
    2: C.GREEN,
    3: C.CYAN,
    4: C.YELLOW,
    5: C.RED,
}

# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────

@dataclass
class Hit:
    url:        str
    status:     int
    size:       int
    redirect:   str = ""
    elapsed_ms: int = 0

@dataclass
class ScanConfig:
    target:     str   = ""
    wordlist:   str   = ""
    threads:    int   = DEFAULT_THREADS
    timeout:    int   = DEFAULT_TIMEOUT
    delay:      float = DEFAULT_DELAY
    extensions: list  = field(default_factory=list)
    status_ok:  set   = field(default_factory=lambda: set(DEFAULT_STATUS_OK))
    recursive:  bool  = True    # auto-pivot on hits
    max_depth:  int   = 3
    user_agent: str   = USER_AGENT
    follow_redirect: bool = False

    def is_ready(self) -> tuple[bool, str]:
        if not self.target:
            return False, "Target URL not set. Use: set target <url>"
        if not self.wordlist:
            return False, "Wordlist not set. Use: set wordlist <path>"
        if not Path(self.wordlist).is_file():
            return False, f"Wordlist not found: {self.wordlist}"
        return True, ""


# ─────────────────────────────────────────────
#  Print lock (thread-safe output)
# ─────────────────────────────────────────────

_print_lock = threading.Lock()

def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

def erase_line():
    sys.stdout.write("\r\033[2K")
    sys.stdout.flush()


# ─────────────────────────────────────────────
#  HTTP engine
# ─────────────────────────────────────────────

def make_request(url: str, cfg: ScanConfig) -> tuple[int, int, str]:
    """
    Returns (status_code, content_length, redirect_url).
    Returns (-1, 0, "") on network error.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent})
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            body   = resp.read()
            status = resp.status
            redir  = resp.url if resp.url != url else ""
            return status, len(body), redir
    except urllib.error.HTTPError as e:
        # HTTPError is still a valid response (4xx / 5xx)
        try:
            body = e.read()
        except Exception:
            body = b""
        redir = e.headers.get("Location", "")
        return e.code, len(body), redir
    except urllib.error.URLError:
        return -1, 0, ""
    except (http.client.RemoteDisconnected,
            http.client.IncompleteRead,
            ConnectionResetError,
            socket.timeout,
            OSError):
        return -1, 0, ""


# ─────────────────────────────────────────────
#  Wordlist helpers
# ─────────────────────────────────────────────

def load_wordlist(path: str) -> list[str]:
    words = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
    except Exception as e:
        tprint(C.r(f"  [-] Cannot read wordlist: {e}"))
    return words


def build_urls(base: str, word: str, extensions: list[str]) -> list[str]:
    """
    Generate all URL variants for a word:
    base/word  +  base/word.ext for each extension.
    """
    base = base.rstrip("/")
    word = word.lstrip("/")
    urls = [f"{base}/{word}"]
    for ext in extensions:
        ext = ext.lstrip(".")
        urls.append(f"{base}/{word}.{ext}")
    return urls


# ─────────────────────────────────────────────
#  Progress bar
# ─────────────────────────────────────────────

class Progress:
    def __init__(self, total: int):
        self.total    = total
        self.done     = 0
        self.hits     = 0
        self.errors   = 0
        self._lock    = threading.Lock()
        self._start   = time.time()

    def tick(self, is_hit: bool = False, is_error: bool = False):
        with self._lock:
            self.done  += 1
            if is_hit:   self.hits   += 1
            if is_error: self.errors += 1

    def render(self, current_url: str = "") -> str:
        elapsed = time.time() - self._start
        rps     = self.done / elapsed if elapsed > 0 else 0
        pct     = self.done / self.total * 100 if self.total else 0
        bar_w   = 24
        filled  = int(bar_w * self.done / self.total) if self.total else 0
        bar     = C.g("█" * filled) + C.dim("░" * (bar_w - filled))
        eta     = int((self.total - self.done) / rps) if rps > 0 else 0

        short_url = current_url[-42:] if len(current_url) > 42 else current_url
        short_url = short_url.ljust(42)

        return (f"\r  {bar} {C.bold(f'{pct:5.1f}%')} "
                f"{C.dim(f'{self.done}/{self.total}')} "
                f"{C.g(f'↑{self.hits}')} "
                f"{C.dim(f'{rps:.0f}r/s')} "
                f"ETA:{C.y(f'{eta}s')} "
                f"{C.dim(short_url)}")


# ─────────────────────────────────────────────
#  Results storage
# ─────────────────────────────────────────────

class ResultStore:
    def __init__(self, target: str):
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts        = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe      = re.sub(r"[^\w\-]", "_", target.replace("://", "_"))
        self.path = OUTPUT_DIR / f"{safe}_{ts}.json"
        self.txt  = OUTPUT_DIR / f"{safe}_{ts}.txt"
        self._hits: list[dict] = []
        self._lock = threading.Lock()

    def add(self, hit: Hit):
        with self._lock:
            self._hits.append({
                "url":        hit.url,
                "status":     hit.status,
                "size":       hit.size,
                "redirect":   hit.redirect,
                "elapsed_ms": hit.elapsed_ms,
            })
            # Append text line immediately
            with open(self.txt, "a") as f:
                redir = f" -> {hit.redirect}" if hit.redirect else ""
                f.write(f"[{hit.status}] {hit.url}  ({hit.size}B){redir}\n")

    def save(self):
        with self._lock:
            with open(self.path, "w") as f:
                json.dump({
                    "meta": {
                        "generated": datetime.datetime.now().isoformat(),
                        "count": len(self._hits),
                    },
                    "hits": self._hits,
                }, f, indent=2)

    def hits(self) -> list[dict]:
        with self._lock:
            return list(self._hits)


# ─────────────────────────────────────────────
#  Scanner engine
# ─────────────────────────────────────────────

class Scanner:
    def __init__(self, cfg: ScanConfig):
        self.cfg    = cfg
        self._stop  = threading.Event()

    def stop(self):
        self._stop.set()

    def _worker(self, q: queue.Queue, store: ResultStore,
                progress: Progress, pivot_queue: queue.Queue | None):
        while not self._stop.is_set():
            try:
                url = q.get(timeout=0.3)
            except queue.Empty:
                break

            t0 = time.time()
            status, size, redir = make_request(url, self.cfg)
            elapsed = int((time.time() - t0) * 1000)

            if self.cfg.delay > 0:
                time.sleep(self.cfg.delay)

            is_hit   = status in self.cfg.status_ok
            is_error = status == -1

            progress.tick(is_hit=is_hit, is_error=is_error)

            if is_hit:
                hit = Hit(url=url, status=status, size=size,
                          redirect=redir, elapsed_ms=elapsed)
                store.add(hit)

                # Status colour
                family = status // 100
                sc     = STATUS_COLOR.get(family, C.WHITE)

                erase_line()
                redir_str = f"  {C.dim('->')} {C.dim(redir[:60])}" if redir else ""
                tprint(
                    f"  {sc}{C.BOLD}[{status}]{C.END} "
                    f"{C.bold(url):<72} "
                    f"{C.dim(f'{size:>8} B')} "
                    f"{C.dim(f'{elapsed}ms')}"
                    f"{redir_str}"
                )

                # Pivot: if it's a directory-like hit, enqueue for recursive scan
                if pivot_queue and self.cfg.recursive:
                    # Only pivot on 2xx / 3xx and if URL looks like a directory
                    if family in (2, 3) and not re.search(r"\.\w{1,6}$", url):
                        pivot_queue.put(url)

            # Update progress bar (throttled to avoid I/O spam)
            if progress.done % 5 == 0 or is_hit:
                with _print_lock:
                    sys.stdout.write(progress.render(url))
                    sys.stdout.flush()

            q.task_done()

    def scan_base(self, base_url: str, words: list[str],
                  store: ResultStore, depth: int = 0,
                  pivot_queue: queue.Queue | None = None) -> list[Hit]:
        """
        Scan base_url with the given words.
        Returns list of hits.
        """
        if self._stop.is_set() or depth > self.cfg.max_depth:
            return []

        # Build full URL list
        urls = []
        for word in words:
            urls.extend(build_urls(base_url, word, self.cfg.extensions))

        total    = len(urls)
        progress = Progress(total)
        work_q   = queue.Queue()
        for u in urls:
            work_q.put(u)

        W = 80
        depth_label = f"  depth {depth}" if depth > 0 else ""
        tprint(f"\n{C.BOLD}{C.YELLOW}{'═' * W}{C.END}")
        tprint(f"{C.BOLD}{C.YELLOW}  SCANNING{C.END}  {C.c(base_url)}{C.dim(depth_label)}")
        tprint(f"  {C.dim(f'{total} URLs')}  ·  "
               f"{C.dim(f'{self.cfg.threads} threads')}  ·  "
               f"{C.dim(f'timeout {self.cfg.timeout}s')}  ·  "
               f"{C.dim(f'delay {self.cfg.delay}s/thread')}")
        tprint(f"{C.BOLD}{C.YELLOW}{'─' * W}{C.END}\n")

        threads = []
        n_threads = min(self.cfg.threads, total)
        for _ in range(n_threads):
            t = threading.Thread(
                target=self._worker,
                args=(work_q, store, progress, pivot_queue),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        erase_line()
        elapsed = time.time() - progress._start
        tprint(
            f"\n  {C.bold('Done:')} "
            f"{C.g(str(progress.hits))} hits  "
            f"{C.dim(str(progress.errors))} errors  "
            f"{C.dim(f'{progress.done} requests in {elapsed:.1f}s')}\n"
        )
        return store.hits()

    def run(self, words: list[str]) -> ResultStore:
        store      = ResultStore(self.cfg.target)
        pivot_q: queue.Queue = queue.Queue()

        # Initial scan
        self.scan_base(self.cfg.target, words, store, depth=0,
                       pivot_queue=pivot_q)

        # Recursive pivot loop
        if self.cfg.recursive:
            visited = {self.cfg.target.rstrip("/")}
            depth   = 1
            while not self._stop.is_set() and depth <= self.cfg.max_depth:
                pivots = []
                try:
                    while True:
                        pivots.append(pivot_q.get_nowait())
                except queue.Empty:
                    pass

                # Deduplicate
                new_pivots = [p.rstrip("/") for p in pivots
                              if p.rstrip("/") not in visited]
                if not new_pivots:
                    break

                for pivot in new_pivots:
                    visited.add(pivot)
                    if self._stop.is_set():
                        break
                    tprint(f"\n  {C.y('↪')} {C.bold('Pivoting into:')} {C.c(pivot)}")
                    self.scan_base(pivot, words, store, depth=depth,
                                   pivot_queue=pivot_q)
                depth += 1

        store.save()
        tprint(f"  {C.g('✔')}  Results saved:")
        tprint(f"     JSON: {C.bold(str(store.path))}")
        tprint(f"     TXT:  {C.bold(str(store.txt))}\n")
        return store


# ─────────────────────────────────────────────
#  Session state
# ─────────────────────────────────────────────

class Session:
    def __init__(self):
        self.cfg: ScanConfig = ScanConfig()
        self._scanner: Scanner | None = None
        self._scan_thread: threading.Thread | None = None

    def is_running(self) -> bool:
        return (self._scan_thread is not None
                and self._scan_thread.is_alive())

    def start_scan(self):
        ok, err = self.cfg.is_ready()
        if not ok:
            tprint(C.r(f"  [-] {err}"))
            return

        words = load_wordlist(self.cfg.wordlist)
        if not words:
            tprint(C.r("  [-] Wordlist is empty or unreadable."))
            return

        tprint(f"\n  {C.dim('Wordlist:')} {C.g(str(len(words)))} words  ·  "
               f"{C.dim('Extensions:')} {C.g(', '.join(self.cfg.extensions) or 'none')}  ·  "
               f"{C.dim('Recursive:')} {C.g(str(self.cfg.recursive))} "
               f"{C.dim('(max depth ' + str(self.cfg.max_depth) + ')')}")

        self._scanner = Scanner(self.cfg)

        def _run():
            self._scanner.run(words)

        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    def stop_scan(self):
        if self._scanner:
            self._scanner.stop()
            tprint(C.y("  [!] Scan stop requested — waiting for threads..."))
            if self._scan_thread:
                self._scan_thread.join(timeout=5)
            tprint(C.dim("  Scan stopped."))


# ─────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────

W = 80

def hr(char="─", color=C.YELLOW) -> str:
    return f"{C.BOLD}{color}{char * W}{C.END}"


def print_options(cfg: ScanConfig):
    def row(k, v, note=""): 
        vc = C.g(str(v)) if v else C.r("not set")
        tprint(f"  {C.bold(k):<{14 + len(C.BOLD) + len(C.END)}}{vc}  {C.dim(note)}")

    tprint(f"\n{hr('─')}")
    tprint(f"  {C.bold('OPTION'):<{14 + len(C.BOLD) + len(C.END)}}{C.bold('VALUE')}")
    tprint(hr("─", C.DIM))
    row("target",     cfg.target,        "URL to enumerate")
    row("wordlist",   cfg.wordlist,       "path to wordlist file")
    row("threads",    cfg.threads,        "concurrent workers")
    row("timeout",    f"{cfg.timeout}s",  "request timeout")
    row("delay",      f"{cfg.delay}s",    "delay per thread between requests")
    row("extensions", ", ".join(cfg.extensions) or "none", "e.g. php,html,txt")
    row("status",     ", ".join(str(s) for s in sorted(cfg.status_ok)), "codes considered as hits")
    row("recursive",  cfg.recursive,      f"auto-pivot on hits (max depth {cfg.max_depth})")
    row("max_depth",  cfg.max_depth,      "pivot recursion limit")
    row("useragent",  cfg.user_agent[:50],"")
    tprint(hr("─"))
    tprint()


def print_results_table(hits: list[dict]):
    if not hits:
        tprint(C.dim("  No hits recorded."))
        return

    tprint(f"\n{hr('═')}")
    tprint(f"{C.BOLD}{C.YELLOW}  RESULTS — {len(hits)} hits{C.END}")
    tprint(hr("═"))
    tprint(f"  {C.bold('STATUS'):<{10 + len(C.BOLD) + len(C.END)}}"
           f"{C.bold('SIZE'):>10}  "
           f"{C.bold('URL')}")
    tprint(hr("─", C.DIM))
    for h in hits:
        family = h["status"] // 100
        sc     = STATUS_COLOR.get(family, C.WHITE)
        redir  = f"  {C.dim('->')} {C.dim(h['redirect'][:50])}" if h.get("redirect") else ""
        tprint(f"  {sc}{C.BOLD}[{h['status']}]{C.END}  "
               f"{C.dim(str(h['size']) + ' B'):>12}  "
               f"{h['url']}{redir}")
    tprint(hr("═"))
    tprint()


def list_past_results():
    if not OUTPUT_DIR.exists():
        tprint(C.dim("  No results found."))
        return
    files = sorted(OUTPUT_DIR.glob("*.txt"), reverse=True)
    if not files:
        tprint(C.dim("  No result files found."))
        return
    tprint(f"\n{hr('─')}")
    tprint(f"  {C.bold('PAST SCANS')}  {C.dim(str(OUTPUT_DIR))}")
    tprint(hr("─", C.DIM))
    for i, f in enumerate(files[:20], 1):
        sz = f.stat().st_size
        tprint(f"  {C.dim(str(i) + '.'):<{5 + len(C.DIM) + len(C.END)}}"
               f"{C.g(f.name):<60}{C.dim(str(sz) + ' B')}")
    tprint(hr("─"))
    tprint()


# ─────────────────────────────────────────────
#  Banner / Help
# ─────────────────────────────────────────────

BANNER = f"""
{C.BOLD}{C.WHITE}
   ▄████████ ███▄▄▄▄   ███    █▄  ▀█████████▄   ▄█     ▄████████ 
  ███    ███ ███▀▀▀██▄ ███    ███   ███    ███ ███    ███    ███ 
  ███    ███ ███   ███ ███    ███   ███    ███ ███▌   ███    █▀  
  ███    ███ ███   ███ ███    ███  ▄███▄▄▄██▀  ███▌   ███        
▀███████████ ███   ███ ███    ███ ▀▀███▀▀▀██▄  ███▌ ▀███████████ 
  ███    ███ ███   ███ ███    ███   ███    ██▄ ███           ███ 
  ███    ███ ███   ███ ███    ███   ███    ███ ███     ▄█    ███ 
  ███    █▀   ▀█   █▀  ████████▀  ▄█████████▀  █▀    ▄████████▀  
{C.END}{C.DIM}
  Web Directory Enumeration Console  •  CTF Edition{C.END}
{C.END}{C.DIM}  Author: {C.BOLD}{C.WHITE}@ZetaOrioniss{C.END}
{C.END}{C.DIM}  Version: {C.BOLD}{C.WHITE}v1.0{C.END}
{C.DIM}
  Results saved in: {C.END}{C.BOLD}{str(OUTPUT_DIR)}{C.END}
{C.DIM}  Type {C.END}{C.BOLD}help{C.END}{C.DIM} to list available commands.{C.END}
"""

HELP = f"""
{C.BOLD}{C.YELLOW}
╔══════════════════════════════════════════════════════════════╗
║                          COMMANDS                            ║
╚══════════════════════════════════════════════════════════════╝{C.END}

  {C.bold('Configuration')}
  {C.g('set target <url>')}           Target base URL  (e.g. http://10.10.11.25)
  {C.g('set wordlist <path>')}        Path to wordlist file
  {C.g('set threads <n>')}            Worker threads  (default: {DEFAULT_THREADS})
  {C.g('set timeout <s>')}            Request timeout in seconds  (default: {DEFAULT_TIMEOUT})
  {C.g('set delay <s>')}              Delay per thread between requests  (default: 0)
  {C.g('set extensions <a,b,…>')}     File extensions to append  (e.g. php,html,txt)
  {C.g('set status <codes>')}         Hit status codes  (default: 200,204,301,302,307,308,401,403)
  {C.g('set recursive <true|false>')} Auto-pivot on directory hits  (default: true)
  {C.g('set depth <n>')}              Max recursion depth  (default: 3)
  {C.g('set useragent <ua>')}         Custom User-Agent string
  {C.g('show options')}               Display current configuration

  {C.bold('Running')}
  {C.g('run')}  /  {C.g('start')}              Start the scan (non-blocking)
  {C.g('wait')}                       Block until current scan finishes
  {C.g('stop')}                       Interrupt running scan
  {C.g('status')}                     Show if a scan is currently running

  {C.bold('Results')}
  {C.g('results')}                    Show hits from the last scan
  {C.g('history')}                    List all saved result files

  {C.bold('Other')}
  {C.g('clear')}                      Clear the screen
  {C.g('help')}                       Show this help
  {C.g('exit')}  /  {C.g('quit')}              Exit
"""


# ─────────────────────────────────────────────
#  Tab completion
# ─────────────────────────────────────────────

COMMANDS = [
    "set", "show", "run", "start", "wait", "stop", "status",
    "results", "history", "clear", "help", "exit", "quit",
]
SET_KEYS = [
    "target", "wordlist", "threads", "timeout", "delay",
    "extensions", "status", "recursive", "depth", "useragent",
]
SHOW_OPTS = ["options"]
BOOL_OPTS = ["true", "false"]


def _wordlist_complete(text: str) -> list[str]:
    """File path completion for the wordlist key."""
    d = os.path.dirname(text) or "."
    base = os.path.basename(text)
    try:
        entries = os.listdir(d)
    except OSError:
        return []
    matches = []
    for e in entries:
        if e.startswith(base):
            full = os.path.join(d, e) if d != "." else e
            matches.append(full + "/" if os.path.isdir(os.path.join(d, e)) else full)
    return matches


def completer(text: str, state: int):
    line   = readline.get_line_buffer().lstrip()
    parts  = line.split()
    nparts = len(parts)

    if nparts == 0 or (nparts == 1 and not line.endswith(" ")):
        opts = [c for c in COMMANDS if c.startswith(text)]
    elif parts[0] == "set" and nparts == 2 and not line.endswith(" "):
        opts = [k for k in SET_KEYS if k.startswith(text)]
    elif parts[0] == "set" and nparts >= 2:
        key = parts[1].lower() if len(parts) > 1 else ""
        if key == "wordlist":
            opts = _wordlist_complete(text)
        elif key == "recursive":
            opts = [o for o in BOOL_OPTS if o.startswith(text)]
        else:
            opts = []
    elif parts[0] == "show" and nparts <= 2:
        opts = [o for o in SHOW_OPTS if o.startswith(text)]
    else:
        opts = []

    return opts[state] if state < len(opts) else None


readline.set_completer(completer)
readline.set_completer_delims(" \t")
readline.parse_and_bind("tab: complete")


# ─────────────────────────────────────────────
#  Prompt
# ─────────────────────────────────────────────

def prompt(session: Session) -> str:
    tgt  = session.cfg.target or "-"
    # Shorten target for display
    tgt  = re.sub(r"https?://", "", tgt)[:30]
    run  = C.g("●") if session.is_running() else C.dim("○")
    return (f"{C.BOLD}{C.RED}anubis{C.END} "
            f"{run} "
            f"{C.dim(f'({tgt})')} "
            f"{C.BOLD}{C.GREEN}>{C.END} ")


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────

def run_console() -> None:
    print(BANNER)
    session = Session()
    last_store: ResultStore | None = None

    while True:
        try:
            raw = input(prompt(session)).strip()
        except (KeyboardInterrupt, EOFError):
            if session.is_running():
                print()
                session.stop_scan()
            else:
                print(f"\n{C.dim('Goodbye.')}\n")
                break
            continue

        if not raw:
            continue

        try:
            parts = shlex.split(raw)
        except ValueError as e:
            print(C.r(f"  [-] Parse error: {e}"))
            continue

        cmd  = parts[0].lower()
        args = parts[1:]

        # ── exit ──────────────────────────────────────────────────────────
        if cmd in ("exit", "quit"):
            if session.is_running():
                print(C.y("  [!] Scan running — stopping first..."))
                session.stop_scan()
            print(f"\n{C.dim('Goodbye.')}\n")
            break

        # ── help ──────────────────────────────────────────────────────────
        elif cmd == "help":
            print(HELP)

        # ── clear ─────────────────────────────────────────────────────────
        elif cmd == "clear":
            print("\033[2J\033[H", end="")
            print(BANNER)

        # ── show ──────────────────────────────────────────────────────────
        elif cmd == "show":
            sub = args[0].lower() if args else "options"
            if sub == "options":
                print_options(session.cfg)
            else:
                print(C.r(f"  [-] Unknown: '{sub}'  (options)"))

        # ── set ───────────────────────────────────────────────────────────
        elif cmd == "set":
            if len(args) < 2:
                print(C.r("  Usage: set <key> <value>"))
            else:
                key = args[0].lower()
                val = " ".join(args[1:])

                if key == "target":
                    # Normalise URL
                    if not val.startswith(("http://", "https://")):
                        val = "http://" + val
                    session.cfg.target = val.rstrip("/")
                    print(f"  {C.dim('target')} => {C.g(session.cfg.target)}")

                elif key == "wordlist":
                    p = Path(val).expanduser()
                    if not p.is_file():
                        print(C.r(f"  [-] File not found: {val}"))
                    else:
                        session.cfg.wordlist = str(p)
                        # Count words
                        try:
                            wc = sum(1 for l in open(p, errors="ignore")
                                     if l.strip() and not l.startswith("#"))
                        except Exception:
                            wc = "?"
                        print(f"  {C.dim('wordlist')} => {C.g(str(p))}  {C.dim('(' + str(wc) + ' words)')}")

                elif key == "threads":
                    try:
                        n = int(val)
                        if not 1 <= n <= 200:
                            raise ValueError
                        session.cfg.threads = n
                        print(f"  {C.dim('threads')} => {C.g(str(n))}")
                    except ValueError:
                        print(C.r("  [-] threads must be an integer between 1 and 200"))

                elif key == "timeout":
                    try:
                        n = float(val)
                        if n <= 0:
                            raise ValueError
                        session.cfg.timeout = n
                        print(f"  {C.dim('timeout')} => {C.g(str(n) + 's')}")
                    except ValueError:
                        print(C.r("  [-] timeout must be a positive number"))

                elif key == "delay":
                    try:
                        n = float(val)
                        if n < 0:
                            raise ValueError
                        session.cfg.delay = n
                        print(f"  {C.dim('delay')} => {C.g(str(n) + 's')}")
                    except ValueError:
                        print(C.r("  [-] delay must be a non-negative number"))

                elif key == "extensions":
                    exts = [e.strip().lstrip(".") for e in val.replace(",", " ").split() if e.strip()]
                    session.cfg.extensions = exts
                    print(f"  {C.dim('extensions')} => {C.g(', '.join(exts) or 'none')}")

                elif key == "status":
                    try:
                        codes = {int(c.strip()) for c in val.replace(",", " ").split() if c.strip()}
                        session.cfg.status_ok = codes
                        print(f"  {C.dim('status')} => {C.g(', '.join(str(c) for c in sorted(codes)))}")
                    except ValueError:
                        print(C.r("  [-] status must be comma-separated HTTP codes"))

                elif key == "recursive":
                    if val.lower() in ("true", "1", "yes", "on"):
                        session.cfg.recursive = True
                    elif val.lower() in ("false", "0", "no", "off"):
                        session.cfg.recursive = False
                    else:
                        print(C.r("  [-] recursive must be true or false"))
                        continue
                    print(f"  {C.dim('recursive')} => {C.g(str(session.cfg.recursive))}")

                elif key == "depth":
                    try:
                        n = int(val)
                        if not 1 <= n <= 10:
                            raise ValueError
                        session.cfg.max_depth = n
                        print(f"  {C.dim('depth')} => {C.g(str(n))}")
                    except ValueError:
                        print(C.r("  [-] depth must be an integer between 1 and 10"))

                elif key == "useragent":
                    session.cfg.user_agent = val
                    print(f"  {C.dim('useragent')} => {C.g(val[:60])}")

                else:
                    print(C.r(f"  [-] Unknown key: '{key}'"))
                    print(f"  {C.dim('Keys:')} {', '.join(SET_KEYS)}")

        # ── run / start ───────────────────────────────────────────────────
        elif cmd in ("run", "start"):
            if session.is_running():
                print(C.y("  [!] A scan is already running. Use 'stop' to abort it."))
            else:
                session.start_scan()

        # ── wait ──────────────────────────────────────────────────────────
        elif cmd == "wait":
            if not session.is_running():
                print(C.dim("  No scan running."))
            else:
                print(C.dim("  Waiting for scan to finish... (Ctrl+C to stop)"))
                try:
                    session._scan_thread.join()
                except KeyboardInterrupt:
                    print()
                    session.stop_scan()

        # ── stop ──────────────────────────────────────────────────────────
        elif cmd == "stop":
            if session.is_running():
                session.stop_scan()
            else:
                print(C.dim("  No scan running."))

        # ── status ────────────────────────────────────────────────────────
        elif cmd == "status":
            if session.is_running():
                print(f"  {C.g('●')} Scan running on {C.c(session.cfg.target)}")
            else:
                print(f"  {C.dim('○')} No scan running.")

        # ── results ───────────────────────────────────────────────────────
        elif cmd == "results":
            # Find most recent result JSON
            if not OUTPUT_DIR.exists():
                print(C.dim("  No results yet."))
            else:
                files = sorted(OUTPUT_DIR.glob("*.json"), reverse=True)
                if not files:
                    print(C.dim("  No results yet."))
                else:
                    with open(files[0]) as f:
                        data = json.load(f)
                    print_results_table(data.get("hits", []))
                    print(f"  {C.dim('File:')} {files[0]}")

        # ── history ───────────────────────────────────────────────────────
        elif cmd == "history":
            list_past_results()

        # ── unknown ───────────────────────────────────────────────────────
        else:
            print(C.r(f"  [-] Unknown command: '{cmd}'"))
            print(f"  {C.dim('Type')} help {C.dim('for available commands.')}")


if __name__ == "__main__":
    run_console()