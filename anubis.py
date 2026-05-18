#!/usr/bin/env python3
"""
anubis — Web directory enumeration console
Style: same aesthetic as revshell / hostsctl (ANSI, readline, shlex).
Pure stdlib — no external dependencies.
"""

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


# ─────────────────────────────────────────────
#  Colours
# ─────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    END     = "\033[0m"

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

OUTPUT_DIR         = Path(os.path.expanduser("~/.anubis/results"))
DEFAULT_THREADS    = 20
DEFAULT_TIMEOUT    = 6
DEFAULT_DELAY      = 0.0
DEFAULT_EXTENSIONS = []
DEFAULT_STATUS_OK  = {200, 204, 301, 302, 307, 308, 401, 403}
USER_AGENT         = "Mozilla/5.0 (anubis/1.0; CTF-scanner)"

STATUS_COLOR = {2: C.GREEN, 3: C.CYAN, 4: C.YELLOW, 5: C.RED}

# Terminal width (fallback 100)
try:
    TERM_W = os.get_terminal_size().columns
except OSError:
    TERM_W = 100


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
    target:          str   = ""
    wordlist:        str   = ""
    threads:         int   = DEFAULT_THREADS
    timeout:         int   = DEFAULT_TIMEOUT
    delay:           float = DEFAULT_DELAY
    extensions:      list  = field(default_factory=list)
    status_ok:       set   = field(default_factory=lambda: set(DEFAULT_STATUS_OK))
    recursive:       bool  = True
    max_depth:       int   = 3
    user_agent:      str   = USER_AGENT
    follow_redirect: bool  = False

    def is_ready(self) -> tuple[bool, str]:
        if not self.target:
            return False, "Target URL not set. Use: set target <url>"
        if not self.wordlist:
            return False, "Wordlist not set. Use: set wordlist <path>"
        if not Path(self.wordlist).is_file():
            return False, f"Wordlist not found: {self.wordlist}"
        return True, ""


# ─────────────────────────────────────────────
#  Display manager
#
#  Single source of truth for stdout during a scan.
#  Workers push Hit objects into _hit_q.
#  The renderer thread:
#    1. erases the progress bar line
#    2. prints any pending hits (clean, above the bar)
#    3. redraws the progress bar on the last line
#  No other thread ever writes to stdout directly.
# ─────────────────────────────────────────────

class DisplayManager:
    # ANSI helpers
    ERASE_LINE  = "\r\033[2K"
    CURSOR_UP   = "\033[1A"
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"

    def __init__(self, total: int, base_url: str):
        self.total    = total
        self.base_url = base_url

        # stats (written by workers, read by renderer)
        self._done   = 0
        self._hits   = 0
        self._errors = 0
        self._skip   = 0
        self._start  = time.time()
        self._lock   = threading.Lock()

        # hit queue: workers push Hit objects here
        self._hit_q: queue.Queue = queue.Queue()

        # renderer state
        self._bar_visible  = False   # is the progress bar currently on screen?
        self._current_url  = ""
        self._stop_render  = threading.Event()
        self._render_thread = threading.Thread(
            target=self._render_loop, daemon=True
        )
        self._render_thread.start()

    # ── called by workers ────────────────────────────────────────────────

    def tick(self, url: str, is_hit: bool = False,
             is_error: bool = False, is_skip: bool = False,
             hit: "Hit | None" = None):
        with self._lock:
            self._done  += 1
            if is_hit:   self._hits   += 1
            if is_error: self._errors += 1
            if is_skip:  self._skip   += 1
            self._current_url = url

        if hit is not None:
            self._hit_q.put(hit)

    # ── renderer thread ──────────────────────────────────────────────────

    def _render_loop(self):
        sys.stdout.write(self.HIDE_CURSOR)
        sys.stdout.flush()
        while not self._stop_render.is_set():
            self._flush()
            time.sleep(0.08)          # ~12 fps — smooth without burning CPU
        self._flush(final=True)       # drain remaining hits after scan ends
        sys.stdout.write(self.SHOW_CURSOR)
        sys.stdout.flush()

    def _flush(self, final: bool = False):
        pending: list[Hit] = []
        try:
            while True:
                pending.append(self._hit_q.get_nowait())
        except queue.Empty:
            pass

        with self._lock:
            done   = self._done
            hits   = self._hits
            errors = self._errors
            skip   = self._skip
            url    = self._current_url

        has_output = bool(pending)

        if has_output or not final:
            # Erase progress bar if it was drawn
            if self._bar_visible:
                sys.stdout.write(self.ERASE_LINE)

            # Print each pending hit on its own clean line
            for h in pending:
                family    = h.status // 100
                sc        = STATUS_COLOR.get(family, C.WHITE)
                redir_str = (f"  {C.dim('→')} {C.dim(h.redirect[:55])}"
                             if h.redirect else "")

                # Status badge + URL + size + time
                badge = f"{sc}{C.BOLD}[{h.status}]{C.END}"
                url_s = h.url
                meta  = (f"{C.dim(f'{h.size:>8} B')}  "
                         f"{C.dim(f'{h.elapsed_ms}ms')}")

                # Truncate URL if too long for terminal
                max_url = TERM_W - 30
                if len(url_s) > max_url:
                    url_s = "…" + url_s[-(max_url - 1):]

                sys.stdout.write(
                    f"  {badge}  {C.bold(url_s)}  {meta}{redir_str}\n"
                )

            # Redraw the progress bar (unless final flush)
            if not final:
                bar_str = self._build_bar(done, hits, errors, url)
                sys.stdout.write(bar_str)
                self._bar_visible = True
            else:
                self._bar_visible = False

            sys.stdout.flush()

    def _build_bar(self, done: int, hits: int, errors: int,
                   current_url: str) -> str:
        elapsed = time.time() - self._start
        rps     = done / elapsed if elapsed > 0 else 0
        pct     = done / self.total * 100 if self.total else 0
        bar_w   = 28
        filled  = int(bar_w * done / self.total) if self.total else 0
        bar     = C.g("\u2588" * filled) + C.dim("\u2591" * (bar_w - filled))
        eta     = int((self.total - done) / rps) if rps > 0 else 0

        # Right side: trim current URL to fit
        right   = (f"  {C.dim(f'{done}/{self.total}')}  "
                   f"{C.g(f'+{hits}')}  "
                   f"{C.dim(f'{rps:.0f} r/s')}  "
                   f"ETA {C.y(f'{eta}s')}")

        # Current URL — what's being scanned right now
        # Strip base URL prefix to keep it short
        short = current_url.replace(self.base_url, "")
        if not short:
            short = current_url
        max_path = max(10, TERM_W - bar_w - 60)
        if len(short) > max_path:
            short = "…" + short[-(max_path - 1):]

        return (f"\r  {bar}  {C.bold(f'{pct:5.1f}%')}"
                f"{right}  {C.dim(short)}")

    # ── called after all threads finish ──────────────────────────────────

    def stop(self) -> dict:
        self._stop_render.set()
        self._render_thread.join(timeout=2)
        # Final clean newline after progress bar area
        sys.stdout.write("\n")
        sys.stdout.flush()
        elapsed = time.time() - self._start
        with self._lock:
            return {
                "hits":    self._hits,
                "errors":  self._errors,
                "skip":    self._skip,
                "done":    self._done,
                "elapsed": elapsed,
            }


# ─────────────────────────────────────────────
#  Progress (thin wrapper kept for compat)
# ─────────────────────────────────────────────

class Progress:
    """Legacy stub — stats now live in DisplayManager."""
    def __init__(self):
        self.hits = self.errors = self.skip = self.done = 0
        self._start = time.time()


# ─────────────────────────────────────────────
#  HTTP engine
# ─────────────────────────────────────────────

def make_request(url: str, cfg: ScanConfig) -> tuple[int, int, str]:
    """
    Returns (status_code, content_length, redirect_url).
      -1  : network / connection error
      -2  : invalid URL (spaces, non-ASCII) — silently skipped
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent})
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            body  = resp.read()
            redir = resp.url if resp.url != url else ""
            return resp.status, len(body), redir

    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        redir = e.headers.get("Location", "") if e.headers else ""
        return e.code, len(body), redir

    except urllib.error.URLError:
        return -1, 0, ""

    except (http.client.RemoteDisconnected,
            http.client.IncompleteRead,
            ConnectionResetError,
            socket.timeout,
            OSError):
        return -1, 0, ""

    except (http.client.InvalidURL, UnicodeEncodeError,
            UnicodeDecodeError, ValueError):
        return -2, 0, ""


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
        print(C.r(f"  [-] Cannot read wordlist: {e}"))
    return words


def _encode_word(word: str) -> str:
    return urllib.parse.quote(word, safe="/:@!$&'()*+,;=-._~")


def build_urls(base: str, word: str, extensions: list[str]) -> list[str]:
    base         = base.rstrip("/")
    word_encoded = _encode_word(word.lstrip("/"))
    urls = [f"{base}/{word_encoded}"]
    for ext in extensions:
        urls.append(f"{base}/{word_encoded}.{ext.lstrip('.')}")
    return urls


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
            with open(self.txt, "a") as f:
                redir = f" -> {hit.redirect}" if hit.redirect else ""
                f.write(f"[{hit.status}] {hit.url}  ({hit.size}B){redir}\n")

    def save(self):
        with self._lock:
            with open(self.path, "w") as f:
                json.dump({
                    "meta": {
                        "generated": datetime.datetime.now().isoformat(),
                        "count":     len(self._hits),
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
        self.cfg   = cfg
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def _worker(self, q: queue.Queue, store: ResultStore,
                dm: DisplayManager, pivot_queue: "queue.Queue | None"):
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
            is_skip  = status == -2

            hit_obj: Hit | None = None
            if is_hit:
                hit_obj = Hit(url=url, status=status, size=size,
                              redirect=redir, elapsed_ms=elapsed)
                store.add(hit_obj)

                # Auto-pivot on directory-like 2xx/3xx
                if pivot_queue and self.cfg.recursive:
                    family = status // 100
                    if family in (2, 3) and not re.search(r"\.\w{1,6}$", url):
                        pivot_queue.put(url)

            dm.tick(url, is_hit=is_hit, is_error=is_error,
                    is_skip=is_skip, hit=hit_obj)

            q.task_done()

    def scan_base(self, base_url: str, words: list[str],
                  store: ResultStore, depth: int = 0,
                  pivot_queue: "queue.Queue | None" = None) -> list[dict]:
        if self._stop.is_set() or depth > self.cfg.max_depth:
            return []

        urls: list[str] = []
        for word in words:
            urls.extend(build_urls(base_url, word, self.cfg.extensions))

        total = len(urls)
        W     = min(TERM_W, 100)

        # ── scan header ──────────────────────────────────────────────────
        depth_label = f"  {C.dim('depth ' + str(depth))}" if depth > 0 else ""
        print(f"\n{C.BOLD}{C.YELLOW}{'─' * W}{C.END}")
        print(f"  {C.BOLD}{C.YELLOW}SCANNING{C.END}  {C.c(base_url)}{depth_label}")
        print(f"  {C.dim(str(total) + ' URLs')}  "
              f"{C.dim('·')}  {C.dim(str(self.cfg.threads) + ' threads')}  "
              f"{C.dim('·')}  {C.dim('timeout ' + str(self.cfg.timeout) + 's')}  "
              f"{C.dim('·')}  {C.dim('delay ' + str(self.cfg.delay) + 's')}")
        print(f"{C.BOLD}{C.YELLOW}{'─' * W}{C.END}\n")

        dm     = DisplayManager(total, base_url)
        work_q: queue.Queue = queue.Queue()
        for u in urls:
            work_q.put(u)

        threads   = []
        n_threads = min(self.cfg.threads, total)
        for _ in range(n_threads):
            t = threading.Thread(
                target=self._worker,
                args=(work_q, store, dm, pivot_queue),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        stats = dm.stop()

        # ── scan footer ──────────────────────────────────────────────────
        elapsed = stats["elapsed"]
        rps     = stats["done"] / elapsed if elapsed > 0 else 0
        print(f"\n  {C.dim('─' * (W - 4))}")
        print(f"  {C.bold('hits')}    {C.g(str(stats['hits']))}")
        print(f"  {C.bold('errors')}  {C.dim(str(stats['errors']))}")
        print(f"  {C.bold('skipped')} {C.dim(str(stats['skip']))}")
        print(f"  {C.bold('total')}   {C.dim(str(stats['done']) + ' requests')}"
              f"  {C.dim('in ' + f'{elapsed:.1f}s')}  "
              f"{C.dim(f'({rps:.0f} r/s)')}")
        print(f"  {C.dim('─' * (W - 4))}\n")

        return store.hits()

    def run(self, words: list[str]) -> ResultStore:
        store   = ResultStore(self.cfg.target)
        pivot_q: queue.Queue = queue.Queue()

        self.scan_base(self.cfg.target, words, store, depth=0,
                       pivot_queue=pivot_q)

        if self.cfg.recursive:
            visited = {self.cfg.target.rstrip("/")}
            depth   = 1
            while not self._stop.is_set() and depth <= self.cfg.max_depth:
                pivots: list[str] = []
                try:
                    while True:
                        pivots.append(pivot_q.get_nowait())
                except queue.Empty:
                    pass

                new_pivots = [p.rstrip("/") for p in pivots
                              if p.rstrip("/") not in visited]
                if not new_pivots:
                    break

                for pivot in new_pivots:
                    visited.add(pivot)
                    if self._stop.is_set():
                        break
                    print(f"\n  {C.y('↪')}  {C.bold('Pivoting into:')}  {C.c(pivot)}\n")
                    self.scan_base(pivot, words, store, depth=depth,
                                   pivot_queue=pivot_q)
                depth += 1

        store.save()
        W = min(TERM_W, 100)
        print(f"{C.BOLD}{C.YELLOW}{'═' * W}{C.END}")
        print(f"  {C.g('✔')}  Scan complete — results saved")
        print(f"     {C.dim('JSON')}  {C.bold(str(store.path))}")
        print(f"     {C.dim('TXT ')}  {C.bold(str(store.txt))}")
        print(f"{C.BOLD}{C.YELLOW}{'═' * W}{C.END}\n")
        return store


# ─────────────────────────────────────────────
#  Session state
# ─────────────────────────────────────────────

class Session:
    def __init__(self):
        self.cfg: ScanConfig = ScanConfig()
        self._scanner: "Scanner | None" = None
        self._scan_thread: "threading.Thread | None" = None

    def is_running(self) -> bool:
        return (self._scan_thread is not None
                and self._scan_thread.is_alive())

    def start_scan(self):
        ok, err = self.cfg.is_ready()
        if not ok:
            print(C.r(f"  [-] {err}"))
            return

        words = load_wordlist(self.cfg.wordlist)
        if not words:
            print(C.r("  [-] Wordlist is empty or unreadable."))
            return

        exts   = ", ".join(self.cfg.extensions) or "none"
        depth  = str(self.cfg.max_depth)
        print(f"\n  {C.dim('Wordlist:')}    {C.g(str(len(words)))} words")
        print(f"  {C.dim('Extensions:')}  {C.g(exts)}")
        print(f"  {C.dim('Recursive:')}   {C.g(str(self.cfg.recursive))}"
              f"  {C.dim('(max depth ' + depth + ')')}\n")

        self._scanner = Scanner(self.cfg)

        def _run():
            self._scanner.run(words)  # type: ignore[union-attr]

        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    def stop_scan(self):
        if self._scanner:
            self._scanner.stop()
            print(C.y("  [!] Scan stop requested — waiting for threads..."))
            if self._scan_thread:
                self._scan_thread.join(timeout=5)
            print(C.dim("  Scan stopped.\n"))


# ─────────────────────────────────────────────
#  Display helpers (static tables)
# ─────────────────────────────────────────────

W_STATIC = 80


def hr(char="-", color=C.YELLOW, w=W_STATIC) -> str:
    return f"{C.BOLD}{color}{char * w}{C.END}"


def print_options(cfg: ScanConfig):
    def row(k, v, note=""):
        vc = C.g(str(v)) if v else C.r("not set")
        print(f"  {C.bold(k):<{16 + len(C.BOLD) + len(C.END)}}{vc}  {C.dim(note)}")

    print(f"\n{hr()}")
    print(f"  {C.bold('OPTION'):<{16 + len(C.BOLD) + len(C.END)}}{C.bold('VALUE')}")
    print(hr(color=C.DIM))
    row("target",     cfg.target,          "URL to enumerate")
    row("wordlist",   cfg.wordlist,         "path to wordlist file")
    row("threads",    cfg.threads,          "concurrent workers")
    row("timeout",    f"{cfg.timeout}s",    "request timeout")
    row("delay",      f"{cfg.delay}s",      "delay per thread between requests")
    row("extensions", ", ".join(cfg.extensions) or "none", "e.g. php,html,txt")
    row("status",     ", ".join(str(s) for s in sorted(cfg.status_ok)),
        "codes considered as hits")
    row("recursive",  cfg.recursive,
        f"auto-pivot on hits (max depth {cfg.max_depth})")
    row("max_depth",  cfg.max_depth,        "pivot recursion limit")
    row("useragent",  cfg.user_agent[:48],  "")
    print(hr())
    print()


def print_results_table(hits: list[dict]):
    if not hits:
        print(C.dim("  No hits recorded."))
        return

    # Dynamic column widths
    max_url = max((len(h["url"]) for h in hits), default=30)
    max_url = min(max_url, TERM_W - 32)

    print(f"\n{hr('=')}")
    print(f"{C.BOLD}{C.YELLOW}  RESULTS  —  {len(hits)} hits{C.END}")
    print(hr("="))
    print(f"  {C.bold('STATUS'):<{10 + len(C.BOLD) + len(C.END)}}"
          f"  {C.bold('SIZE'):>10}  "
          f"  {C.bold('TIME'):>8}  "
          f"  {C.bold('URL')}")
    print(hr(color=C.DIM))

    for h in hits:
        family = h["status"] // 100
        sc     = STATUS_COLOR.get(family, C.WHITE)
        redir  = (f"  {C.dim('→')} {C.dim(h['redirect'][:50])}"
                  if h.get("redirect") else "")
        url_s  = h["url"]
        if len(url_s) > max_url:
            url_s = "…" + url_s[-(max_url - 1):]
        print(f"  {sc}{C.BOLD}[{h['status']}]{C.END}"
              f"  {C.dim(str(h['size']) + ' B'):>12}"
              f"  {C.dim(str(h.get('elapsed_ms', 0)) + 'ms'):>9}"
              f"  {url_s}{redir}")

    print(hr("="))
    print()


def list_past_results():
    if not OUTPUT_DIR.exists():
        print(C.dim("  No results found."))
        return
    files = sorted(OUTPUT_DIR.glob("*.txt"), reverse=True)
    if not files:
        print(C.dim("  No result files found."))
        return
    print(f"\n{hr()}")
    print(f"  {C.bold('PAST SCANS')}  {C.dim(str(OUTPUT_DIR))}")
    print(hr(color=C.DIM))
    for i, f in enumerate(files[:20], 1):
        sz  = f.stat().st_size
        idx = f"{C.dim(str(i) + '.')}"
        print(f"  {idx:<{4 + len(C.DIM) + len(C.END)}}"
              f"  {C.g(f.name):<56}"
              f"  {C.dim(str(sz) + ' B')}")
    print(hr())
    print()


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
  Web Directory Enumeration Console  ·  CTF Edition{C.END}
{C.DIM}  Author: {C.BOLD}{C.WHITE}@ZetaOrioniss{C.END}   {C.DIM}Version: {C.BOLD}{C.WHITE}v1.1{C.END}
{C.DIM}
  Results: {C.END}{C.BOLD}{str(OUTPUT_DIR)}{C.END}
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
  {C.g('set extensions <a,b,...>')}   File extensions to append  (e.g. php,html,txt)
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
    d    = os.path.dirname(text) or "."
    base = os.path.basename(text)
    try:
        entries = os.listdir(d)
    except OSError:
        return []
    matches = []
    for e in entries:
        if e.startswith(base):
            full = os.path.join(d, e) if d != "." else e
            matches.append(
                full + "/" if os.path.isdir(os.path.join(d, e)) else full
            )
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
    tgt = session.cfg.target or "-"
    tgt = re.sub(r"https?://", "", tgt)[:32]
    run = C.g("●") if session.is_running() else C.dim("○")
    return (f"{C.BOLD}{C.RED}Anubis{C.END} "
            f"{run} "
            f"{C.dim(f'({tgt})')} "
            f"{C.BOLD}{C.GREEN}>{C.END} ")


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────

def run_console() -> None:
    print(BANNER)
    session = Session()

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
                        try:
                            wc = sum(1 for ln in open(p, errors="ignore")
                                     if ln.strip() and not ln.startswith("#"))
                        except Exception:
                            wc = "?"
                        print(f"  {C.dim('wordlist')} => {C.g(str(p))}"
                              f"  {C.dim('(' + str(wc) + ' words)')}")

                elif key == "threads":
                    try:
                        n = int(val)
                        if not 1 <= n <= 200:
                            raise ValueError
                        session.cfg.threads = n
                        print(f"  {C.dim('threads')} => {C.g(str(n))}")
                    except ValueError:
                        print(C.r("  [-] threads must be between 1 and 200"))

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
                        print(C.r("  [-] delay must be >= 0"))

                elif key == "extensions":
                    exts = [e.strip().lstrip(".")
                            for e in val.replace(",", " ").split()
                            if e.strip()]
                    session.cfg.extensions = exts
                    print(f"  {C.dim('extensions')} => {C.g(', '.join(exts) or 'none')}")

                elif key == "status":
                    try:
                        codes = {int(c.strip())
                                 for c in val.replace(",", " ").split()
                                 if c.strip()}
                        session.cfg.status_ok = codes
                        print(f"  {C.dim('status')} => "
                              f"{C.g(', '.join(str(c) for c in sorted(codes)))}")
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
                        print(C.r("  [-] depth must be between 1 and 10"))

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
                    session._scan_thread.join()  # type: ignore[union-attr]
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