#!/usr/bin/env python3
"""
recon_engine.py — Professional Reconnaissance Framework
AI-Ready Edition | High-Speed Async | Authorized Use Only
"""

import argparse
import asyncio
import contextlib
import dataclasses
import ipaddress
import json
import logging
import random
import re
import socket
import sys
import textwrap
import time
import urllib.parse
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp
import httpx

warnings.filterwarnings("ignore")

try:
    from aiohttp_socks import ProxyConnector as _SocksConnector
    _HAS_SOCKS = True
except ImportError:
    _HAS_SOCKS = False

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table

# ─────────────────────────────────────────────────────────────────────
#  Single shared Console — prevents double-render conflicts
# ─────────────────────────────────────────────────────────────────────
console = Console(highlight=False)

# ─────────────────────────────────────────────────────────────────────
#  Logging — file only (console output via console.log / Progress)
# ─────────────────────────────────────────────────────────────────────
_fh = logging.FileHandler("recon.log", mode="a", encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
log = logging.getLogger("recon_engine")
log.setLevel(logging.DEBUG)
log.addHandler(_fh)
log.propagate = False
for _lib in ("urllib3", "asyncio", "httpx", "httpcore", "aiohttp", "hpack"):
    logging.getLogger(_lib).setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────────
#  Runtime configuration (overridden by CLI args)
# ─────────────────────────────────────────────────────────────────────
TOOL_TIMEOUT:      int  = 300   # generic per-tool hard limit
HARVESTER_TIMEOUT: int  = 45    # dedicated limit for theHarvester
VALIDATE_TIMEOUT:  int  = 5     # per-host httpx timeout (connect + read)
VALIDATE_CONCUR:   int  = 150   # max concurrent validation tasks
DNS_PREFLIGHT_TO:  float = 2.5  # DNS pre-filter timeout per host
USE_TOR:           bool = False
TOR_SOCKS:         str  = "socks5h://127.0.0.1:9050"
TOR_CTRL_HOST:     str  = "127.0.0.1"
TOR_CTRL_PORT:     int  = 9051
TOR_CTRL_PASS:     str  = ""
_PROXY_ROTATOR:    "ProxyRotator | None" = None

# Photon static-asset exclusion regex (passed via --exclude)
PHOTON_EXCLUDE_RE: str = (
    r"\.(jpg|jpeg|png|gif|bmp|svg|ico|webp|tiff|"
    r"woff|woff2|ttf|eot|otf|"
    r"mp4|mp3|avi|mov|wmv|flv|"
    r"pdf|zip|tar|gz|7z|rar|exe|dmg)(\?[^\"]*)?$"
)

# ─────────────────────────────────────────────────────────────────────
#  User-Agent pool + randomiser
# ─────────────────────────────────────────────────────────────────────
_UAS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
]


def random_ua() -> str:
    return random.choice(_UAS)


# ─────────────────────────────────────────────────────────────────────
#  Proxy rotator (round-robin)
# ─────────────────────────────────────────────────────────────────────
class ProxyRotator:
    def __init__(self, proxies: list[str]) -> None:
        self._proxies = [p.strip() for p in proxies if p.strip()]
        self._idx = 0

    def __len__(self) -> int:
        return len(self._proxies)

    def next_str(self) -> Optional[str]:
        if not self._proxies:
            return None
        p = self._proxies[self._idx % len(self._proxies)]
        self._idx += 1
        return p

    def next_dict(self) -> Optional[dict]:
        p = self.next_str()
        return {"http": p, "https": p} if p else None

    @classmethod
    def from_file(cls, path: str) -> "ProxyRotator":
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        return cls([l for l in lines if l.strip() and not l.startswith("#")])


# ─────────────────────────────────────────────────────────────────────
#  Target resolution — parses any input form (URL, bare host, IP)
# ─────────────────────────────────────────────────────────────────────
def resolve_target(raw: str) -> dict:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw_for_parse = "https://" + raw
    else:
        raw_for_parse = raw
    parsed = urllib.parse.urlparse(raw_for_parse)
    host   = parsed.hostname or raw
    port   = parsed.port
    path   = parsed.path.rstrip("/") or "/"
    scheme = parsed.scheme.lower() or "https"
    url    = f"{scheme}://{host}" + (f":{port}" if port else "") + path

    resolved_ips: list[str] = []
    fqdn = host
    try:
        seen: set[str] = set()
        for item in socket.getaddrinfo(host, None):
            ip = item[4][0]
            if ip not in seen:
                seen.add(ip)
                resolved_ips.append(ip)
        fqdn = socket.getfqdn(host)
    except socket.gaierror as exc:
        log.warning(f"DNS resolution failed for {host}: {exc}")

    return {
        "input": raw, "host": host, "fqdn": fqdn,
        "url": url, "scheme": scheme, "port": port, "ips": resolved_ips,
    }


# ─────────────────────────────────────────────────────────────────────
#  Regex helpers
# ─────────────────────────────────────────────────────────────────────
_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_RE_IPV4  = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_IPV6  = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_RE_TITLE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.I | re.S)


def _is_public_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


def _extract_subdomains(text: str, domain: str) -> set[str]:
    pat = re.compile(r"\b((?:[a-zA-Z0-9\-]+\.)*" + re.escape(domain) + r")\b")
    return {m.lower() for m in pat.findall(text)}


# ─────────────────────────────────────────────────────────────────────
#  Tor helpers
# ─────────────────────────────────────────────────────────────────────
def check_tor_connectivity() -> bool:
    """Sync Tor pre-flight check via requests (runs before the event loop)."""
    import requests as _req  # local import — only used here
    try:
        resp = _req.get(
            "https://check.torproject.org/api/ip",
            proxies={"https": TOR_SOCKS.replace("socks5h", "socks5"),
                     "http":  TOR_SOCKS.replace("socks5h", "socks5")},
            timeout=20,
            headers={"User-Agent": random_ua()},
        )
        data      = resp.json()
        ip, is_tor = data.get("IP", "?"), data.get("IsTor", False)
        log.info(f"Tor check — exit IP: {ip} | IsTor: {is_tor}")
        console.log(
            f"[bold]Tor check[/bold]: exit IP [cyan]{ip}[/cyan] | "
            f"Anonymous: {'[green]YES[/green]' if is_tor else '[red]NO[/red]'}"
        )
        return bool(is_tor)
    except Exception as exc:
        log.error(f"Tor connectivity check failed: {exc}")
        console.log(f"[red]Tor check failed:[/red] {exc}")
        return False


def renew_tor_circuit() -> bool:
    """Send SIGNAL NEWNYM via stem (falls back to raw socket)."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(address=TOR_CTRL_HOST, port=TOR_CTRL_PORT) as c:
            c.authenticate(password=TOR_CTRL_PASS) if TOR_CTRL_PASS else c.authenticate()
            c.signal(Signal.NEWNYM)
            log.info("Tor circuit renewed (stem NEWNYM)")
            time.sleep(1)
            return True
    except ImportError:
        pass
    except Exception as exc:
        log.warning(f"stem NEWNYM failed: {exc}")
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((TOR_CTRL_HOST, TOR_CTRL_PORT))
        s.send((f'AUTHENTICATE "{TOR_CTRL_PASS}"\r\n' if TOR_CTRL_PASS
                else b'AUTHENTICATE ""\r\n'))
        s.recv(1024)
        s.send(b"SIGNAL NEWNYM\r\n")
        s.recv(1024)
        s.close()
        log.info("Tor circuit renewed (raw socket NEWNYM)")
        time.sleep(1)
        return True
    except Exception as exc:
        log.error(f"NEWNYM raw socket failed: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────────
#  aiohttp session factory (used for crt.sh)
#  Tor → aiohttp_socks.ProxyConnector | proxy-list → SocksConnector
#  plain → aiohttp.TCPConnector
# ─────────────────────────────────────────────────────────────────────
@contextlib.asynccontextmanager
async def aiohttp_session(proxy_str: Optional[str] = None):
    connector: aiohttp.BaseConnector
    if USE_TOR and _HAS_SOCKS:
        connector = _SocksConnector.from_url(TOR_SOCKS, rdns=True)
    elif proxy_str and _HAS_SOCKS and proxy_str.startswith("socks"):
        connector = _SocksConnector.from_url(proxy_str, rdns=True)
    else:
        connector = aiohttp.TCPConnector()

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=TOOL_TIMEOUT),
        headers={"User-Agent": random_ua()},
    ) as sess:
        yield sess


# ─────────────────────────────────────────────────────────────────────
#  SubdomainRecord — validated state for one host
# ─────────────────────────────────────────────────────────────────────
@dataclasses.dataclass
class SubdomainRecord:
    host:       str
    port_80:    bool       = False
    port_443:   bool       = False
    status_80:  int | None = None
    status_443: int | None = None
    title:      str | None = None
    redirect:   str | None = None
    alive:      bool       = False

    def open_port_count(self) -> int:
        return int(self.port_80) + int(self.port_443)

    def best_url(self) -> Optional[str]:
        if self.port_443:
            return f"https://{self.host}"
        if self.port_80:
            return f"http://{self.host}"
        return None

    def to_dict(self) -> dict:
        return {
            "status": {
                "alive":      self.alive,
                "port_80":    self.port_80,
                "port_443":   self.port_443,
                "http_code":  self.status_80,
                "https_code": self.status_443,
            },
            "metadata": {
                "title":    self.title,
                "redirect": self.redirect,
                "best_url": self.best_url(),
            },
        }


# ─────────────────────────────────────────────────────────────────────
#  DNS pre-filter — discard hosts with no A/AAAA record before HTTP
# ─────────────────────────────────────────────────────────────────────
async def _dns_resolves(host: str) -> bool:
    """Return True if *host* resolves in DNS within DNS_PREFLIGHT_TO seconds."""
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, host, None),
            timeout=DNS_PREFLIGHT_TO,
        )
        return True
    except Exception:
        return False


async def dns_preflight(
    domains: list[str],
    progress: Progress,
) -> list[str]:
    """
    Resolve all domains in parallel and return only those that have
    a DNS record.  Runs before HTTP validation to avoid spending
    VALIDATE_TIMEOUT on definitively dead hosts.
    """
    if not domains:
        return []
    task_id = progress.add_task(
        f"[cyan]DNS pre-filter ({len(domains)} hosts)", total=len(domains)
    )
    checks = await asyncio.gather(
        *[_dns_resolves(d) for d in domains], return_exceptions=True
    )
    live: list[str] = []
    for domain, ok in zip(domains, checks):
        if ok is True:
            live.append(domain)
        progress.advance(task_id)

    progress.update(
        task_id,
        description=f"[green]DNS pre-filter ({len(live)}/{len(domains)} resolve)",
    )
    log.info(f"DNS pre-filter: {len(live)}/{len(domains)} hosts resolve")
    return live


# ─────────────────────────────────────────────────────────────────────
#  Async httpx validation layer
#  Checks port 80/443, captures HTTP status + page title per host.
#  https and http probed in parallel; sleep only when Tor is active.
# ─────────────────────────────────────────────────────────────────────
async def _probe_scheme(
    client: httpx.AsyncClient,
    host: str,
    scheme: str,
) -> tuple[bool, int | None, str | None, str | None]:
    """
    Probe one scheme (http or https) against *host*.
    Returns (reachable, status_code, page_title, final_url_if_redirected).
    """
    try:
        r = await client.get(
            f"{scheme}://{host}",
            headers={"User-Agent": random_ua()},
            timeout=httpx.Timeout(VALIDATE_TIMEOUT),
        )
        title: str | None = None
        m = _RE_TITLE.search(r.text)
        if m:
            title = " ".join(m.group(1).split())[:100]
        redirect = str(r.url) if r.history else None
        return True, r.status_code, title, redirect
    except (httpx.ConnectError, httpx.TimeoutException,
            httpx.RemoteProtocolError, httpx.ReadError):
        return False, None, None, None
    except Exception as exc:
        log.debug(f"validate[{host}][{scheme}]: {type(exc).__name__}: {exc}")
        return False, None, None, None


async def _validate_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    host: str,
) -> SubdomainRecord:
    rec = SubdomainRecord(host=host)
    async with sem:
        # Only add jitter when routing through Tor to avoid circuit fingerprinting.
        # Plain validation needs no artificial delay.
        if USE_TOR:
            await asyncio.sleep(random.uniform(0.05, 0.2))

        # Probe https and http simultaneously — cuts per-host time in half
        (ok_s, code_s, title_s, redir_s), (ok_h, code_h, title_h, redir_h) = (
            await asyncio.gather(
                _probe_scheme(client, host, "https"),
                _probe_scheme(client, host, "http"),
            )
        )
        if ok_s:
            rec.port_443   = True
            rec.status_443 = code_s
            rec.alive      = True
            rec.title      = rec.title or title_s
            rec.redirect   = rec.redirect or redir_s
        if ok_h:
            rec.port_80   = True
            rec.status_80 = code_h
            rec.alive     = True
            rec.title     = rec.title or title_h
            rec.redirect  = rec.redirect or redir_h
    return rec


async def validate_all(
    domains: list[str],
    progress: Progress,
) -> dict[str, SubdomainRecord]:
    """
    Two-stage validation pipeline:
      1. DNS pre-filter  — parallel getaddrinfo, drops unresolvable hosts
      2. HTTP validation — parallel httpx probes (https + http simultaneously)
    """
    if not domains:
        return {}

    # ── Stage 1: DNS pre-filter ──────────────────────────────────────
    live_domains = await dns_preflight(domains, progress)
    # Hosts that didn't resolve are kept in results as dead records
    dead = set(domains) - set(live_domains)

    if not live_domains:
        log.info("DNS pre-filter: no hosts resolved — skipping HTTP validation")
        return {h: SubdomainRecord(host=h) for h in domains}

    # ── Stage 2: HTTP validation ─────────────────────────────────────
    sem = asyncio.Semaphore(VALIDATE_CONCUR)
    client_kwargs: dict = {
        "verify": False,
        "follow_redirects": True,
        "timeout": httpx.Timeout(VALIDATE_TIMEOUT),
        # Connection pool sized to match concurrency
        "limits": httpx.Limits(
            max_connections=VALIDATE_CONCUR + 50,
            max_keepalive_connections=VALIDATE_CONCUR,
            keepalive_expiry=5,
        ),
    }
    if USE_TOR:
        client_kwargs["proxies"] = {"all://": "socks5://127.0.0.1:9050"}
    elif _PROXY_ROTATOR:
        px = _PROXY_ROTATOR.next_dict()
        if px:
            client_kwargs["proxies"] = px

    val_task = progress.add_task(
        f"[bold magenta]HTTP validate ({len(live_domains)} live)",
        total=len(live_domains),
    )

    results: dict[str, SubdomainRecord] = {h: SubdomainRecord(host=h) for h in dead}

    async with httpx.AsyncClient(**client_kwargs) as client:
        async def _run_one(host: str) -> tuple[str, SubdomainRecord]:
            rec = await _validate_one(client, sem, host)
            progress.advance(val_task)
            return host, rec

        gathered = await asyncio.gather(
            *[_run_one(d) for d in live_domains],
            return_exceptions=True,
        )

    for item in gathered:
        if isinstance(item, tuple):
            host, rec = item
            results[host] = rec
        else:
            log.warning(f"validate gather exception: {item}")

    alive = sum(1 for r in results.values() if r.alive)
    log.info(f"Validation complete: {alive}/{len(domains)} alive")
    progress.update(
        val_task,
        description=f"[green]HTTP validate ({alive} alive / {len(dead)} no-DNS)",
    )
    return results


# ─────────────────────────────────────────────────────────────────────
#  Async subprocess runner (optionally prepends torsocks)
# ─────────────────────────────────────────────────────────────────────
async def run_tool(
    name: str,
    cmd: list[str],
    timeout: Optional[int] = None,
) -> tuple[str, str | None]:
    effective_timeout = timeout if timeout is not None else TOOL_TIMEOUT
    effective_cmd     = (["torsocks"] + cmd) if USE_TOR else cmd
    try:
        proc = await asyncio.create_subprocess_exec(
            *effective_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(), timeout=effective_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            msg = f"{name} timed out after {effective_timeout}s"
            log.warning(msg)
            return "", msg
        stdout = out_b.decode(errors="replace").strip()
        stderr = err_b.decode(errors="replace").strip()
        if proc.returncode != 0 and not stdout:
            msg = f"{name} exited {proc.returncode}: {stderr[:300]}"
            log.warning(msg)
            return stdout, msg
        return stdout, None
    except FileNotFoundError:
        msg = f"{name}: '{effective_cmd[0]}' not found — install it or check PATH"
        log.error(msg)
        return "", msg
    except Exception as exc:
        msg = f"{name} unexpected error: {exc}"
        log.exception(msg)
        return "", msg


# ─────────────────────────────────────────────────────────────────────
#  Partial parser — fires immediately when a tool finishes first
# ─────────────────────────────────────────────────────────────────────
def _parse_partial(name: str, stdout: str, host: str) -> dict:
    subs   = _extract_subdomains(stdout, host)
    ips    = {ip for ip in _RE_IPV4.findall(stdout) if _is_public_ip(ip)}
    ips   |= {ip for ip in _RE_IPV6.findall(stdout) if _is_public_ip(ip)}
    emails = {e.lower() for e in _RE_EMAIL.findall(stdout)}
    log.info(
        f"[partial/{name}] subs={len(subs)} ips={len(ips)} emails={len(emails)}"
    )
    return {"subdomains": subs, "ips": ips, "emails": emails}


# ─────────────────────────────────────────────────────────────────────
#  crt.sh via aiohttp — async, retries with backoff, Tor-aware
# ─────────────────────────────────────────────────────────────────────
async def run_crt_sh(
    target: str,
    session: aiohttp.ClientSession,
    max_retries: int = 5,
) -> tuple[str, str | None]:
    """
    Query crt.sh certificate transparency logs.
    Uses 5 retries with progressive backoff (5 → 10 → 20 → 40 → 60 s)
    to handle transient 503 / overload responses.
    """
    url = f"https://crt.sh/?q=%.{target}&output=json"
    # Full browser-like headers reduce the chance of being served an error page
    headers = {
        "Accept":          "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
        "User-Agent":      random_ua(),
    }
    last_err = ""
    for attempt in range(1, max_retries + 1):
        # Small jitter on first attempt; larger backoff only on retries
        jitter = random.uniform(0.05, 0.2) if attempt == 1 else random.uniform(0.3, 0.8)
        await asyncio.sleep(jitter)
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status in (403, 429) and USE_TOR:
                    log.warning(f"crt.sh HTTP {resp.status} — renewing Tor circuit")
                    renew_tor_circuit()
                    wait = min(60, 5 * (2 ** (attempt - 1)))
                    await asyncio.sleep(wait)
                    headers["User-Agent"] = random_ua()
                    continue

                if resp.status in (429, 500, 502, 503, 504):
                    wait = min(60, 5 * (2 ** (attempt - 1)))  # 5, 10, 20, 40, 60
                    log.warning(
                        f"crt.sh HTTP {resp.status} "
                        f"(attempt {attempt}/{max_retries}) — retry in {wait}s"
                    )
                    await asyncio.sleep(wait)
                    headers["User-Agent"] = random_ua()
                    continue

                if resp.status != 200:
                    last_err = f"crt.sh unexpected HTTP {resp.status}"
                    log.warning(last_err)
                    await asyncio.sleep(min(60, 5 * (2 ** (attempt - 1))))
                    continue

                try:
                    entries = await resp.json(content_type=None)
                except Exception as exc:
                    last_err = f"crt.sh JSON parse error: {exc}"
                    log.warning(last_err)
                    await asyncio.sleep(min(60, 5 * (2 ** (attempt - 1))))
                    continue

                lines: list[str] = []
                for entry in entries:
                    for sub in entry.get("name_value", "").splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub:
                            lines.append(sub)
                log.info(f"crt.sh: {len(entries)} certificate entries")
                return "\n".join(lines), None

        except asyncio.TimeoutError:
            last_err = f"crt.sh timed out (attempt {attempt}/{max_retries})"
            log.warning(last_err)
            await asyncio.sleep(min(60, 5 * (2 ** (attempt - 1))))
        except aiohttp.ClientError as exc:
            last_err = f"crt.sh client error: {exc}"
            log.error(last_err)
            await asyncio.sleep(min(60, 5 * (2 ** (attempt - 1))))

    return "", last_err or "crt.sh failed after all retries"


# ─────────────────────────────────────────────────────────────────────
#  Orchestrator — all tools in parallel via asyncio.gather
#  theHarvester + Photon have a done-callback for immediate partial parse
# ─────────────────────────────────────────────────────────────────────
async def orchestrate(
    target: str,
    http: aiohttp.ClientSession,
) -> tuple[dict[str, str], dict[str, str]]:
    raw:  dict[str, str] = {}
    errs: dict[str, str] = {}

    # ── Command definitions ──────────────────────────────────────────
    tool_defs: dict[str, tuple[list[str], Optional[int]]] = {
        "theHarvester": (
            ["theHarvester", "-d", target, "-b", "bing,crtsh,duckduckgo", "-n"],
            HARVESTER_TIMEOUT,
        ),
        "photon": (
            ["photon", "-u", target, "--wayback",
             "--level", "1", "--threads", "100",
             "--exclude", PHOTON_EXCLUDE_RE],
            None,
        ),
        "subfinder": (["subfinder", "-d", target, "-silent", "-t", "100"], None),
        "dig":       (["dig", "ANY", target, "+short"],        None),
        "whois":     (["whois", target],                        None),
    }
    total_tools = len(tool_defs) + 1  # +1 for crt.sh

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description:<26}"),
        BarColumn(bar_width=26),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:

        overall = progress.add_task("[bold green]Recon Pipeline", total=total_tools)

        # Create one asyncio.Task per tool (true parallel execution)
        tasks:    dict[str, asyncio.Task] = {}
        prog_ids: dict[str, int]          = {}

        for name, (cmd, tmt) in tool_defs.items():
            pid = progress.add_task(f"[yellow]{name}", total=1)
            prog_ids[name] = pid
            tasks[name] = asyncio.create_task(run_tool(name, cmd, timeout=tmt))

        # crt.sh uses the shared aiohttp session
        crt_pid = progress.add_task("[yellow]crt.sh", total=1)
        prog_ids["crt.sh"] = crt_pid
        tasks["crt.sh"] = asyncio.create_task(run_crt_sh(target, http))

        # ── Partial-parse callbacks for photon + theHarvester ────────
        # The first of the two to finish immediately extracts findings
        # without blocking on the slower sibling.
        def _on_fast_done(name: str, task: asyncio.Task) -> None:
            if task.cancelled():
                return
            exc = task.exception()
            if exc:
                return
            stdout, err = task.result()
            if stdout and not err:
                partial = _parse_partial(name, stdout, target)
                log.info(
                    f"[{name}] finished early → partial: "
                    f"{len(partial['subdomains'])} subs, "
                    f"{len(partial['ips'])} IPs"
                )

        for name in ("photon", "theHarvester"):
            tasks[name].add_done_callback(
                lambda t, n=name: _on_fast_done(n, t)
            )

        # ── asyncio.gather — all tools run in true parallel ──────────
        names   = list(tasks.keys())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, result in zip(names, results):
            pid = prog_ids[name]
            if isinstance(result, Exception):
                errs[name] = str(result)
                log.error(f"[{name}] gather exception: {result}")
                colour = "red"
            else:
                stdout, err = result
                raw[name] = stdout
                if err:
                    errs[name] = err
                colour = "red" if name in errs else "green"
            progress.update(pid, completed=1, description=f"[{colour}]{name}")
            progress.advance(overall)

    return raw, errs


# ─────────────────────────────────────────────────────────────────────
#  Data normalisation
# ─────────────────────────────────────────────────────────────────────
def normalise(
    target_info: dict,
    raw: dict[str, str],
    validated: Optional[dict[str, SubdomainRecord]] = None,
) -> dict:
    host = target_info["host"]
    subs:   set[str] = set()
    ips:    set[str] = set(target_info["ips"])
    emails: set[str] = set()

    for text in raw.values():
        if not text:
            continue
        subs   |= _extract_subdomains(text, host)
        for ip in _RE_IPV4.findall(text):
            if _is_public_ip(ip):
                ips.add(ip)
        for ip in _RE_IPV6.findall(text):
            if _is_public_ip(ip):
                ips.add(ip)
        emails |= {e.lower() for e in _RE_EMAIL.findall(text)}

    if subs:
        subs.add(host)

    return {
        "target":     host,
        "fqdn":       target_info["fqdn"],
        "url":        target_info["url"],
        "resolved":   target_info["ips"],
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "subdomains": sorted(subs),
        "ips":        sorted(ips),
        "emails":     sorted(emails),
        "validated":  validated or {},
    }


# ─────────────────────────────────────────────────────────────────────
#  Report generators
# ─────────────────────────────────────────────────────────────────────

# ── JSON — hierarchical AI-ready structure ───────────────────────────
def write_json(data: dict, errors: dict, raw: dict) -> Path:
    target    = data["target"]
    validated = data.get("validated", {})
    alive     = sum(1 for r in validated.values() if r.alive)

    # Build subdomain hierarchy: Target → Subdomains → Status → Metadata
    subs_section: dict[str, dict] = {}
    for sub in data["subdomains"]:
        rec = validated.get(sub)
        subs_section[sub] = rec.to_dict() if rec else {
            "status": {"alive": None, "port_80": None, "port_443": None,
                       "http_code": None, "https_code": None},
            "metadata": {"title": None, "redirect": None, "best_url": None},
        }

    payload = {
        "meta": {
            "target":       data["target"],
            "fqdn":         data["fqdn"],
            "url":          data["url"],
            "resolved_ips": data["resolved"],
            "timestamp":    data["timestamp"],
        },
        "summary": {
            "total_subdomains": len(data["subdomains"]),
            "alive_hosts":      alive,
            "total_ips":        len(data["ips"]),
            "total_emails":     len(data["emails"]),
            "ips":              data["ips"],
            "emails":           data["emails"],
        },
        "subdomains": subs_section,
        "raw": {
            "whois": raw.get("whois", ""),
            "dig":   raw.get("dig",   ""),
        },
        "errors": errors,
    }
    path = Path(f"report_{target}.json")
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# ── Markdown — tables with clickable links ───────────────────────────
def write_markdown(data: dict, errors: dict, raw: dict) -> Path:
    target    = data["target"]
    validated = data.get("validated", {})
    alive = sum(1 for r in validated.values() if r.alive)

    def _code(text: str) -> list[str]:
        return ["```", text.strip() if text and text.strip() else "(no output)", "```"]

    # Separate alive vs dead for the table
    alive_rows: list[str] = []
    dead_rows:  list[str] = []
    for sub in sorted(data["subdomains"]):
        rec = validated.get(sub)
        if rec and rec.alive:
            http_s  = f"`{rec.status_80}`"  if rec.status_80  else "—"
            https_s = f"`{rec.status_443}`" if rec.status_443 else "—"
            title   = (rec.title or "—").replace("|", "\\|")
            link    = f"[{sub}]({rec.best_url()})"
            alive_rows.append(f"| {link} | {http_s} | {https_s} | {title} |")
        else:
            dead_rows.append(f"| `{sub}` | — | — | *(unresponsive)* |")

    tbl_header = [
        "| Subdomain | HTTP | HTTPS | Title |",
        "|-----------|:----:|:-----:|-------|",
    ]
    sub_table = tbl_header + alive_rows + dead_rows if (alive_rows or dead_rows) \
                else ["_None found_"]

    lines: list[str] = [
        f"# Recon Report — `{target}`",
        "",
        "## Target Info",
        "| Field | Value |",
        "|-------|-------|",
        f"| **FQDN** | `{data['fqdn']}` |",
        f"| **URL** | <{data['url']}> |",
        f"| **Resolved IPs** | {', '.join(f'`{ip}`' for ip in data['resolved']) or '—'} |",
        f"| **Alive Hosts** | {alive} / {len(data['subdomains'])} |",
        f"| **Generated** | `{data['timestamp']}` |",
        "",
        "## Subdomains",
        *sub_table,
        "",
        "## IP Addresses",
        *([f"- `{ip}`" for ip in data["ips"]] or ["_None found_"]),
        "",
        "## Email Addresses",
        *([f"- `{e}`" for e in data["emails"]] or ["_None found_"]),
        "",
        "## WHOIS",
        *_code(raw.get("whois", "")),
        "",
        "## DIG (ANY)",
        *_code(raw.get("dig", "")),
        "",
    ]
    if errors:
        lines += [
            "## Tool Errors",
            *[f"- **{k}**: {v}" for k, v in errors.items()],
            "",
        ]
    lines += ["---", "_Generated by recon\\_engine.py — Authorized use only._"]
    path = Path(f"report_{target}.md")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ── Toon — ASCII art with Threat Level meter ─────────────────────────
def write_toon(data: dict, errors: dict, raw: dict) -> Path:
    target    = data["target"]
    validated = data.get("validated", {})
    alive      = sum(1 for r in validated.values() if r.alive)
    open_ports = sum(r.open_port_count() for r in validated.values())
    subs  = data["subdomains"]
    ips   = data["ips"]
    mails = data["emails"]

    BANNER = r"""
  ____  _____ ____ ___  _   _   ___  _   _  ____ ___ _   _ _____
 |  _ \| ____/ ___/ _ \| \ | | | __|| \ | |/ ___|_ _| \ | | ____|
 | |_) |  _|| |  | | | |  \| | |  _||  \| | |  _ | ||  \| |  _|
 |  _ <| |__| |__| |_| | |\  | | |__| |\  | |_| || || |\  | |___
 |_| \_\_____\____\___/|_| \_| |___|_| \_|\____|___|_| \_|_____|
    """

    W    = 64
    DIV  = "=" * W
    HDIV = "-" * W

    def _box(title: str, items: list[str], icon: str = ">>") -> str:
        bar = "+" + "-" * (W - 2) + "+"
        hdr = f"| {icon}  {title:<{W - 6}} |"
        body: list[str] = []
        for item in items[:30]:
            for k, chunk in enumerate(textwrap.wrap(item, W - 6)):
                pfx = "   " if k else "  * "
                body.append(f"|{pfx}{chunk:<{W - len(pfx) - 2}} |")
        if not items:
            body.append(f"|  {'(none discovered)':<{W - 4}} |")
        if len(items) > 30:
            body.append(f"|  {'... and ' + str(len(items) - 30) + ' more':<{W - 4}} |")
        return "\n".join([bar, hdr, bar] + body + [bar])

    def _alive_box() -> str:
        bar = "+" + "-" * (W - 2) + "+"
        hdr = f"| [+] {'VALIDATED LIVE HOSTS':<{W - 7}} |"
        body: list[str] = []
        alive_recs = sorted(
            [(h, r) for h, r in validated.items() if r.alive],
            key=lambda x: x[0],
        )
        for host, rec in alive_recs[:25]:
            ports = " | ".join(filter(None, [
                f"HTTP:{rec.status_80}"  if rec.port_80  else "",
                f"SSL:{rec.status_443}"  if rec.port_443 else "",
            ]))
            title = f" \"{rec.title[:28]}\"" if rec.title else ""
            line  = f"{host}  [{ports}]{title}"
            for k, chunk in enumerate(textwrap.wrap(line, W - 6)):
                pfx = "   " if k else "  + "
                body.append(f"|{pfx}{chunk:<{W - len(pfx) - 2}} |")
        if not alive_recs:
            body.append(f"|  {'(no live hosts found)':<{W - 4}} |")
        if len(alive_recs) > 25:
            body.append(f"|  {'... and ' + str(len(alive_recs) - 25) + ' more':<{W - 4}} |")
        return "\n".join([bar, hdr, bar] + body + [bar])

    def _raw_box(title: str, text: str, icon: str) -> str:
        bar  = "+" + "-" * (W - 2) + "+"
        hdr  = f"| {icon}  {title:<{W - 6}} |"
        body: list[str] = []
        raw_lines = text.strip().splitlines() if text and text.strip() else ["(no output)"]
        for line in raw_lines[:50]:
            for chunk in (textwrap.wrap(line, W - 4) or [""]):
                body.append(f"|  {chunk:<{W - 4}} |")
        if len(raw_lines) > 50:
            body.append(f"|  {'[truncated — see report .json]':<{W - 4}} |")
        return "\n".join([bar, hdr, bar] + body + [bar])

    err_section = ""
    if errors:
        lines = [f"\n{'!' * W}", "[!] TOOL ERRORS — full details in recon.log:"]
        for k, v in errors.items():
            lines.append(f"    [{k}] {v[:72]}")
        err_section = "\n".join(lines)

    content = "\n".join([
        BANNER,
        DIV,
        f"  Target   : {target}",
        f"  FQDN     : {data['fqdn']}",
        f"  URL      : {data['url']}",
        f"  Resolved : {', '.join(data['resolved']) or 'n/a'}",
        f"  Timestamp: {data['timestamp']}",
        HDIV,
        f"  Subdomains: {len(subs):>4}    IPs: {len(ips):>4}    Emails: {len(mails):>4}",
        f"  Alive:      {alive:>4}    Open ports: {open_ports:>4}",
        DIV,
        "",
        _alive_box(),
        "",
        _box("ALL SUBDOMAINS",  subs,  icon=">>"),
        "",
        _box("IP ADDRESSES",    ips,   icon="##"),
        "",
        _box("EMAIL ADDRESSES", mails, icon="@@"),
        "",
        _raw_box("WHOIS",     raw.get("whois", ""), icon="~~"),
        "",
        _raw_box("DIG (ANY)", raw.get("dig",   ""), icon="::"),
        err_section,
        "",
        DIV,
        "  [*] Stay legal. Recon responsibly. Authorized engagements only.",
        "  [*] recon_engine.py — AI-Ready Professional Edition",
        DIV,
    ])
    path = Path(f"report_{target}.toon")
    path.write_text(content, encoding="utf-8")
    return path


# ─────────────────────────────────────────────────────────────────────
#  Rich summary table
# ─────────────────────────────────────────────────────────────────────
def print_summary(data: dict, errors: dict) -> None:
    validated  = data.get("validated", {})
    alive      = sum(1 for r in validated.values() if r.alive)
    open_ports = sum(r.open_port_count() for r in validated.values())

    table = Table(
        title=f"[bold]Recon Summary — {data['target']}[/bold]",
        show_lines=True,
    )
    table.add_column("Category", style="cyan bold", min_width=18)
    table.add_column("Count",    style="magenta",   justify="right")

    rows = [
        ("Subdomains",  len(data["subdomains"])),
        ("Alive hosts", alive),
        ("Open ports",  open_ports),
        ("IPs",         len(data["ips"])),
        ("Emails",      len(data["emails"])),
    ]
    for label, count in rows:
        table.add_row(label, str(count))

    if errors:
        table.add_row("[red]Errors[/red]", str(len(errors)))

    console.print(table)


# ─────────────────────────────────────────────────────────────────────
#  CLI argument parsing
# ─────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon_engine",
        description="Professional async recon framework — authorized use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python3 recon_engine.py example.com
              python3 recon_engine.py https://target.org --timeout 120
              python3 recon_engine.py target.com --tor
              python3 recon_engine.py target.com --proxy-list proxies.txt
              python3 recon_engine.py target.com --no-validate
        """),
    )
    p.add_argument("target",      help="Target domain, hostname, or URL")
    p.add_argument("--timeout",   type=int, default=300,
                   help="Per-tool timeout in seconds (default: 300)")
    p.add_argument("--no-validate", action="store_true",
                   help="Skip httpx validation phase (faster, fewer findings)")

    anon = p.add_argument_group("anonymity")
    anon.add_argument(
        "--tor", dest="use_tor", action="store_true",
        help="Route HTTP via Tor SOCKS5 (aiohttp_socks + httpx) "
             "and prepend torsocks to subprocesses",
    )
    anon.add_argument("--tor-password", default="", metavar="PASS",
                      help="Tor control port password (default: none)")
    anon.add_argument(
        "--proxy-list", metavar="FILE",
        help="Newline-separated SOCKS5/HTTP proxy list; rotated per tool",
    )
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────
#  Entry point — three-phase pipeline: Recon → Validate → Report
# ─────────────────────────────────────────────────────────────────────
async def main() -> None:
    global TOOL_TIMEOUT, USE_TOR, TOR_CTRL_PASS, _PROXY_ROTATOR

    args          = parse_args()
    TOOL_TIMEOUT  = args.timeout
    USE_TOR       = args.use_tor
    TOR_CTRL_PASS = args.tor_password

    if args.proxy_list:
        _PROXY_ROTATOR = ProxyRotator.from_file(args.proxy_list)
        console.log(f"[cyan]Proxy rotator:[/cyan] {len(_PROXY_ROTATOR)} proxies loaded")

    if USE_TOR and not _HAS_SOCKS:
        console.print(
            "[yellow]WARNING:[/yellow] aiohttp_socks not installed — "
            "Tor routing unavailable for HTTP calls. "
            "Run: pip install aiohttp-socks"
        )

    target_info = resolve_target(args.target)
    host        = target_info["host"]

    tor_status = (
        "[green]ON (aiohttp_socks)[/green]" if (USE_TOR and _HAS_SOCKS)
        else "[yellow]ON (no socks lib)[/yellow]" if USE_TOR
        else "[dim]off[/dim]"
    )
    console.print(Panel(
        f"[bold green]Recon Engine[/bold green] — [bold yellow]{host}[/bold yellow]\n"
        f"FQDN     : [cyan]{target_info['fqdn']}[/cyan]\n"
        f"URL      : [cyan]{target_info['url']}[/cyan]\n"
        f"Resolved : [cyan]{', '.join(target_info['ips']) or 'unresolved'}[/cyan]\n"
        f"Timeout  : [cyan]{TOOL_TIMEOUT}s[/cyan]  |  Tor: {tor_status}  |  "
        f"Proxies: {('[green]' + str(len(_PROXY_ROTATOR)) + '[/green]') if _PROXY_ROTATOR else '[dim]none[/dim]'}\n"
        f"[dim]{datetime.now(timezone.utc).isoformat()}[/dim]",
        title="[bold]recon_engine.py — AI-Ready Professional Edition[/bold]",
        border_style="bright_blue",
    ))

    # Tor pre-flight
    if USE_TOR:
        console.rule("[bold yellow]Tor Connectivity Check[/bold yellow]")
        if not check_tor_connectivity():
            console.print(
                "[bold red]WARNING:[/bold red] Tor anonymity unconfirmed — "
                "traffic may not be anonymised."
            )
        console.rule()

    # ── Phase 1: Recon ───────────────────────────────────────────────
    console.rule("[bold]Phase 1 — Recon[/bold]")
    px_str = _PROXY_ROTATOR.next_str() if _PROXY_ROTATOR else None
    async with aiohttp_session(proxy_str=px_str) as http:
        raw_outputs, errors = await orchestrate(host, http)

    data = normalise(target_info, raw_outputs)

    # ── Phase 2: Validation (httpx layer) ────────────────────────────
    validated: dict[str, SubdomainRecord] = {}
    if not args.no_validate and data["subdomains"]:
        console.rule("[bold]Phase 2 — Validation (httpx)[/bold]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description:<30}"),
            BarColumn(bar_width=24),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
            redirect_stdout=False,
            redirect_stderr=False,
        ) as val_progress:
            validated = await validate_all(data["subdomains"], val_progress)
    else:
        console.print("[dim]Validation skipped (--no-validate)[/dim]")

    data["validated"] = validated

    # ── Phase 3: Reports ─────────────────────────────────────────────
    console.rule("[bold]Phase 3 — Reports[/bold]")
    p_json = write_json(data, errors, raw_outputs)
    p_md   = write_markdown(data, errors, raw_outputs)
    p_toon = write_toon(data, errors, raw_outputs)

    print_summary(data, errors)

    console.print(
        f"\n[bold]Reports written:[/bold]\n"
        f"  [green]{p_json}[/green]\n"
        f"  [green]{p_md}[/green]\n"
        f"  [green]{p_toon}[/green]\n"
        f"  [dim]recon.log[/dim]"
    )

    if errors:
        console.print(
            f"[yellow]{len(errors)} tool(s) reported errors — see recon.log[/yellow]"
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)
