#!/usr/bin/env python3
"""fetch_subs — download v2ray subscription URLs into raw/.

Reads the `subscriptions:` list from config/links.yaml, downloads each URL
into raw/, and auto-detects/decodes base64-encoded subscriptions before
saving. Plain-text subscriptions, JSON (nekobox) and other plaintext are
saved verbatim; HTML pages (github repo cards, telegram channel pages) are
detected and skipped.

Base64 detection is conservative: the *entire* body (whitespace collapsed)
must be pure base64 charset AND decode to UTF-8 containing a `://` scheme.
This never mis-decodes plain `vmess://…` text (it contains `:` outside the
base64 alphabet), JSON, or HTML.

Usage:  python3 lib/fetch_subs.py            # all subscriptions
        python3 lib/fetch_subs.py --limit N  # first N (for testing)
        python3 lib/fetch_subs.py --workers 8

Override the output dir with FETCH_RAW_DIR (default: ./raw).
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parent.parent  # project root (parent of lib/)
CONFIG = ROOT / "config" / "links.yaml"
OUT = Path(os.environ.get("FETCH_RAW_DIR", ROOT / "raw"))

UA = "fetch-subs/1.0"
TIMEOUT = 15           # seconds per attempt
RETRIES = 2            # extra attempts after the first
WORKERS = 8

_PURE_B64 = re.compile(r"[A-Za-z0-9+/=]+")
_SCHEME = re.compile(r"://")
_HTML = re.compile(r"<\s*(html|head|body|!doctype)", re.I)


# -------------------------------------------------------------------------- #
# URL policy
# -------------------------------------------------------------------------- #

def skip_url(url: str) -> bool:
    """True for URLs we know return HTML, not a subscription."""
    p = url.split("#", 1)[0]
    try:
        parsed = urlparse(p)
    except ValueError:
        return False
    netloc = parsed.netloc
    segs = [s for s in parsed.path.split("/") if s]
    # telegram channel message pages -> HTML
    if netloc.startswith("telegram.me") and segs[:1] == ["s"]:
        return True
    # bare github.com/<owner>/<repo> (repo card) -> HTML
    if netloc == "github.com" and len(segs) == 2:
        return True
    return False


def fname_for(url: str, index: int, seen: set[str]) -> str:
    """Readable, collision-free filename for a subscription URL."""
    p = url.split("#", 1)[0].split("?", 1)[0]
    try:
        parsed = urlparse(p)
    except ValueError:
        parsed = urlparse(url)
    segs = [s for s in parsed.path.split("/") if s]
    seg = unquote(segs[-1]) if segs else (parsed.netloc or "sub")
    seg = re.sub(r"[^A-Za-z0-9._-]+", "_", seg).strip("_") or f"sub_{index:03d}"
    name = seg
    if name in seen:
        h = hashlib.sha1(p.encode("utf-8", "replace")).hexdigest()[:8]
        name = f"{seg}-{h}"
    seen.add(name)
    return name


# -------------------------------------------------------------------------- #
# Fetching
# -------------------------------------------------------------------------- #

def fetch(url: str) -> bytes:
    """Download with retry/backoff; raise on terminal failure."""
    last: Exception | None = None
    for attempt in range(1 + RETRIES):
        try:
            req = Request(url, headers={"User-Agent": UA})
            with urlopen(req, timeout=TIMEOUT) as r:
                return r.read()
        except Exception as e:  # URLError / HTTPError / timeout / 429
            last = e
            if hasattr(e, "code") and e.code in (404, 410):
                raise
            time.sleep(2 * (attempt + 1))
    raise last  # type: ignore[misc]


def looks_like_html(data: bytes) -> bool:
    return _HTML.search(data[:2048].decode("utf-8", "replace")) is not None


def decode_if_b64(data: bytes) -> bytes:
    """Decode the body if (and only if) it is a pure base64-encoded sub.

    Gate: collapsed body must be pure base64 charset, must decode to valid
    UTF-8, and the decoded text must contain a `://` scheme.  Plain text,
    JSON, and HTML all fail the pure-base64 gate and pass through unchanged.
    """
    try:
        txt = data.decode("utf-8", "replace")
    except Exception:
        return data
    compact = "".join(txt.split())
    if not compact or not _PURE_B64.fullmatch(compact):
        return data
    try:
        dec = base64.b64decode(compact, validate=True)
    except Exception:
        return data
    try:
        decoded_txt = dec.decode("utf-8", "replace")
    except Exception:
        return data
    if _SCHEME.search(decoded_txt):
        return dec
    return data

# -------------------------------------------------------------------------- #
# Download + save
# -------------------------------------------------------------------------- #

def fetch_one(url: str, name: str) -> tuple[str, str, int, str]:
    """Download one subscription. Returns (status, name, bytes, detail).

    status in {ok, skip, empty, fail}; detail is 'b64-decoded' or 'raw' for ok,
    or a human-readable reason otherwise."""
    if skip_url(url):
        return "skip", name, 0, "HTML page (pre-filtered)"
    try:
        data = fetch(url)
    except Exception as e:
        return "fail", name, 0, f"{type(e).__name__}: {e}"
    if not data.strip():
        return "empty", name, 0, "empty body"
    if looks_like_html(data):
        return "skip", name, 0, "HTML page (content)"
    out = decode_if_b64(data)
    out = out.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    (OUT / name).write_bytes(out)
    detail = "b64-decoded" if len(out) != len(data) else "raw"
    return "ok", name, len(out), detail


# -------------------------------------------------------------------------- #
# CLI
# -------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Download v2ray subscription URLs from config/links.yaml into raw/.")
    ap.add_argument("--limit", type=int, default=0,
                    help="process only the first N URLs (default: all)")
    ap.add_argument("--workers", type=int, default=WORKERS,
                    help="concurrent downloads (default: %(default)s)")
    args = ap.parse_args(argv)

    if not CONFIG.exists():
        print(f"fetch_subs: config not found: {CONFIG}", file=sys.stderr)
        return 1
    doc = yaml.safe_load(CONFIG.read_text()) or {}
    urls = doc.get("subscriptions", [])
    if not isinstance(urls, list):
        print("fetch_subs: subscriptions is not a list", file=sys.stderr)
        return 1
    if args.limit:
        urls = urls[:args.limit]

    OUT.mkdir(parents=True, exist_ok=True)

    # Pre-resolve unique filenames single-threaded (collision-free).
    seen: set[str] = set()
    names = [fname_for(u, i, seen) for i, u in enumerate(urls)]

    counts = {"raw": 0, "b64-decoded": 0, "skip": 0, "empty": 0, "fail": 0}
    failures: list[str] = []

    print(f"fetching {len(urls)} subscriptions -> {OUT} ({args.workers} workers)")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, u, n): n for u, n in zip(urls, names)}
        for f in as_completed(futs):
            status, name, nbytes, detail = f.result()
            if status == "ok":
                counts[detail] += 1
                verb = "b64-decoded" if detail == "b64-decoded" else "saved"
                print(f"  [{name:<48}] {verb} -> {nbytes} bytes")
            elif status == "skip":
                counts["skip"] += 1
                print(f"  [{name:<48}] skip ({detail})")
            elif status == "empty":
                counts["empty"] += 1
                print(f"  [{name:<48}] empty")
            else:
                counts["fail"] += 1
                failures.append(f"{name}: {detail}")
                print(f"  [{name:<48}] FAIL ({detail})")

    saved = counts["raw"] + counts["b64-decoded"]
    print(f"\nDone: {saved} saved ({counts['b64-decoded']} b64-decoded), "
          f"{counts['skip']} skipped, {counts['empty']} empty, "
          f"{counts['fail']} failed of {len(urls)}")
    if failures:
        print("Failures:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
    return 1 if counts["fail"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
