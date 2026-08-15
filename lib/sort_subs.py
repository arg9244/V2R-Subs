#!/usr/bin/env python3
"""sort_subs — classify, clean and dedup raw v2ray subscriptions.

Reads every regular file directly under raw/ (the decoded subscription
dumps from fetch_subs.py), classifies each node URI by protocol, strips
non-functional remarks/flavour text, and writes one file per protocol into
subs/ — e.g. ss.txt, vless.txt, vmess.txt, trojan.txt, hys.txt,
tuic.txt, wireguard.txt, snell.txt, socks5.txt — with duplicates removed.

Cleaning rules (researched v2ray/xray node-URI syntax):

  * Every URI scheme may carry an optional `#remark` fragment that is a
    display name only — v2ray clients never use it for the connection — so
    everything from the first `#` onward is dropped.  (URL-encoded `#`
    inside a value is `%23`, so a literal `#` is always the fragment start.)

  * `vmess://<base64(json)>` carries its remark in the JSON `ps` field.
    The base64 (standard, occasionally url-safe) is decoded, `ps` is removed
    and the JSON is re-emitted as standard base64.  If decode or JSON parse
    fails the original line is left untouched (no data loss).

  * `wireguard://<base64(json)>` uses `#name` — only the fragment is
    stripped; no re-encoding needed.

  * `ss://`, `vless://`, `trojan://`, `hysteria2://`/`hy2://`, `tuic://`,
    `snell://`, `socks5://` all take only the fragment off (the `?query`
    params are functional and kept).

Lines that are not recognised node URIs (JSON braces, comments, reference
URLs, http/https reference links) are skipped.

Usage:  python3 lib/sort_subs.py
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # project root (parent of lib/)
RAW = ROOT / "raw"
OUT = ROOT / "subs"
CONFIG_NOTE = "config/links.yaml"  # only used to know the source of raw/

# protocol -> output filename
SCHEME_FILE: dict[str, str] = {
    "ss": "ss.txt",
    "vless": "vless.txt",
    "vmess": "vmess.txt",
    "trojan": "trojan.txt",
    "hysteria": "hys.txt",
    "hy2": "hys.txt",
    "hysteria2": "hys.txt",
    "tuic": "tuic.txt",
    "wireguard": "wireguard.txt",
    "snell": "snell.txt",
    "socks5": "socks.txt",
}

_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*)://", re.I)


def scheme_of(line: str) -> str | None:
    m = _SCHEME_RE.match(line)
    if not m:
        return None
    s = m.group(1).lower()
    return s if s in SCHEME_FILE else None


def _b64decode(payload: str) -> bytes | None:
    """Decode vmess/wireguard base64, tolerating missing padding and url-safe."""
    pad = "=" * (-len(payload) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return dec(payload + pad)
        except Exception:
            continue
    return None


_B64_GATE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def clean_vmess(line: str) -> str:
    # 1. drop the `#remark` fragment (display name only) for both vmess shapes.
    i = line.find("#")
    core = line[:i] if i != -1 else line
    payload = core[len("vmess://"):].strip()
    # 2. standard `vmess://<base64(json)>` — decode, drop the `ps` remark, re-encode.
    if _B64_GATE.fullmatch(payload):
        raw = _b64decode(payload)
        if raw is not None:
            try:
                obj = json.loads(raw)
            except Exception:
                obj = None
            if isinstance(obj, dict):
                obj.pop("ps", None)            # `ps` is the remark (display name only)
                re_enc = base64.b64encode(
                    json.dumps(obj, separators=(",", ":")).encode("utf-8")
                ).decode("ascii")
                return "vmess://" + re_enc
    # URI-style `vmess://uuid@host:port?...#name` — fragment already stripped above.
    return core


def classify(line: str) -> tuple[str, str] | None:
    """Return (scheme, cleaned_line) or None if the line is not a node URI."""
    s = scheme_of(line)
    if s is None:
        return None
    if s == "vmess":
        return s, clean_vmess(line)
    i = line.find("#")             # drop the `#remark` fragment
    return s, line[:i] if i != -1 else line


def main(argv: list[str]) -> int:
    if not RAW.is_dir():
        print(f"sort_subs: raw dir not found: {RAW}", file=sys.stderr)
        return 1

    inputs = [p for p in RAW.iterdir() if p.is_file()]
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*"):                 # fresh output each run
        if stale.is_file():
            stale.unlink()

    buckets: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    n_lines = n_dups = n_nodes = n_skip = 0

    for f in sorted(inputs, key=lambda p: p.name):
        for raw in f.read_text("utf-8", "replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            n_lines += 1
            res = classify(line)
            if res is None:
                n_skip += 1
                continue
            s, cl = res
            fn = SCHEME_FILE[s]
            bucket = buckets.setdefault(fn, [])
            used = seen.setdefault(fn, set())
            if cl in used:
                n_dups += 1
                continue
            used.add(cl)
            bucket.append(cl)
            n_nodes += 1

    for fn, lines in sorted(buckets.items()):
        (OUT / fn).write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"sources : {len(inputs)} files under {RAW}")
    print(f"lines   : {n_lines}")
    print(f"nodes   : {n_nodes}")
    print(f"dups    : {n_dups}  (removed)")
    print(f"skipped : {n_skip}  (non-URI lines, comments, reference URLs)")
    print(f"written : {len(buckets)} files in {OUT}")
    for fn in sorted(buckets):
        print(f"  {fn:<16} {len(buckets[fn])} unique")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
