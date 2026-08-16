#!/usr/bin/env python3
"""Organize subscription nodes into structured layouts.

Reads ``subs/*.txt`` (one node URL per line), then produces:

  subs/
  ├── protocols/        # Original per-protocol files (moved here)
  │   ├── vless.txt
  │   ├── ss.txt
  │   ├── trojan.txt
  │   └── ...
  ├── mix.txt           # ALL nodes concatenated (deduplicated)
  ├── country/          # Nodes grouped by detected country
  │   ├── ir.txt
  │   ├── us.txt
  │   └── other.txt
  └── 1000/             # mix.txt split into chunks of 1000 lines
      ├── 000.txt
      ├── 001.txt
      └── ...

Run directly or import :func:`organize_subs`.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

ROOT = Path(__file__).resolve().parent.parent
SUBS_DIR = ROOT / "subs"

# ---------------------------------------------------------------------------
# Country detection helpers
# ---------------------------------------------------------------------------

# 2-letter ISO country code → friendly name (most common V2Ray node TLDs)
TLD_COUNTRY: dict[str, str] = {
    "ir": "iran", "cn": "china", "us": "us", "uk": "uk", "de": "germany",
    "fr": "france", "nl": "netherlands", "ru": "russia", "sg": "singapore",
    "jp": "japan", "kr": "south-korea", "tr": "turkey", "ar": "argentina",
    "br": "brazil", "in": "india", "id": "indonesia", "th": "thailand",
    "ml": "malaysia", "ph": "philippines", "my": "malaysia", "vn": "vietnam",
    "ua": "ukraine", "pl": "poland", "it": "italy", "es": "spain",
    "ca": "canada", "se": "sweden", "no": "norway", "fi": "finland",
    "pt": "portugal", "gr": "greece", "ch": "switzerland", "at": "austria",
    "be": "belgium", "dk": "denmark", "cz": "czech-republic", "ro": "romania",
    "hu": "hungary", "bg": "bulgaria", "hr": "croatia", "sk": "slovakia",
    "si": "slovenia", "lt": "lithuania", "lv": "latvia", "ee": "estonia",
    "lu": "luxembourg", "ie": "ireland", "is": "iceland", "cy": "cyprus",
}

# Keywords in remarks/SNI that hint at a country
KEYWORD_COUNTRY: list[tuple[str, str]] = [
    ("iran", "iran"), ("ir@", "iran"), ("@ir_", "iran"), ("parsashe", "iran"),
    ("mahdi", "iran"), ("anten", "iran"), ("ir-", "iran"),
    ("v2xnet", "other"), ("natvpn", "other"), ("v2config", "other"),
]


def _extract_remark(url: str) -> str:
    """Extract the remark from a V2Ray/VMess/VLESS/Trojan URL."""
    try:
        scheme = url.split("://")[0].lower()
    except Exception:
        return ""

    if scheme == "vless":
        # vless://remark@host:port?...
        at_idx = url.find("://")
        at_idx = url.find("@", at_idx + 3) if at_idx >= 0 else -1
        if at_idx > 0:
            return unquote(url[3:at_idx])
    elif scheme == "trojan":
        # trojan://password@host:port?...
        at_idx = url.find("://")
        at_idx = url.find("@", at_idx + 3) if at_idx >= 0 else -1
        if at_idx > 0:
            return unquote(url[3:at_idx])
    return ""


def _extract_sni(url: str) -> str:
    """Extract the SNI / server_name from a node URL's query params."""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        sni = qs.get("sni", [""])[0]
        if not sni:
            sni = qs.get("server_name", [""])[0]
        return sni
    except Exception:
        return ""


def _extract_host(url: str) -> str:
    """Extract the hostname from a node URL."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def detect_country(url: str) -> str:
    """Heuristically detect the country of a node from its URL.

    Checks (in order of confidence):
      1. Country-related keywords in the remark
      2. 2-letter country code in the remark
      3. Country TLD in the SNI domain
      4. Country TLD in the host domain
      5. ``"other"``
    """
    remark = _extract_remark(url).lower()
    sni = _extract_sni(url)
    host = _extract_host(url)

    # 1. Keyword matching
    for kw, country in KEYWORD_COUNTRY:
        if kw in remark or kw in (sni or "").lower():
            if country != "other":
                return country

    # 2. Two-letter country code in remark (e.g. "IR_NETLIFY", "US_NODE")
    m = re.search(r"\b([A-Za-z]{2})\b", remark)
    if m:
        tld = m.group(1).lower()
        if tld in TLD_COUNTRY:
            return TLD_COUNTRY[tld]

    # 3. TLD from SNI
    if sni and "." in sni:
        tld = sni.rsplit(".", 1)[-1].lower()
        if tld in TLD_COUNTRY:
            return TLD_COUNTRY[tld]

    # 4. TLD from host
    if host and "." in host:
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in TLD_COUNTRY:
            return TLD_COUNTRY[tld]

    return "other"


# ---------------------------------------------------------------------------
# Organization logic
# ---------------------------------------------------------------------------


def load_all_nodes(subs_dir: Path) -> list[str]:
    """Load all node URLs from subs/*.txt, deduplicated and sorted."""
    seen: set[str] = set()
    nodes: list[str] = []
    for f in sorted(subs_dir.glob("*.txt")):
        for line in f.read_text("utf-8", "replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line not in seen:
                seen.add(line)
                nodes.append(line)
    return nodes


def organize_subs(subs_dir: Path) -> None:
    """Reorganize ``subs/`` into the structured layout described in the docstring."""
    if not subs_dir.exists():
        print(f"subs dir not found: {subs_dir}", file=sys.stderr)
        return

    # 1. Load all nodes
    nodes = load_all_nodes(subs_dir)
    print(f"Loaded {len(nodes)} unique nodes")

    # 2. Move protocol files to subs/protocols/
    protocols_dir = subs_dir / "protocols"
    protocols_dir.mkdir(parents=True, exist_ok=True)

    # Clear old protocol files
    for old in protocols_dir.glob("*.txt"):
        old.unlink()

    for f in sorted(subs_dir.glob("*.txt")):
        dest = protocols_dir / f.name
        shutil.move(str(f), str(dest))
        count = sum(1 for _ in dest.open("r", encoding="utf-8", errors="replace"))
        print(f"  protocols/{f.name:<16} {count} nodes")

    # 3. Create subs/mix.txt — all nodes combined
    mix_path = subs_dir / "mix.txt"
    mix_path.write_text("\n".join(nodes) + "\n", encoding="utf-8")
    print(f"\n  mix.txt           {len(nodes)} nodes")

    # 4. Create subs/country/ — group by detected country
    country_dir = subs_dir / "country"
    if country_dir.exists():
        for old in country_dir.glob("*.txt"):
            old.unlink()
    country_dir.mkdir(parents=True, exist_ok=True)

    country_buckets: dict[str, list[str]] = {}
    for url in nodes:
        country = detect_country(url)
        country_buckets.setdefault(country, []).append(url)

    for country, urls in sorted(country_buckets.items()):
        path = country_dir / f"{country}.txt"
        path.write_text("\n".join(urls) + "\n", encoding="utf-8")
        print(f"  country/{country}.txt     {len(urls)} nodes")

    # 5. Create subs/1000/ — split mix.txt into chunks of 1000
    chunk_dir = subs_dir / "1000"
    if chunk_dir.exists():
        for old in chunk_dir.glob("*.txt"):
            old.unlink()
    chunk_dir.mkdir(parents=True, exist_ok=True)

    chunk_size = 1000
    for i in range(0, len(nodes), chunk_size):
        chunk = nodes[i : i + chunk_size]
        fname = f"{i // chunk_size:03d}.txt"
        (chunk_dir / fname).write_text("\n".join(chunk) + "\n", encoding="utf-8")

    num_chunks = (len(nodes) + chunk_size - 1) // chunk_size if nodes else 0
    print(f"  1000/              {num_chunks} files ({chunk_size} nodes each)")

    print(f"\nDone. {len(nodes)} nodes organized into {subs_dir}")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Organize subs/*.txt into protocols/, mix.txt, country/, 1000/"
    )
    parser.add_argument(
        "--subs-dir",
        type=str,
        default=None,
        help="Override subs directory (default: ./subs)",
    )
    args = parser.parse_args()

    subs_dir = Path(args.subs_dir) if args.subs_dir else SUBS_DIR
    organize_subs(subs_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
