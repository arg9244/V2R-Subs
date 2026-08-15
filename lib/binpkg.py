#!/usr/bin/env python3
"""binpkg — update GitHub-release binaries into bin/.

A small, dependency-free manager that keeps a set of GitHub-release
binaries and geo-data files current.  It mirrors the behaviour of
scripts/binpkg (bash) but is cross-platform: asset selection adapts to
the detected OS and CPU architecture.

Manifest — one entry per package:
  name   | owner/repo           | asset matchers          | files to install

  asset matchers                 space-separated globs (fnmatch, case-sensitive)
                                    or regexes (when the asset name contains
                                    version-embedded variants that a glob
                                    cannot disambiguate — e.g. mihomo's
                                    go120/v1/v2/compatible builds).
  files to install                 space-separated archive member names to
                                    extract; empty => matched assets are
                                    copied as raw files under their own name.
                                    (.tar.gz/.zip are unpacked; a plain .gz
                                    is treated as a gzipped single binary and
                                    decompressed to the first file-to-install
                                    name; everything else is copied verbatim.)

Commands:
  binpkg            update every outdated package
  binpkg check      report versions only, change nothing
  binpkg install    (re)install every package, ignoring version stamps
  binpkg update N   update only the named package(s)
  binpkg install N  force-reinstall the named package(s)
  binpkg list       print the manifest

Version stamps live in $BINPKG_STATE_DIR/<name> (default ./.cache/binpkg).
Latest versions come from GitHub's /releases/latest redirect — no API call
for plain checks; the API is consulted only when an update actually runs.

Overrides:
  BINPKG_BIN_DIR    install target (default: ./bin)
  BINPKG_STATE_DIR  version-stamp directory (default: ./.cache/binpkg)
"""

from __future__ import annotations

import gzip
import io
import json
import os
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent.parent  # project root (parent of lib/)
BIN_DIR = Path(os.environ.get("BINPKG_BIN_DIR", ROOT / "bin"))
STATE_DIR = Path(os.environ.get("BINPKG_STATE_DIR", ROOT / ".cache" / "binpkg"))

GH = "https://github.com"
GHA = "https://api.github.com"
UA = "binpkg/1.0"  # GitHub requires a User-Agent for API access


# --------------------------------------------------------------------------- #
# Platform detection
# --------------------------------------------------------------------------- #

def detect_os() -> str:
    s = platform.system().lower()
    return {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(s, s)


def detect_arch() -> str:
    m = platform.machine().lower()
    table = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "i386": "386", "i686": "386", "x86": "386",
        "armv7l": "armv7", "armv7": "armv7",
        "armv5l": "armv5", "armv5": "armv5",
        "loong64": "loong64",
        "mips64": "mips64", "mips64el": "mips64el",
        "riscv64": "riscv64",
    }
    return table.get(m, m)


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #

@dataclass
class Package:
    name: str
    repo: str
    asset_globs: list[str] = field(default_factory=list)      # case-sensitive fnmatch
    asset_regexes: list[str] = field(default_factory=list)    # re.fullmatch patterns
    files: list[str] = field(default_factory=list)            # archive members to install
    raw: bool = False                                          # True => copy assets verbatim


def _glob_has_meta(s: str) -> bool:
    return any(c in s for c in "*?[")

_AETHER_OS = {"linux": "linux", "darwin": "macos", "windows": "windows"}
_AETHER_ARCH = {"amd64": "x86_64", "arm64": "arm64", "armv7": "armv7"}

# xray ships linux + windows (no darwin builds); amd64 -> "64", arm64 -> "arm64-v8a",
# always a .zip.  (Other arch codes like riscv64/mips64 exist but are skipped
# — they don't follow the amd64/arm64 pattern the original targeted.)
_XRAY_CODE = {"amd64": "64", "arm64": "arm64-v8a"}


def manifest(os_name: str, arch: str) -> list[Package]:
    exe = ".exe" if os_name == "windows" else ""
    pkgs: list[Package] = []

    # --- aether — linux / macos / windows; its own naming scheme -------------
    #   aether-{linux|macos|windows}-{x86_64|arm64}.tar.gz
    #   (aether-windows-x86_64.zip on windows).  amd64/arm64/armv7 on
    #   linux+macos; windows ships x86_64 only.
    aeth_os = _AETHER_OS.get(os_name)
    aeth_arch = _AETHER_ARCH.get(arch)
    if aeth_os and aeth_arch and not (os_name == "windows" and aeth_arch != "x86_64"):
        aeth_ext = ".zip" if os_name == "windows" else ".tar.gz"
        pkgs.append(Package(
            "aether", "CluvexStudio/Aether",
            asset_globs=[f"aether-{aeth_os}-{aeth_arch}{aeth_ext}"],
            files=[f"aether{exe}"],
        ))

    # --- geo (Iran v2ray rules) — platform independent -----------------------
    pkgs.append(Package(
        "geo", "Chocolate4U/Iran-v2ray-rules",
        asset_globs=["geoip.dat", "geosite.dat"],
        files=[], raw=True,
    ))

    # --- sing-box — standard goos/goarch; .tar.gz (unix) / .zip (windows) ---
    pkgs.append(Package(
        "sing-box", "sagernet/sing-box",
        asset_globs=[
            f"sing-box-*-{os_name}-{arch}.tar.gz",
            f"sing-box-*-{os_name}-{arch}.zip",
        ],
        files=[f"sing-box{exe}"],
    ))

    # --- mihomo — plain gzipped binary (unix) / .zip (windows) ---------------
    # Releases carry many variants (go120/123, v1/v2/v3, compatible, .deb/.rpm).
    # Globs can't disambiguate, so regex-select the default build per extension.
    pkgs.append(Package(
        "mihomo", "metacubex/mihomo",
        asset_regexes=[
            rf"^mihomo-{re.escape(os_name)}-{re.escape(arch)}-v\d[\w.]*\.gz$",
            rf"^mihomo-{re.escape(os_name)}-{re.escape(arch)}-v\d[\w.]*\.zip$",
        ],
        files=[f"mihomo{exe}"],
    ))

    # --- xray — linux + windows; amd64 -> 64 / arm64 -> arm64-v8a ------------
    xr = _XRAY_CODE.get(arch)
    if xr and os_name in ("linux", "windows"):
        pkgs.append(Package(
            "xray", "xtls/xray-core",
            asset_globs=[f"Xray-{os_name}-{xr}.zip"],
            files=[f"xray{exe}"],
        ))

    return pkgs


def find_pkg(name: str, pkgs: list[Package]) -> Package | None:
    for p in pkgs:
        if p.name == name:
            return p
    return None


# --------------------------------------------------------------------------- #
# GitHub helpers
# --------------------------------------------------------------------------- #

def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": UA,
                                                "Accept": "application/octet-stream"})


def _urlopen(req: urllib.request.Request, timeout: int = 30,
             retries: int = 4, backoff: float = 2.0) -> object:
    """urlopen with retry/backoff — GitHub's CDN is flaky; curl hides this,
    urllib does not, so we retry idempotent GETs here."""
    import time
    last: Exception | None = None
    for attempt in range(retries):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except Exception as e:  # URLError / HTTPError / timeout
            last = e
            # 404 is terminal — retrying won't change the resource
            if hasattr(e, "code") and e.code == 404:
                raise
            time.sleep(backoff * (attempt + 1))
    raise last


def _github_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/vnd.github+json"})
    with _urlopen(req) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def latest_tag(repo: str) -> str:
    """Resolve the latest release tag via the /releases/latest redirect only."""
    url = f"{GH}/{repo}/releases/latest"
    with _urlopen(_request(url), timeout=30) as r:
        return r.url.rstrip("/").split("/")[-1]


def release_assets(repo: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (tag, [(asset_name, browser_download_url), ...])."""
    data = _github_json(f"{GHA}/repos/{repo}/releases/latest")
    assets = [(a["name"], a["browser_download_url"]) for a in data.get("assets", [])]
    return data["tag_name"], assets


def _download(url: str, dest: Path) -> None:
    with _urlopen(_request(url), timeout=120, retries=6, backoff=3.0) as r, \
         open(dest, "wb") as out:
        shutil.copyfileobj(r, out, length=1024 * 1024)


# --------------------------------------------------------------------------- #
# Asset matching
# --------------------------------------------------------------------------- #

def match_assets(pkg: Package, names: list[str]) -> list[str]:
    matched: list[str] = []
    for n in names:
        for g in pkg.asset_globs:
            if fnmatchcase(n, g):
                matched.append(n)
                break
        else:
            for rx in pkg.asset_regexes:
                if re.fullmatch(rx, n):
                    matched.append(n)
                    break
    return matched


def asset_kind(name: str) -> str:
    low = name.lower()
    if low.endswith(".tar.gz") or low.endswith(".tgz"):
        return "tar"
    if low.endswith(".zip"):
        return "zip"
    if low.endswith(".gz"):
        return "gz"
    return "raw"


# --------------------------------------------------------------------------- #
# Core operations
# --------------------------------------------------------------------------- #

def check_pkg(pkg: Package) -> None:
    installed = ""
    stamp = STATE_DIR / pkg.name
    if stamp.exists():
        installed = stamp.read_text().strip()
    latest = latest_tag(pkg.repo)
    if not installed:
        status = "not installed"
    elif installed == latest:
        status = "up to date"
    else:
        status = "update available"
    print(f"  {pkg.name:<8} latest={latest:<14} "
          f"installed={(installed or '-'):<14} {status}")


def _targets_for(pkg: Package) -> list[str]:
    """File names to install (archive members), or literal raw-asset names."""
    if pkg.files:
        return list(pkg.files)
    # raw assets: literal (non-glob) asset names are installed verbatim
    return [g for g in pkg.asset_globs if not _glob_has_meta(g)]


def install_pkg(pkg: Package, force: bool = False) -> None:
    stamp = STATE_DIR / pkg.name
    installed = stamp.read_text().strip() if stamp.exists() else ""

    # latest_tag via redirect — cheap; no API call (mirrors scripts/binpkg).
    latest = latest_tag(pkg.repo)
    targets = _targets_for(pkg)

    # Fast skip: same stamp AND every target already present in bin dir.
    if not force and installed and installed == latest \
            and targets and all((BIN_DIR / t).exists() for t in targets):
        print(f"  {pkg.name}: up to date ({latest})")
        return

    # Hit the API only when we're actually going to install.
    tag, assets = release_assets(pkg.repo)
    asset_urls = {n: u for n, u in assets}
    matched = match_assets(pkg, [n for n, _ in assets])
    if not matched:
        raise SystemExit(f"binpkg: no asset of {pkg.name} matches: "
                         f"{' '.join(pkg.asset_globs + pkg.asset_regexes)}")

    if force:
        print(f"  {pkg.name}: installing {tag}")
    else:
        print(f"  {pkg.name}: updating {installed or '-'} -> {tag}")

    kind_map = {m: asset_kind(m) for m in matched}
    tmp = Path(tempfile.mkdtemp(prefix="binpkg-"))
    try:
        for aname in matched:
            k = kind_map[aname]
            dst = tmp / aname
            _download(asset_urls[aname], dst)
            if k == "tar":
                with tarfile.open(dst, "r:*") as tf:
                    tf.extractall(tmp, filter="data")
            elif k == "zip":
                with zipfile.ZipFile(dst) as zf:
                    zf.extractall(tmp)
            elif k == "gz":
                # single gzipped binary: decompress to the target member name
                out_name = pkg.files[0] if pkg.files else dst.name[:-3]
                out = tmp / out_name
                with gzip.open(dst, "rb") as src, open(out, "wb") as out_f:
                    shutil.copyfileobj(src, out_f, length=1024 * 1024)
            # raw assets are left as tmp/<aname>
            print(f"    downloaded {aname}")

        BIN_DIR.mkdir(parents=True, exist_ok=True)
        for t in targets:
            src = _find_member(tmp, t)
            if src is None:
                raise SystemExit(f"binpkg: member '{t}' not found in {pkg.name} archive")
            dst = BIN_DIR / t
            shutil.copyfile(src, dst)
            os.chmod(dst, 0o755)
            print(f"    installed {dst}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    stamp.write_text(f"{tag}\n")


def _find_member(root: Path, name: str) -> Path | None:
    """Locate a file by basename within root (recursive)."""
    for p in root.rglob(name):
        if p.is_file():
            return p
    return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def usage() -> None:
    print(__doc__.strip().split("\n\n")[0])
    print("""
usage: binpkg [command] [package...]

commands:
  update [name...]   update outdated packages (default: all)
  check [name...]    report versions only, change nothing
  install [name...]  (re)install packages, ignoring version stamps
  list               print the manifest

Packages are derived from OS/arch detection at runtime.
Version stamps are kept in ./.cache/binpkg (override: BINPKG_STATE_DIR).
Install target is ./bin (override: BINPKG_BIN_DIR).
""")


def main(argv: list[str]) -> int:
    pkgs = manifest(detect_os(), detect_arch())
    if not pkgs:
        print("binpkg: no packages match this platform", file=sys.stderr)
        return 1

    cmd = argv[0] if argv else "update"
    args = argv[1:]

    if cmd in ("-h", "--help", "help"):
        usage()
        return 0

    if cmd == "list":
        for p in pkgs:
            matchers = " ".join(p.asset_globs) or " ".join(p.asset_regexes)
            files = " ".join(p.files) if p.files else "(raw assets)"
            print(f"  {p.name:<10} {p.repo:<36} {matchers:<48} {files}")
        return 0

    if cmd == "check":
        names = args or [p.name for p in pkgs]
        for n in names:
            p = find_pkg(n, pkgs)
            if p is None:
                print(f"binpkg: unknown package: {n}", file=sys.stderr)
                return 1
            check_pkg(p)
        return 0

    if cmd == "update":
        names = args or [p.name for p in pkgs]
        for n in names:
            p = find_pkg(n, pkgs)
            if p is None:
                print(f"binpkg: unknown package: {n}", file=sys.stderr)
                return 1
            install_pkg(p)
        return 0

    if cmd == "install":
        names = args or [p.name for p in pkgs]
        for n in names:
            p = find_pkg(n, pkgs)
            if p is None:
                print(f"binpkg: unknown package: {n}", file=sys.stderr)
                return 1
            install_pkg(p, force=True)
        return 0

    print(f"binpkg: unknown command: {cmd}", file=sys.stderr)
    usage()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
