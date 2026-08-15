#!/usr/bin/env python3
"""
Speed test surviving v2ray nodes through local sing-box proxies.

Reads nodes from subs/*.txt (output of a prior fasttest run that already
eliminated dead servers), then for each node:
  1. Generates a minimal sing-box config with the node as an outbound
  2. Starts sing-box on a unique local SOCKS5 port
  3. Downloads a test file through the proxy
  4. Measures throughput (mbps)
  5. Kills sing-box

Nodes slower than --min-speed-mbps are filtered out.
Results are written back to the same subs/ directory (overwriting input files).

Usage:
  python3 lib/speedtest_singbox.py [--concurrency N] [--min-speed-mbps 50]
                                   [--test-url URL] [--speed-timeout 5]

Prerequisites: sing-box binary in bin/sing-box or on PATH.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote
import base64

# Project root
ROOT = Path(__file__).resolve().parent.parent
SUBS_DIR = ROOT / "subs"
BIN_SING_BOX = ROOT / "bin" / "sing-box"
_system_singbox = shutil.which("sing-box")
SING_BOX = str(BIN_SING_BOX) if BIN_SING_BOX.exists() else (_system_singbox or "")

# Defaults
DEFAULT_CONCURRENCY = 50
DEFAULT_MIN_SPEED_Mbps = 50
DEFAULT_TEST_URL = "https://speed.cloudflare.com/__down?bytes=2621440"  # 2.5MB
DEFAULT_SPEED_TIMEOUT = 5  # seconds for the download test


@dataclass
class NodeResult:
    url: str
    scheme: str
    host: str
    port: int
    speed_mbps: float = 0.0
    passed: bool = False


@dataclass
class TestStats:
    total: int = 0
    tested: int = 0
    passed: int = 0
    failed: int = 0
    slow_filtered: int = 0
    start_time: float = field(default_factory=time.time)


def is_ipv6_host(host: str) -> bool:
    """Check if host is an IPv6 address."""
    cleaned = host.strip('[]')
    return ':' in cleaned and cleaned.count(':') > 1


def parse_node_url(url: str) -> Optional[tuple[str, str, int]]:
    """Extract (scheme, host, port) from node URL. Returns None if IPv6 or invalid."""
    try:
        if url.lower().startswith("vmess://"):
            payload = url[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)
            try:
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                cfg = json.loads(decoded)
                addr = cfg.get("add", "")
                port = int(cfg.get("port", 0))
                if addr and port:
                    if is_ipv6_host(addr):
                        return None
                    return ("vmess", addr, port)
                return None
            except Exception:
                return None

        elif url.lower().startswith("vless://"):
            match = re.match(r'vless://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            match = re.match(r'vless://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("vless", host, port)
            return None

        elif url.lower().startswith("ss://"):
            match = re.match(r'ss://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            match = re.match(r'ss://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("ss", host, port)
            return None

        elif url.lower().startswith("trojan://"):
            match = re.match(r'trojan://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            match = re.match(r'trojan://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("trojan", host, port)
            return None

        elif url.lower().startswith("hysteria") or url.lower().startswith("hy2://"):
            match = re.match(r'hysteria2?://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            match = re.match(r'hysteria2?://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("hys", host, port)
            return None

        elif url.lower().startswith("tuic://"):
            match = re.match(r'tuic://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            match = re.match(r'tuic://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("tuic", host, port)
            return None

        elif url.lower().startswith("socks5://"):
            match = re.match(r'socks5://\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            match = re.match(r'socks5://([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("socks5", host, port)
            return None

        return None
    except Exception:
        return None


def node_to_singbox_outbound(url: str) -> Optional[dict]:
    """Convert a v2ray node URL to a sing-box outbound config dict."""
    try:
        lower = url.lower()

        # VMess: vmess://base64(json)
        if lower.startswith("vmess://"):
            payload = url[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            cfg = json.loads(decoded)
            outbound = {
                "type": "vmess",
                "server": cfg["add"],
                "server_port": int(cfg["port"]),
                "uuid": cfg["id"],
                "security": cfg.get("encrypt", "auto"),
            }
            if cfg.get("net") == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": cfg.get("path", "/"),
                    "headers": {"Host": cfg.get("host", "")} if cfg.get("host") else {},
                }
            if cfg.get("tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": cfg.get("sni", ""),
                    "insecure": cfg.get("allowInsecure", 1) == 1,
                }
            return outbound

        # VLESS: vless://uuid@host:port?type=...&security=...&...
        elif lower.startswith("vless://"):
            # Parse the URL
            # vless://uuid@host:port?type=tcp&security=tls&sni=example.com&flow=xtls-rprx-vision
            at_idx = url.find("@")
            if at_idx == -1:
                return None
            before_at = url[len("vless://"):at_idx]
            uuid = before_at
            rest = url[at_idx + 1:]

            # Split host:port from query
            q_idx = rest.find("?")
            if q_idx == -1:
                host_port = rest
                query = ""
            else:
                host_port = rest[:q_idx]
                query = rest[q_idx + 1:]

            # Parse host:port
            bracket_match = re.match(r'\[([^\]]+)\]:(\d+)', host_port)
            if bracket_match:
                host = bracket_match.group(1)
                port = int(bracket_match.group(2))
            else:
                parts = host_port.rsplit(":", 1)
                if len(parts) != 2:
                    return None
                host = parts[0]
                port = int(parts[1])

            qs = parse_qs(query) if query else {}

            outbound = {
                "type": "vless",
                "server": host,
                "server_port": port,
                "uuid": uuid,
            }

            # Transport type — TCP is the default in sing-box, so only set
            # transport when it's not tcp
            net = qs.get("type", ["tcp"])[0]
            if net == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": qs.get("path", ["/"])[0],
                    "headers": {"Host": qs.get("host", [""])[0]} if "host" in qs else {},
                }
            elif net == "kcp":
                outbound["transport"] = {"type": "kcp"}
            elif net == "quic":
                outbound["transport"] = {"type": "quic"}
            elif net == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": qs.get("serviceName", [""])[0],
                }

            # TLS / security — default to TLS when sni is present
            security = qs.get("security", ["tls" if "sni" in qs else "none"])[0]
            if security == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": qs.get("sni", [host])[0],
                    "insecure": int(qs.get("allow_insecure", ["0"])[0]) == 1,
                }
            elif security == "reality":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": qs.get("sni", [host])[0],
                    "insecure": int(qs.get("allow_insecure", ["0"])[0]) == 1,
                    "reality": {
                        "public_key": qs.get("pbk", [""])[0],
                        "short_id": qs.get("sid", [""])[0],
                    },
                }
            elif security == "xtls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": qs.get("sni", [host])[0],
                    "insecure": int(qs.get("allow_insecure", ["0"])[0]) == 1,
                }

            # Flow — set at outbound level, skip "none"
            if "flow" in qs and qs["flow"][0] != "none":
                outbound["flow"] = qs["flow"][0]

            # Encryption
            # Encryption (for VLESS this is typically "none" — skip, sing-box expects it empty)
            return outbound

        # SS: ss://base64@host:port or ss://cipher:pass@host:port
        elif lower.startswith("ss://"):
            # Try base64 format first
            payload = url[len("ss://"):]
            i = payload.find("#")
            payload = payload[:i] if i != -1 else payload
            try:
                decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode('utf-8', errors='ignore')
                match = re.match(r'([^:@]+):([^@]+)@([^:]+):(\d+)', decoded)
                if match:
                    method = match.group(1)
                    password = match.group(2)
                    host = match.group(3)
                    port = int(match.group(4))
                    return {
                        "type": "shadowsocks",
                        "server": host,
                        "server_port": port,
                        "method": method,
                        "password": password,
                    }
            except Exception:
                pass

            # Try standard format: ss://cipher:pass@host:port
            match = re.match(r'ss://([^:]+):([^@]+)@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                method = match.group(1)
                password = unquote(match.group(2))
                host = match.group(3)
                port = int(match.group(4))
                return {
                    "type": "shadowsocks",
                    "server": host,
                    "server_port": port,
                    "method": method,
                    "password": password,
                }
            return None

        # Trojan: trojan://password@host:port?...
        elif lower.startswith("trojan://"):
            match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)', url, re.IGNORECASE)
            if not match:
                return None
            password = unquote(match.group(1))
            host = match.group(2)
            port = int(match.group(3))

            qs = parse_qs(urlparse(url).query) if "?" in url else {}

            outbound = {
                "type": "trojan",
                "server": host,
                "server_port": port,
                "password": password,
            }

            security = qs.get("security", ["tls"])[0] if "security" in qs else "tls"
            if security == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": qs.get("sni", [host])[0] if "sni" in qs else host,
                    "insecure": int(qs.get("allow_insecure", ["0"])[0]) == 1,
                }
            return outbound

        # Hysteria2: hysteria2://auth@host:port?...
        elif lower.startswith("hysteria") or lower.startswith("hy2://"):
            match = re.match(r'hysteria2?://([^@]+)@([^:]+):(\d+)', url, re.IGNORECASE)
            if not match:
                return None
            auth = match.group(1)
            host = match.group(2)
            port = int(match.group(3))

            qs = parse_qs(urlparse(url).query) if "?" in url else {}

            outbound = {
                "type": "hysteria2",
                "server": host,
                "server_port": port,
                "password": auth,
                "up_mbps": int(qs.get("upmbps", ["0"])[0]) if "upmbps" in qs else 0,
                "down_mbps": int(qs.get("downmbps", ["0"])[0]) if "downmbps" in qs else 0,
                "sni": qs.get("sni", [host])[0] if "sni" in qs else host,
            }
            if "obfs" in qs:
                outbound["obfs"] = qs["obfs"][0]
            return outbound

        # Tuic: tuic://user:pass@host:port?...
        elif lower.startswith("tuic://"):
            match = re.match(r'tuic://([^:]+):([^@]+)@([^:]+):(\d+)', url, re.IGNORECASE)
            if not match:
                return None
            user = match.group(1)
            password = match.group(2)
            host = match.group(3)
            port = int(match.group(4))

            qs = parse_qs(urlparse(url).query) if "?" in url else {}

            outbound = {
                "type": "tuic",
                "server": host,
                "server_port": port,
                "uuid": user,
                "password": password,
                "sni": qs.get("sni", [host])[0] if "sni" in qs else host,
                "congestion_control": qs.get("congestion_control", ["bbr"])[0],
            }
            if "alpn" in qs:
                outbound["alpn"] = qs["alpn"][0].split(",")
            return outbound

        return None
    except Exception:
        return None


def create_singbox_config(outbound: dict, listen_port: int) -> dict:
    """Create a minimal sing-box config with the given outbound."""
    return {
        "log": {"level": "fatal"},
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": listen_port,
            "users": [],
        }],
        "outbounds": [outbound],
    }


def load_nodes(subs_dir: Optional[Path] = None) -> list[NodeResult]:
    """Load all nodes from subs/*.txt, excluding IPv6."""
    nodes = []
    d = subs_dir if subs_dir is not None else SUBS_DIR

    if not d.exists():
        print(f"subs dir not found: {d}", file=sys.stderr)
        return nodes

    for f in sorted(d.glob("*.txt")):
        for line in f.read_text("utf-8", "replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = parse_node_url(line)
            if parsed is None:
                continue
            scheme, host, port = parsed
            node = NodeResult(url=line, scheme=scheme, host=host, port=port)
            nodes.append(node)

    return nodes


def wait_for_port(host: str, port: int, timeout: float) -> bool:
    """Wait until a TCP port is accepting connections."""
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (OSError, socket.timeout):
            time.sleep(0.1)
    return False


def speed_test_with_curl(proxy_port: int, test_url: str, timeout: float) -> Optional[float]:
    """Use curl to download through SOCKS5 proxy and measure speed (Mbps)."""
    cmd = [
        "curl",
        "--socks5-hostname", f"127.0.0.1:{proxy_port}",
        "--max-time", str(timeout),
        "--connect-timeout", str(timeout),
        "--silent",
        "--insecure",
        "-L",
        "--output", "/dev/null",
        "--write-out", "%{speed_download}",
        test_url,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        if result.returncode != 0:
            return None

        # speed_download is in bytes/second
        speed_bps = float(result.stdout.strip())
        speed_mbps = speed_bps * 8 / 1_000_000
        return speed_mbps
    except (subprocess.TimeoutExpired, ValueError, Exception):
        return None


def test_node_speed(node: NodeResult, port: int, test_url: str,
                    speed_timeout: float, min_speed_mbps: float,
                    stats: TestStats) -> Optional[NodeResult]:
    """Full speed test: generate config, start sing-box, download, measure."""
    outbound = node_to_singbox_outbound(node.url)
    if outbound is None:
        stats.failed += 1
        return None

    config = create_singbox_config(outbound, port)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [SING_BOX, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        # Wait for proxy to be ready
        if not wait_for_port("127.0.0.1", port, 3.0):
            stats.failed += 1
            return None

        # Download test file through proxy
        speed_mbps = speed_test_with_curl(port, test_url, speed_timeout)

        if speed_mbps is not None:
            stats.tested += 1
            node.speed_mbps = speed_mbps
            if speed_mbps >= min_speed_mbps:
                node.passed = True
                stats.passed += 1
            else:
                stats.slow_filtered += 1
            return node if node.passed else None
        else:
            stats.failed += 1
            return None

    finally:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=2)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
        try:
            os.unlink(config_path)
        except Exception:
            pass


async def run_speed_tests(nodes: list[NodeResult], concurrency: int,
                          test_url: str, speed_timeout: float,
                          min_speed_mbps: float) -> list[NodeResult]:
    """Run speed tests on all nodes using a thread pool for sing-box processes."""
    stats = TestStats()
    stats.total = len(nodes)
    print(f"Running speed tests on {stats.total} nodes (concurrency={concurrency})")

    # Use ThreadPoolExecutor for the blocking subprocess operations
    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(concurrency)
    port_counter = [10800]  # Starting port for local SOCKS5 proxies

    def _test_wrapper(node: NodeResult) -> Optional[NodeResult]:
        with semaphore:
            port = port_counter[0]
            port_counter[0] += 1
            return test_node_speed(node, port, test_url, speed_timeout, min_speed_mbps, stats)

    # Run in thread pool to avoid blocking the event loop
    tasks = [loop.run_in_executor(None, _test_wrapper, node) for node in nodes]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    passed_nodes = []
    for r in results:
        if isinstance(r, NodeResult) and r.passed:
            passed_nodes.append(r)
        elif isinstance(r, Exception):
            stats.failed += 1

    elapsed = time.time() - stats.start_time
    print(f"\nResults:")
    print(f"  Total: {stats.total}")
    print(f"  Tested: {stats.tested}")
    print(f"  Passed (>={min_speed_mbps}mbps): {stats.passed}")
    print(f"  Slow filtered (<{min_speed_mbps}mbps): {stats.slow_filtered}")
    print(f"  Failed (connect/error): {stats.failed}")
    print(f"  Time elapsed: {elapsed:.1f}s")
    if elapsed > 0 and stats.tested > 0:
        avg_speed = sum(n.speed_mbps for n in passed_nodes) / max(1, len(passed_nodes)) if passed_nodes else 0
        print(f"  Avg speed (passed): {avg_speed:.1f} Mbps")
        print(f"  Throughput: {stats.tested / elapsed:.0f} nodes/sec")

    return passed_nodes


def save_results(nodes: list[NodeResult], subs_dir: Path) -> None:
    """Save surviving nodes to subs_dir, replacing existing files."""
    for stale in subs_dir.glob("*.txt"):
        if stale.is_file():
            stale.unlink()

    buckets: dict[str, list[str]] = {}
    for node in nodes:
        fn = f"{node.scheme}.txt"
        buckets.setdefault(fn, []).append(node.url)

    for fn, lines in sorted(buckets.items()):
        (subs_dir / fn).write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
        print(f"  {fn:<16} {len(lines)} nodes")

    print(f"\nWritten: {sum(len(v) for v in buckets.values())} nodes to {subs_dir}")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Speed test v2ray nodes through sing-box proxies")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Concurrent speed tests (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--min-speed-mbps", type=float, default=DEFAULT_MIN_SPEED_Mbps,
                        help=f"Minimum download speed in Mbps (default: {DEFAULT_MIN_SPEED_Mbps})")
    parser.add_argument("--test-url", type=str, default=DEFAULT_TEST_URL,
                        help="URL to download for speed testing")
    parser.add_argument("--speed-timeout", type=float, default=DEFAULT_SPEED_TIMEOUT,
                        help="Timeout for each speed test download (default: 5s)")
    parser.add_argument("--subs-dir", type=str, default=None,
                        help="Override subs directory (default: ./subs)")
    args = parser.parse_args()

    min_speed = args.min_speed_mbps

    # Check sing-box binary
    if not SING_BOX or not Path(SING_BOX).exists():
        print(f"Error: sing-box binary not found at {SING_BOX}", file=sys.stderr)
        print("Install with: curl -sL https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-amd64.tar.gz | tar xz -C bin --strip-components=1", file=sys.stderr)
        return 1

    subs_dir = Path(args.subs_dir) if args.subs_dir else SUBS_DIR
    nodes = load_nodes(subs_dir)
    if not nodes:
        print("No nodes found to speed test", file=sys.stderr)
        return 1

    print(f"sing-box: {SING_BOX}")
    print(f"Test URL: {args.test_url}")
    print(f"Min speed: {min_speed} Mbps")
    print(f"Speed timeout: {args.speed_timeout}s")
    print()

    passed = asyncio.run(run_speed_tests(
        nodes, args.concurrency, args.test_url,
        args.speed_timeout, min_speed
    ))

    if passed:
        save_results(passed, subs_dir)
        print("\nSpeed testing complete!")
    else:
        print("\nNo nodes passed speed testing!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
