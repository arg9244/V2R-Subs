#!/usr/bin/env python3
"""generate_mihomo_config — convert subs/*.txt node URLs into mihomo YAML configs.

Mirrors the subs/ folder structure:
  - mix.yaml            — all nodes + url-test LB
  - country/*.yaml      — nodes by country + url-test LB
  - protocol/*.yaml     — nodes by protocol + url-test LB
  - 1000/*.yaml         — chunks of 1000 + url-test LB each

Each config has:
  - mixed-port: 7890 (SOCKS5 + HTTP)
  - `proxies:` array — one entry per node
  - A `proxy-groups:` url-test group as the default load balancer (least-ping)
  - `rules:` routing MATCH traffic into the url-test group

Usage:
  python3 lib/generate_mihomo_config.py                    # default: reads subs/, writes mihomo/
  python3 lib/generate_mihomo_config.py --subs-dir subs --out-dir mihomo
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure lib/ is on sys.path so parse_nodes is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_nodes import NodeConfig, load_all_nodes, load_nodes_from_file

ROOT = Path(__file__).resolve().parent.parent


def _sanitize_str(val: str) -> str:
    """Sanitize a string for safe YAML output — strip non-UTF-8 and control chars."""
    if not val:
        return ""
    # Ensure valid UTF-8 (replaces invalid bytes with ?)
    try:
        val = val.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    except Exception:
        val = str(val)
    # Remove ALL control characters (C0 + C1 ranges) except tab/newline
    import unicodedata
    return "".join(
        c for c in val
        if not unicodedata.category(c).startswith("C") or c in "\t\n"
    )


def _node_to_mihomo_proxy(nc: NodeConfig) -> dict:
    proxy: dict = {
        "name": _sanitize_str(nc.tag),
        "server": _sanitize_str(nc.server),
        "port": nc.port,
        "udp": True,
    }

    # --- Per-protocol ---
    if nc.scheme == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = nc.uuid
        if nc.flow and nc.flow != "none":
            proxy["flow"] = nc.flow

    elif nc.scheme == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = nc.uuid
        if nc.security and nc.security != "auto":
            proxy["cipher"] = nc.security  # Xray AEAD cipher or auto
        # alterId defaults to 0

    elif nc.scheme == "ss":
        proxy["type"] = "ss"
        proxy["cipher"] = nc.cipher
        proxy["password"] = nc.password
        if nc.plugin:
            proxy["plugin"] = nc.plugin
            if nc.plugin_opts:
                proxy["plugin-opts"] = nc.plugin_opts

    elif nc.scheme == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = nc.password

    elif nc.scheme in ("hysteria2", "hy2"):
        proxy["type"] = "hysteria2"
        if nc.password:
            proxy["password"] = nc.password
        elif nc.auth:
            proxy["auth-str"] = nc.auth
        if nc.obfs:
            proxy["obfs"] = nc.obfs
        if nc.sni:
            proxy["sni"] = nc.sni
        if nc.alpn:
            proxy["alpn"] = nc.alpn
        if nc.down_mbps:
            proxy["down"] = nc.down_mbps
        if nc.up_mbps:
            proxy["up"] = nc.up_mbps
        if nc.allow_insecure:
            proxy["insecure"] = True

    elif nc.scheme == "hysteria":
        proxy["type"] = "hysteria"
        if nc.auth:
            proxy["auth-str"] = nc.auth
        if nc.obfs:
            proxy["obfs"] = nc.obfs
        if nc.sni:
            proxy["sni"] = nc.sni
        if nc.alpn:
            proxy["alpn"] = nc.alpn

    elif nc.scheme == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = nc.uuid
        proxy["password"] = nc.password
        if nc.congestion_control:
            proxy["congestion-controller"] = nc.congestion_control
        if nc.alpn:
            proxy["alpn"] = nc.alpn
        if nc.sni:
            proxy["sni"] = nc.sni
        if nc.disable_sni:
            proxy["disable-sni"] = True
        if nc.udp_relay_mode:
            proxy["udp-relay-mode"] = nc.udp_relay_mode

    elif nc.scheme == "socks5":
        proxy["type"] = "socks5"
        if nc.username:
            proxy["username"] = nc.username
        if nc.password:
            proxy["password"] = nc.password

    # --- TLS / Reality / Fingerprint ---
    if nc.tls:
        proxy["tls"] = True
        if nc.allow_insecure:
            proxy["skip-cert-verify"] = True
        if nc.sni:
            proxy["servername"] = nc.sni
        if nc.alpn:
            proxy["alpn"] = nc.alpn
        if nc.fingerprint and nc.fingerprint != "None":
            proxy["client-fingerprint"] = nc.fingerprint
        if nc.reality:
            proxy["reality-opts"] = {
                "public-key": nc.public_key,
                "short-id": nc.short_id,
            }

    # --- Transport ---
    if nc.network:
        net = nc.network
        if net == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path": nc.ws_path or "/",
            }
            if nc.ws_headers:
                proxy["ws-opts"]["headers"] = nc.ws_headers
            if nc.max_early_data > 0:
                proxy["ws-opts"]["max-early-data"] = nc.max_early_data
                if nc.early_data_header:
                    proxy["ws-opts"]["early-data-header-name"] = nc.early_data_header
        elif net == "httpupgrade":
            proxy["network"] = "http"
            proxy["ws-opts"] = {
                "path": nc.http_path or "/",
                "headers": nc.http_headers or {},
            }
        elif net == "http":
            proxy["network"] = "http"
            proxy["http-opts"] = {
                "path": nc.http_path or "/",
                "headers": nc.http_headers or {},
            }
        elif net == "h2":
            proxy["network"] = "h2"
            proxy["h2-opts"] = {"path": nc.h2_path or "/"}
            if nc.h2_host:
                proxy["h2-opts"]["host"] = [nc.h2_host]
        elif net == "grpc":
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": nc.grpc_service or ""}
        elif net == "xhttp":
            proxy["network"] = "xhttp"
            proxy["xhttp-opts"] = {
                "path": nc.http_path or "/",
                "host": nc.http_headers.get("Host", "") if nc.http_headers else "",
            }

    return proxy


def _build_urltest_group(proxy_names: list[str]) -> dict:
    """Build a mihomo url-test proxy-group (least-ping load balancer)."""
    return {
        "name": "url-test",
        "type": "url-test",
        "proxies": proxy_names,
        "url": "https://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "expected-status": 204,
    }


def _build_config(nodes: list[NodeConfig]) -> dict:
    """Build a complete mihomo config with all nodes + url-test group."""
    proxies = [_node_to_mihomo_proxy(nc) for nc in nodes]
    proxy_names = [p["name"] for p in proxies]

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "default-nameservers": ["1.1.1.1", "8.8.8.8"],
            "nameserver-over-tls": ["https+1.1.1.1:853#Cloudflare"],
            "rules": ["RULE-SET,cn,dnss", "FINAL,dns"],
        },
        "proxies": proxies,
        "proxy-groups": [_build_urltest_group(proxy_names)],
        "rules": [
            "DOMAIN-KEYWORD,local,DIRECT",
            "DOMAIN-SUFFIX,localhost,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR6,::1/128,DIRECT,no-resolve",
            "MATCH,url-test",
        ],
        "clash-api": {
            "external-controller": "0.0.0.0:9090",
            "secret": "",
        },
        "external-controller": "0.0.0.0:9090",
        "secret": "",
        "ipv6-hint": False,
        "snell-address": [],
        "redir-host": True,
    }

    return config


def _dump_yaml(data, indent: int = 0) -> str:
    """Minimal YAML serializer (no external dependency needed)."""
    lines: list[str] = []
    pad = "  " * indent

    if isinstance(data, dict):
        for k, v in data.items():
            if v is None:
                continue
            if isinstance(v, dict):
                nested = _dump_yaml(v, indent + 1)
                if nested.strip():
                    lines.append(f"{pad}{k}:")
                    lines.append(nested)
                else:
                    lines.append(f"{pad}{k}: {{}}")
            elif isinstance(v, list):
                if len(v) == 0:
                    lines.append(f"{pad}{k}: []")
                elif all(isinstance(_x, (str, int, float, bool)) for _x in v):
                    items = ", ".join(_yaml_scalar(x) for x in v)
                    lines.append(f"{pad}{k}: [{items}]")
                else:
                    lines.append(f"{pad}{k}:")
                    for item in v:
                        if isinstance(item, dict):
                            nested = _dump_yaml(item, indent + 2)
                            first = True
                            for nl in nested.splitlines():
                                if first:
                                    lines.append(f"{pad}- {nl}")
                                    first = False
                                else:
                                    lines.append(f"  {pad}{nl}")
                        elif isinstance(item, list):
                            nested = _dump_yaml({"list": item}, indent + 2)
                            lines.append(f"{pad}-")
                            for nl in nested.splitlines():
                                lines.append(f"  {pad}{nl}")
                        else:
                            lines.append(f"{pad}- {_yaml_scalar(item)}")
            else:
                lines.append(f"{pad}{k}: {_yaml_scalar(v)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                nested = _dump_yaml(item, indent + 1)
                lines.append(f"{pad}-")
                for nl in nested.splitlines():
                    lines.append(f"  {pad}{nl}")
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    else:
        lines.append(f"{pad}{_yaml_scalar(data)}")

    return "\n".join(lines)


def _yaml_scalar(val) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        val = _sanitize_str(val)
        # Quote if contains special chars or starts with reserved chars (@, `, -, :, etc.)
        needs_quote = (
            any(c in val for c in [":", "#", "{", "}", "[", "]", ",", "&", "*", "?", "|", "<", ">", "=", "!", "%", "@", "`"])
            or val.strip() != val
            or val.startswith(("-", "?", ":", " ", "\t"))
            or val.lower() in ("yes", "no", "true", "false", "null", "none", "~")
        )
        if needs_quote:
            escaped = val.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        if not val:
            return '""'
        return val
    return str(val)


def generate(subs_dir: Path, out_dir: Path) -> int:
    """Generate mihomo configs mirroring the subs/ layout."""
    if not subs_dir.exists():
        print(f"generate_mihomo: subs dir not found: {subs_dir}", file=sys.stderr)
        return 1

    count = 0

    # mix.yaml — ALL nodes
    all_nodes = load_all_nodes(subs_dir)
    cfg = _build_config(all_nodes)
    _write_config(cfg, out_dir / "mix.yaml")
    count += 1
    print(f"  mihomo/mix.yaml — {len(all_nodes)} nodes")

    # Protocol files
    proto_dir = subs_dir / "protocols"
    if proto_dir.is_dir():
        out_proto = out_dir / "protocol"
        for f in sorted(proto_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_proto / f"{f.stem}.yaml")
            count += 1
        print(f"  mihomo/protocol/ — {len(list(out_proto.glob('*.yaml')))} files")

    # Country files
    country_dir = subs_dir / "country"
    if country_dir.is_dir():
        out_country = out_dir / "country"
        for f in sorted(country_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_country / f"{f.stem}.yaml")
            count += 1
        print(f"  mihomo/country/ — {len(list(out_country.glob('*.yaml')))} files")

    # 1000-chunk files
    chunk_dir = subs_dir / "1000"
    if chunk_dir.is_dir():
        out_chunks = out_dir / "1000"
        for f in sorted(chunk_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_chunks / f"{f.stem}.yaml")
            count += 1
        print(f"  mihomo/1000/ — {len(list(out_chunks.glob('*.yaml')))} files")

    print(f"\nDone. {count} mihomo config files written to {out_dir}")
    return 0


def _write_config(config: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    yaml_text = _dump_yaml(config)
    path.write_text(yaml_text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate mihomo YAML configs from subs/*.txt node URLs"
    )
    parser.add_argument("--subs-dir", type=str, default=str(ROOT / "subs"),
                        help="Input subs directory (default: ./subs)")
    parser.add_argument("--out-dir", type=str, default=str(ROOT / "mihomo"),
                        help="Output directory for configs (default: ./mihomo)")
    args = parser.parse_args()

    subs_dir = Path(args.subs_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    return generate(subs_dir, out_dir)


if __name__ == "__main__":
    sys.exit(main())
