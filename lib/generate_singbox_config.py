#!/usr/bin/env python3
"""generate_singbox_config — convert subs/*.txt node URLs into sing-box JSON configs.

Mirrors the subs/ folder structure:
  - mix.json            — all nodes + urltest LB
  - country/*.json      — nodes by country + urltest LB
  - protocol/*.json     — nodes by protocol + urltest LB
  - 1000/*.json         — chunks of 1000 + urltest LB each

Each config has:
  - A local `mixed` inbound (SOCKS5 + HTTP) on 127.0.0.1:1080
  - One outbound per node (parsed from the raw URL)
  - A `urltest` outbound as the default load balancer (least-ping by HTTP RTT)
  - route.final → urltest (all traffic goes through the LB)

Usage:
  python3 lib/generate_singbox_config.py                    # default: reads subs/, writes sing-box/
  python3 lib/generate_singbox_config.py --subs-dir subs --out-dir sing-box
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure lib/ is on sys.path so parse_nodes is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_nodes import NodeConfig, load_all_nodes, load_nodes_from_file

ROOT = Path(__file__).resolve().parent.parent


def _node_to_singbox_outbound(nc: NodeConfig) -> dict:
    """Convert a NodeConfig to a sing-box outbound JSON object."""
    out: dict = {
        "tag": nc.tag,
        "server": nc.server,
        "server_port": nc.port,
    }

    # --- Per-protocol settings ---
    if nc.scheme == "vless":
        out["type"] = "vless"
        out["uuid"] = nc.uuid
        if nc.flow:
            out["flow"] = nc.flow

    elif nc.scheme == "vmess":
        out["type"] = "vmess"
        out["uuid"] = nc.uuid
        if nc.security and nc.security != "auto":
            out["security"] = nc.security
        elif nc.security and nc.security == "auto":
            pass  # sing-box defaults to auto
        # Xray AEAD: alterId=0 → security auto; just set uuid

    elif nc.scheme == "ss":
        out["type"] = "shadowsocks"
        out["method"] = nc.cipher
        out["password"] = nc.password
        if nc.plugin:
            out["plugin"] = {
                "enabled": True,
                "name": nc.plugin,
                "options": nc.plugin_opts if nc.plugin_opts else {},
            }

    elif nc.scheme == "trojan":
        out["type"] = "trojan"
        out["password"] = nc.password

    elif nc.scheme in ("hysteria2", "hy2"):
        out["type"] = "hysteria2"
        if nc.password:
            out["password"] = nc.password
        elif nc.auth:
            out["password"] = nc.auth
        if nc.obfs:
            out["obfs"] = nc.obfs
        if nc.obfs_password:
            out["obfs_password"] = nc.obfs_password

    elif nc.scheme == "hysteria":
        out["type"] = "hysteria"
        if nc.auth:
            out["auth"] = nc.auth
        if nc.obfs:
            out["obfs"] = nc.obfs

    elif nc.scheme == "tuic":
        out["type"] = "tuic"
        out["uuid"] = nc.uuid
        out["password"] = nc.password
        if nc.congestion_control:
            out["congestion_control"] = nc.congestion_control

    elif nc.scheme == "socks5":
        out["type"] = "socks"
        if nc.username:
            out["username"] = nc.username
        if nc.password:
            out["password"] = nc.password

    # --- TLS ---
    if nc.tls or nc.tls is True or (nc.scheme in ("vless", "vmess", "trojan", "tuic", "hysteria", "hysteria2") and nc.tls):
        tls: dict = {"enabled": True}
        if nc.allow_insecure:
            tls["insecure"] = True
        if nc.sni:
            tls["server_name"] = nc.sni
        if nc.alpn:
            tls["alpn"] = {"enabled": True, "protocols": nc.alpn}
        # Reality
        if nc.reality:
            tls["reality"] = {
                "enabled": True,
                "public_key": nc.public_key,
            }
            if nc.short_id:
                tls["reality"]["short_id"] = nc.short_id
        # UTLS fingerprint
        if nc.fingerprint:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": nc.fingerprint,
            }
        out["tls"] = tls

    # --- Transport ---
    if nc.network:
        transport: dict = {}
        net = nc.network

        if net in ("ws", "httpupgrade"):
            transport["type"] = "ws"
            transport["path"] = nc.ws_path or "/"
            if nc.ws_headers:
                transport["headers"] = nc.ws_headers
            if nc.max_early_data > 0:
                transport["max_early_data"] = nc.max_early_data
                if nc.early_data_header:
                    transport["early_data_header_name"] = nc.early_data_header
            out["transport"] = transport
        elif net == "http":
            transport["type"] = "http"
            transport["path"] = nc.http_path or "/"
            if nc.http_headers:
                transport["headers"] = nc.http_headers
            if nc.max_early_data > 0:
                transport["max_early_data"] = nc.max_early_data
            out["transport"] = transport
        elif net == "h2":
            transport["type"] = "http2"
            transport["path"] = nc.h2_path or "/"
            if nc.h2_host:
                transport["authoritative_domains"] = [nc.h2_host]
            out["transport"] = transport
        elif net == "grpc":
            transport["type"] = "grpc"
            if nc.grpc_service:
                transport["service_name"] = nc.grpc_service
            out["transport"] = transport
        elif net == "xhttp":
            transport["type"] = "http"
            transport["method"] = "POST"
            transport["path"] = nc.http_path or "/"
            if nc.http_headers.get("Host"):
                transport["headers"] = {"Host": nc.http_headers["Host"]}
            out["transport"] = transport

    # --- Multiplex ---
    if nc.max_early_data > 0 or nc.network in ("ws", "http"):
        out["multiplex"] = {
            "enabled": True,
            "max_connections": 8,
            "max_streams": 8,
        }

    return out


def _build_config(nodes: list[NodeConfig], *, lb_tag: str = "urltest") -> dict:
    """Build a complete sing-box config with all nodes + a urltest LB."""
    inbounds: list[dict] = [{
        "type": "mixed",
        "listen": "127.0.0.1",
        "listen_port": 1080,
        "tag": "local",
    }]

    outbounds: list[dict] = []
    node_tags: list[str] = []

    for nc in nodes:
        ob = _node_to_singbox_outbound(nc)
        outbounds.append(ob)
        node_tags.append(ob["tag"])

    # Default load-balancer outbound
    outbounds.append({
        "tag": lb_tag,
        "type": "urltest",
        "outbounds": node_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "3m",
        "tolerance": 50,
        "idle_timeout": "30m",
    })

    config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"final": lb_tag},
        "dns": {
            "servers": [{"tag": "local", "address": "1.1.1.1", "detour": "local"}],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "local",
        },
    }

    return config


def _write_config(config: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")


def generate(subs_dir: Path, out_dir: Path) -> int:
    """Generate sing-box configs mirroring the subs/ layout."""
    if not subs_dir.exists():
        print(f"generate_singbox: subs dir not found: {subs_dir}", file=sys.stderr)
        return 1

    count = 0

    # mix.json — ALL nodes
    all_nodes = load_all_nodes(subs_dir)
    cfg = _build_config(all_nodes)
    _write_config(cfg, out_dir / "mix.json")
    count += 1
    print(f"  sing-box/mix.json — {len(all_nodes)} nodes")

    # country/*.json
    country_dir = subs_dir / "country"
    if country_dir.is_dir():
        out_country = out_dir / "country"
        for f in sorted(country_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_country / f"{f.stem}.json")
            count += 1
        print(f"  sing-box/country/ — {len(list((out_country).glob('*.json')))} files")

    # protocol/*.json (from subs/protocols/)
    proto_dir = subs_dir / "protocols"
    if proto_dir.is_dir():
        out_proto = out_dir / "protocol"
        for f in sorted(proto_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_proto / f"{f.stem}.json")
            count += 1
        print(f"  sing-box/protocol/ — {len(list(out_proto.glob('*.json')))} files")

    # 1000/*.json
    chunk_dir = subs_dir / "1000"
    if chunk_dir.is_dir():
        out_chunks = out_dir / "1000"
        for f in sorted(chunk_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_chunks / f"{f.stem}.json")
            count += 1
        print(f"  sing-box/1000/ — {len(list(out_chunks.glob('*.json')))} files")

    print(f"\nDone. {count} sing-box config files written to {out_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate sing-box JSON configs from subs/*.txt node URLs"
    )
    parser.add_argument("--subs-dir", type=str, default=str(ROOT / "subs"),
                        help="Input subs directory (default: ./subs)")
    parser.add_argument("--out-dir", type=str, default=str(ROOT / "sing-box"),
                        help="Output directory for configs (default: ./sing-box)")
    args = parser.parse_args()

    subs_dir = Path(args.subs_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    return generate(subs_dir, out_dir)


if __name__ == "__main__":
    sys.exit(main())
