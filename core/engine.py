#!/usr/bin/env python3
"""PortScope core logic."""
from __future__ import annotations

from .config import load_tool_data

import argparse
import csv
import json
import os
import signal
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import psutil

from .utils import (
    console,
    format_bytes,
    make_table,
    print_error,
    print_info,
    print_success,
    print_tool_header,
    print_warning,
    prompt_confirm,
    prompt_menu,
    prompt_text,
)


@dataclass
class PortEntry:
    protocol: str  # TCP | UDP
    local_ip: str
    local_port: int
    interface: str
    status: str
    pid: Optional[int]
    process_name: str
    cmdline: str = ""
    username: str = ""


@dataclass
class ProcessDetails:
    pid: int
    name: str
    status: str
    username: str
    exe: str
    cwd: str
    cmdline: str
    create_time: str
    cpu_percent: float
    memory_rss: int
    num_threads: int
    open_ports: List[int] = field(default_factory=list)


def _build_ip_interface_map() -> Dict[str, str]:
    """Map local IP addresses to network interface names (e.g., 127.0.0.1 -> lo)."""
    mapping: Dict[str, str] = {
        "0.0.0.0": "all-ipv4 (*)",
        "::": "all-ipv6 (*)",
        "*": "all (*)",
    }
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for snic in addrs:
                if snic.address:
                    addr_clean = snic.address.split("%")[0]
                    mapping[addr_clean] = iface
    except Exception:
        pass
    return mapping


def _enrich_process_info(pid: Optional[int]) -> Tuple[str, str, str]:
    """Return (process_name, cmdline, username) for a PID if accessible."""
    if not pid:
        return ("-", "", "")
    try:
        proc = psutil.Process(pid)
        name = proc.name() or f"pid-{pid}"
        try:
            cmdline = " ".join(proc.cmdline()[:6])
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = ""
        try:
            username = proc.username()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            username = ""
        return (name, cmdline, username)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return (f"pid-{pid}", "", "")


def list_active_ports(protocol_filter: Optional[str] = None) -> List[PortEntry]:
    """List active listening TCP and bound UDP sockets on the local machine."""
    iface_map = _build_ip_interface_map()
    proto_norm = (protocol_filter or "all").strip().upper()
    entries: List[PortEntry] = []
    seen_keys = set()

    def _add_conn(proto_label: str, conn: Any) -> None:
        if not getattr(conn, "laddr", None):
            return
        ip = getattr(conn.laddr, "ip", None) or conn.laddr[0]
        port = getattr(conn.laddr, "port", None) or conn.laddr[1]
        status = getattr(conn, "status", "") or ("UDP-BOUND" if proto_label == "UDP" else "LISTEN")

        if proto_label == "TCP" and status not in ("LISTEN", "ESTABLISHED", "NONE"):
            return
        if proto_label == "TCP" and status == "ESTABLISHED":
            # Focus on listening sockets for active port listing unless no LISTEN exists
            return

        pid = getattr(conn, "pid", None)
        key = (proto_label, str(ip), int(port), pid)
        if key in seen_keys:
            return
        seen_keys.add(key)

        pname, cmdline, username = _enrich_process_info(pid)
        clean_ip = str(ip).split("%")[0]
        iface = iface_map.get(clean_ip, "custom/virtual")
        entries.append(
            PortEntry(
                protocol=proto_label,
                local_ip=str(ip),
                local_port=int(port),
                interface=iface,
                status=status if status != "NONE" else "BOUND",
                pid=pid,
                process_name=pname,
                cmdline=cmdline,
                username=username,
            )
        )

    # 1. Try system-wide psutil.net_connections
    kinds = []
    if proto_norm in ("ALL", "TCP"):
        kinds.append(("TCP", "tcp"))
    if proto_norm in ("ALL", "UDP"):
        kinds.append(("UDP", "udp"))

    for proto_label, kind in kinds:
        try:
            for c in psutil.net_connections(kind=kind):
                _add_conn(proto_label, c)
        except (psutil.AccessDenied, PermissionError):
            pass

    # 2. Also scan accessible per-process connections to ensure PIDs are populated on restricted OSes
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for c in proc.net_connections(kind="inet"):
                c_type = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                if proto_norm not in ("ALL", c_type):
                    continue
                if c_type == "TCP" and c.status != "LISTEN":
                    continue
                if not c.laddr:
                    continue
                ip = getattr(c.laddr, "ip", None) or c.laddr[0]
                port = getattr(c.laddr, "port", None) or c.laddr[1]
                # Replace any entry missing PID for this (proto, ip, port)
                existing_idx = next(
                    (
                        i
                        for i, e in enumerate(entries)
                        if e.protocol == c_type and e.local_ip == str(ip) and e.local_port == int(port)
                    ),
                    None,
                )
                pname, cmdline, username = _enrich_process_info(proc.pid)
                clean_ip = str(ip).split("%")[0]
                new_entry = PortEntry(
                    protocol=c_type,
                    local_ip=str(ip),
                    local_port=int(port),
                    interface=iface_map.get(clean_ip, "custom/virtual"),
                    status=c.status if c.status != "NONE" else "BOUND",
                    pid=proc.pid,
                    process_name=pname,
                    cmdline=cmdline,
                    username=username,
                )
                if existing_idx is not None:
                    if entries[existing_idx].pid is None:
                        entries[existing_idx] = new_entry
                else:
                    entries.append(new_entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    entries.sort(key=lambda e: (e.local_port, e.protocol, e.local_ip))
    return entries


def search_by_port(port: int, protocol_filter: Optional[str] = None) -> List[PortEntry]:
    """Find listening sockets and processes using a specific local port."""
    all_ports = list_active_ports(protocol_filter=protocol_filter)
    return [e for e in all_ports if e.local_port == int(port)]


def search_by_process(query: str, protocol_filter: Optional[str] = None) -> List[PortEntry]:
    """Locate ports opened by a specific process name, command line, or PID."""
    q = query.strip().lower()
    all_ports = list_active_ports(protocol_filter=protocol_filter)
    matched: List[PortEntry] = []
    for e in all_ports:
        if (
            q in e.process_name.lower()
            or q in e.cmdline.lower()
            or (e.pid is not None and q == str(e.pid))
        ):
            matched.append(e)
    return matched


def get_process_details(pid: int) -> ProcessDetails:
    """Inspect comprehensive details about a selected process by PID."""
    proc = psutil.Process(int(pid))
    with proc.oneshot():
        name = proc.name()
        status = proc.status()
        try:
            username = proc.username()
        except psutil.AccessDenied:
            username = "AccessDenied"
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            exe = "AccessDenied"
        try:
            cwd = proc.cwd()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cwd = "AccessDenied"
        try:
            cmdline = " ".join(proc.cmdline())
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = ""
        create_dt = datetime.fromtimestamp(proc.create_time()).isoformat(timespec="seconds")
        cpu_pct = proc.cpu_percent(interval=0.05)
        mem_rss = proc.memory_info().rss
        threads = proc.num_threads()

    ports = sorted({e.local_port for e in list_active_ports() if e.pid == int(pid)})
    return ProcessDetails(
        pid=int(pid),
        name=name,
        status=status,
        username=username,
        exe=exe,
        cwd=cwd,
        cmdline=cmdline,
        create_time=create_dt,
        cpu_percent=cpu_pct,
        memory_rss=mem_rss,
        num_threads=threads,
        open_ports=ports,
    )


def _load_tool_data(filename: str) -> dict:
    """Thin alias: load this tool's own config via core/config.py."""
    return load_tool_data(filename)


TOOL_DATA = _load_tool_data("portscope_profile.json")
TERMINATE_WAIT_SECONDS = float(TOOL_DATA.get("terminate_wait_seconds", 3.0))


def terminate_process(pid: int, force: bool = False, timeout: float = TERMINATE_WAIT_SECONDS) -> Tuple[bool, str]:
    """Terminate a process by PID cleanly (SIGTERM) or forcefully (SIGKILL)."""
    try:
        proc = psutil.Process(int(pid))
        pname = proc.name()
        if force:
            proc.kill()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.0)
        return (True, f"Process '{pname}' (PID {pid}) terminated successfully.")
    except psutil.NoSuchProcess:
        return (False, f"Process with PID {pid} does not exist.")
    except psutil.AccessDenied:
        return (False, f"Access denied when attempting to terminate PID {pid}.")
    except Exception as exc:
        return (False, f"Failed to terminate PID {pid}: {exc}")


def check_port_availability(
    port: int,
    host: str = "127.0.0.1",
    protocol: str = "TCP",
) -> Tuple[bool, str, List[PortEntry]]:
    """Check whether a local port is free or currently occupied."""
    proto = protocol.upper()
    active_matches = search_by_port(port, protocol_filter=proto)
    if active_matches:
        owners = ", ".join(
            f"{m.process_name} (PID {m.pid or '?'})" for m in active_matches
        )
        return (False, f"Port {port}/{proto} is OCCUPIED by: {owners}", active_matches)

    # Also test actual socket binding on the requested host
    sock_type = socket.SOCK_STREAM if proto == "TCP" else socket.SOCK_DGRAM
    try:
        with socket.socket(socket.AF_INET, sock_type) as s:
            if proto == "TCP":
                # Check if anything is actively listening via connect_ex first
                if s.connect_ex((host, int(port))) == 0:
                    return (
                        False,
                        f"Port {port}/{proto} on {host} is OCCUPIED (accepting connections).",
                        active_matches,
                    )
    except OSError:
        pass

    return (True, f"Port {port}/{proto} on {host} is AVAILABLE (free).", [])


def export_port_results(
    entries: Sequence[PortEntry],
    output_path: Path | str,
    fmt: Optional[str] = None,
) -> Path:
    """Export port and process table to JSON or CSV."""
    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    export_format = (fmt or out.suffix.lstrip(".") or "json").lower()

    if export_format == "csv":
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
                    "protocol",
                    "local_ip",
                    "local_port",
                    "interface",
                    "status",
                    "pid",
                    "process_name",
                    "username",
                    "cmdline",
                ],
            )
            writer.writeheader()
            for e in entries:
                writer.writerow(asdict(e))
    else:
        payload = {
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "count": len(entries),
            "ports": [asdict(e) for e in entries],
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def display_port_entries(entries: Sequence[PortEntry], title: str = "Active Local Ports & Processes") -> None:
    if not entries:
        print_warning("No matching active ports found.")
        return

    rows = [
        (
            e.protocol,
            e.local_ip,
            str(e.local_port),
            e.interface,
            e.status,
            str(e.pid) if e.pid is not None else "-",
            e.process_name,
            e.cmdline[:60] if e.cmdline else "-",
        )
        for e in entries
    ]
    console.print()
    console.print(
        make_table(
            title=f"{title} ({len(entries)} socket(s))",
            columns=[
                ("Proto", "bold magenta"),
                ("Local IP", "cyan"),
                ("Port", "bold green"),
                ("Interface", "dim white"),
                ("State", "yellow"),
                ("PID", "bold cyan"),
                ("Process", "bold white"),
                ("Command Line", "dim white"),
            ],
            rows=rows,
        )
    )


def display_process_details(details: ProcessDetails) -> None:
    rows = [
        ("PID", str(details.pid)),
        ("Process Name", details.name),
        ("Status", details.status),
        ("Username", details.username),
        ("Executable", details.exe),
        ("Working Directory", details.cwd),
        ("Command Line", details.cmdline or "-"),
        ("Created At", details.create_time),
        ("CPU Usage", f"{details.cpu_percent:.1f}%"),
        ("Memory (RSS)", format_bytes(details.memory_rss)),
        ("Threads", str(details.num_threads)),
        ("Bound Local Ports", ", ".join(str(p) for p in details.open_ports) or "None"),
    ]
    console.print()
    console.print(
        make_table(
            title=f"Process Details - {details.name} (PID {details.pid})",
            columns=[("Property", "bold cyan"), ("Value", "white")],
            rows=rows,
        )
    )
