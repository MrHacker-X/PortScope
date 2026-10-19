#!/usr/bin/env python3
"""PortScope configuration constants (built-in, self-contained)."""
from __future__ import annotations

_CONFIGS: dict = {
    "defaults.json": {
        "tool": "portscope",
        "name": "PortScope",
        "subtitle": "Local Port & Process Inspector",
        "version": "1.1.0",
        "description": "Action to perform: list, port (search by port), process (search by process), details (PID info), check (port availability), kill (terminate PID)",
        "homepage": "https://github.com/MrHacker-X/portscope",
        "author": "MrHacker-X",
        "email": "contact@vritrasec.com",
        "website": "https://vritrasec.com",
        "network": "https://link.vritrasec.com",
        "about_overview": (
            "PortScope is a local port and process inspector: it shows live listeners on every interface, maps ports to owning processes, checks whether a port is free, and can safely terminate processes - all from userspace, with no raw sockets or elevated privileges required."
        ),
        "about_features": [
            "Live list of active TCP/UDP listeners and their owners",
            "Search by port, process name or PID",
            "Port availability checks before you bind a service",
            "Safe process termination with confirmation",
            "Export results to JSON or CSV",
            "Dual interface: interactive menu or direct CLI flags",
        ]
    },
    "portscope_profile.json": {
        "reserved_protocols": [
            "TCP",
            "UDP"
        ],
        "terminating_signal": "SIGTERM",
        "terminating_signal_force": "SIGKILL",
        "terminate_wait_seconds": 3.0,
        "force_kickoff_grace_seconds": 1.0
    }
}


def load_tool_data(filename: str) -> dict:
    """Return the built-in configuration table stored under `filename`."""
    return dict(_CONFIGS.get(filename, {}))


def load_defaults() -> dict:
    """Return the tool identity / defaults configuration."""
    return dict(_CONFIGS.get("defaults.json", {}))
