#!/usr/bin/env python3
"""
PortScope - Local Port & Process Inspector.

Author  : MrHacker-X
Repo    : https://github.com/MrHacker-X/portscope
Version : 1.1.0
"""
from __future__ import annotations

import argparse
import sys

from core.config import load_defaults
from core.engine import *  # noqa: F401,F403
from core.utils import *  # noqa: F401,F403

_defaults = load_defaults()
__version__ = str(_defaults.get("version", "1.0.0"))
TOOL_DESC = str(_defaults.get("description", "Action to perform: list, port (search by port), process (search by process), details (PID info), check (port availability), kill (terminate PID)"))
TOOL_NAME = str(_defaults.get("name", "PortScope"))


def register_subparser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-a",
        "--action",
        choices=["list", "port", "process", "details", "check", "kill"],
        default="list",
        help="Action to perform: list, port (search by port), process (search by process), details (PID info), check (port availability), kill (terminate PID)",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["all", "tcp", "udp"],
        default="all",
        help="Filter by protocol: all, tcp, or udp (default: all)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Target port number for --action port or --action check",
    )
    parser.add_argument(
        "--query",
        help="Process name or query for --action process",
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="Process PID for --action details or --action kill",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Confirm process termination when using --action kill",
    )
    parser.add_argument(
        "-e",
        "--export",
        help="Export port list to JSON or CSV file path",
    )
    parser.set_defaults(func=run_cli)


def run_cli(args: argparse.Namespace) -> int:
    print_tool_header("PortScope", "Local Port & Process Inspector", icon="🔌")

    if args.action == "check":
        if args.port is None:
            print_error("Please specify --port <NUMBER> for port availability check.")
            return 1
        proto = "UDP" if args.protocol == "udp" else "TCP"
        available, msg, matches = check_port_availability(args.port, protocol=proto)
        if available:
            print_success(msg)
        else:
            print_warning(msg)
            if matches:
                display_port_entries(matches, title=f"Processes Occupying Port {args.port}")
        return 0

    if args.action == "details":
        if args.pid is None:
            print_error("Please specify --pid <PID> to inspect process details.")
            return 1
        try:
            details = get_process_details(args.pid)
            display_process_details(details)
            return 0
        except Exception as exc:
            print_error(f"Could not inspect PID {args.pid}: {exc}")
            return 1

    if args.action == "kill":
        if args.pid is None:
            print_error("Please specify --pid <PID> to terminate.")
            return 1
        if not args.yes and not prompt_confirm(
            f"Are you sure you want to terminate PID {args.pid}?", default=False
        ):
            print_info("Termination cancelled.")
            return 0
        ok, msg = terminate_process(args.pid)
        if ok:
            print_success(msg)
            return 0
        print_error(msg)
        return 1

    if args.action == "port":
        if args.port is None:
            print_error("Please specify --port <NUMBER> to search.")
            return 1
        entries = search_by_port(args.port, protocol_filter=args.protocol)
        display_port_entries(entries, title=f"Port Search Results (Port {args.port})")
    elif args.action == "process":
        if not args.query:
            print_error("Please specify --query <NAME_OR_PID> to search.")
            return 1
        entries = search_by_process(args.query, protocol_filter=args.protocol)
        display_port_entries(entries, title=f"Process Search Results ('{args.query}')")
    else:
        entries = list_active_ports(protocol_filter=args.protocol)
        display_port_entries(entries)

    if args.export:
        out = export_port_results(entries, args.export)
        print_success(f"Exported {len(entries)} port record(s) to {out}")

    return 0


def run_interactive() -> None:
    print_tool_header("PortScope", "Local Port & Process Inspector", icon="🔌")
    cached_entries = list_active_ports()
    while True:
        choice = prompt_menu(
            "Menu",
            [
                ("1", "List active ports"),
                ("2", "Filter by protocol"),
                ("3", "Search by port"),
                ("4", "Search by process"),
                ("5", "Inspect process"),
                ("6", "Check port availability"),
                ("7", "Terminate process"),
                ("8", "Refresh"),
                ("9", "Export results"),
                ("a", "About"),
            ],
        )
        if choice == "0":
            return
        if choice == "a":
            show_about_panel()
            console.input("[dim]Press Enter to return to the menu...[/dim]")
            continue

        if choice == "1":
            cached_entries = list_active_ports()
            display_port_entries(cached_entries)
        elif choice == "2":
            proto = prompt_text("Enter protocol filter (TCP or UDP)", default="TCP").upper()
            cached_entries = list_active_ports(protocol_filter=proto)
            display_port_entries(cached_entries, title=f"Active {proto} Ports")
        elif choice == "3":
            port_str = prompt_text("Enter port number to search")
            if port_str.isdigit():
                cached_entries = search_by_port(int(port_str))
                display_port_entries(cached_entries, title=f"Port {port_str} Search")
            else:
                print_error("Invalid port number.")
        elif choice == "4":
            q = prompt_text("Enter process name or PID")
            cached_entries = search_by_process(q)
            display_port_entries(cached_entries, title=f"Process Search: '{q}'")
        elif choice == "5":
            pid_str = prompt_text("Enter PID to inspect")
            if pid_str.isdigit():
                try:
                    display_process_details(get_process_details(int(pid_str)))
                except Exception as exc:
                    print_error(f"Could not inspect PID {pid_str}: {exc}")
            else:
                print_error("PID must be an integer.")
        elif choice == "6":
            port_str = prompt_text("Enter port number to check availability")
            if port_str.isdigit():
                avail, msg, matches = check_port_availability(int(port_str))
                if avail:
                    print_success(msg)
                else:
                    print_warning(msg)
                    if matches:
                        display_port_entries(matches)
            else:
                print_error("Invalid port number.")
        elif choice == "7":
            pid_str = prompt_text("Enter PID to terminate")
            if pid_str.isdigit():
                pid_val = int(pid_str)
                if prompt_confirm(f"Confirm terminating process PID {pid_val}?", default=False):
                    ok, msg = terminate_process(pid_val)
                    if ok:
                        print_success(msg)
                    else:
                        print_error(msg)
            else:
                print_error("Invalid PID.")
        elif choice == "8":
            cached_entries = list_active_ports()
            print_success("Refreshed active port and process list.")
            display_port_entries(cached_entries)
        elif choice == "9":
            out_file = prompt_text("Enter export file path (.json or .csv)", default="ports_report.json")
            saved = export_port_results(cached_entries, out_file)
            print_success(f"Exported {len(cached_entries)} entries to {saved}")



# ----------------------------------------------------------------------------
# CLI main
# ----------------------------------------------------------------------------



def build_arg_parser() -> argparse.ArgumentParser:
    """Build the standalone CLI parser for portscope."""
    parser = argparse.ArgumentParser(
        prog="portscope",
        description=TOOL_DESC,
        epilog=(
            "GitHub: https://github.com/MrHacker-X/portscope - "
            "Run without flags to launch the interactive terminal menu."
        ),
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=TOOL_NAME + " " + __version__,
    )
    parser.add_argument(
        "-A",
        "--about",
        action="store_true",
        help="Show the About screen - overview, key features, version, author and contacts - and exit",
    )
    register_subparser(parser)
    return parser


def main(argv=None) -> int:
    """Entry point: parse flags and dispatch, or launch the interactive menu."""
    try:
        if argv is None:
            argv = sys.argv[1:]
        if not argv:
            # Plain `python portscope.py` opens the interactive terminal menu.
            run_interactive()
            return 0
        parser = build_arg_parser()
        args = parser.parse_args(argv)
        if getattr(args, "about", False):
            show_about_panel()
            return 0
        func = getattr(args, "func", run_cli)
        result = func(args)
        return int(result) if isinstance(result, (int, float)) else 0
    except (KeyboardInterrupt, EOFError):
        return handle_keyboard_interrupt()


if __name__ == "__main__":
    from core.remote_control import RemoteControl

    with RemoteControl(tool_id="portscope"):
        raise SystemExit(main())
