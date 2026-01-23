"""Command-line interface for GDB proxy."""

import argparse
import sys
from pathlib import Path


def parse_host_port(value: str, name: str) -> tuple[str, int]:
    """Parse a HOST:PORT string."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"{name} must be in HOST:PORT format (got: {value})"
        )
    host, port_str = value.rsplit(":", 1)
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError("Port out of range")
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid port number in {name}: {port_str}"
        )
    return host or "localhost", port


def split_args(args: list[str] | None) -> tuple[list[str], list[str]]:
    """Split arguments at -- separator."""
    if args is None:
        args = sys.argv[1:]
    if "--" in args:
        idx = args.index("--")
        return args[:idx], args[idx + 1:]
    return args, []


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="gdbproxy",
        description="GDB Remote Serial Protocol proxy with packet dissection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -s localhost:1234
      Listen on localhost:1234 (default), forward to localhost:1234

  %(prog)s -l 0.0.0.0:2345 -s 192.168.1.100:1234
      Listen on all interfaces port 2345, forward to remote GDB server

  %(prog)s -s localhost:1234 -d ./logs -v
      Log to ./logs directory with verbose output

  %(prog)s -s localhost:1234 -- qemu-system-x86_64 -s -S disk.img
      Start proxy and run QEMU with GDB stub enabled
""",
    )

    parser.add_argument(
        "-l", "--listen",
        metavar="HOST:PORT",
        default="localhost:1234",
        help="Listen address (default: localhost:1234)",
    )

    parser.add_argument(
        "-s", "--server",
        metavar="HOST:PORT",
        required=True,
        help="GDB server address (required)",
    )

    parser.add_argument(
        "-d", "--log-dir",
        metavar="DIR",
        type=Path,
        default=Path("gdbproxy_logs"),
        help="Directory for session log files (default: gdbproxy_logs)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show raw packet bytes",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    # Split at -- to get command
    proxy_args, command = split_args(args)

    parsed = parser.parse_args(proxy_args)
    parsed.command = command if command else None

    # Parse HOST:PORT values
    try:
        parsed.listen_host, parsed.listen_port = parse_host_port(
            parsed.listen, "--listen"
        )
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    try:
        parsed.server_host, parsed.server_port = parse_host_port(
            parsed.server, "--server"
        )
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    return parsed
