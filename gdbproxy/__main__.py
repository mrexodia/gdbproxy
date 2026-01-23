"""Entry point for python -m gdbproxy."""

import asyncio
import sys

from .cli import parse_args
from .proxy import ProxyServer, run_with_subprocess


def main():
    args = parse_args()

    server = ProxyServer(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        server_host=args.server_host,
        server_port=args.server_port,
        verbose=args.verbose,
        use_color=not args.no_color,
        log_dir=args.log_dir,
    )

    try:
        if args.command:
            return_code = asyncio.run(run_with_subprocess(server, args.command))
            sys.exit(return_code)
        else:
            asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
