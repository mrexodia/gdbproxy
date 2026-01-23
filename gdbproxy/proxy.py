"""Async TCP proxy and session management for GDB RSP."""

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from .dissector import Dissector
from .packet import Packet, PacketParser, PacketType


class Logger:
    """Handles logging to stdout and optionally to a file."""

    def __init__(
        self,
        session_id: int,
        verbose: bool = False,
        use_color: bool = True,
        log_file: TextIO | None = None,
    ):
        self.session_id = session_id
        self.verbose = verbose
        self.use_color = use_color
        self.log_file = log_file
        self.dissector = Dissector()

        # ANSI colors
        self._colors = {
            "reset": "\033[0m",
            "client": "\033[36m",  # Cyan
            "server": "\033[33m",  # Yellow
            "info": "\033[32m",    # Green
            "error": "\033[31m",   # Red
            "dim": "\033[2m",      # Dim
        }

    def _color(self, name: str) -> str:
        if self.use_color:
            return self._colors.get(name, "")
        return ""

    def _timestamp(self) -> str:
        return datetime.now().strftime("[%H:%M:%S.%f]")[:-3]

    def _write(self, line: str):
        print(line, flush=True)
        if self.log_file:
            # Strip ANSI codes for log file
            import re
            clean = re.sub(r"\033\[[0-9;]*m", "", line)
            self.log_file.write(clean + "\n")
            self.log_file.flush()

    def session_started(self, client_addr: tuple[str, int], server_addr: tuple[str, int]):
        ts = self._timestamp()
        info = self._color("info")
        reset = self._color("reset")
        self._write(
            f"{ts} {info}Session {self.session_id} started{reset}: "
            f"server({server_addr[0]}:{server_addr[1]}) <-> client({client_addr[0]}:{client_addr[1]})"
        )

    def session_ended(self):
        ts = self._timestamp()
        info = self._color("info")
        reset = self._color("reset")
        self._write(f"{ts} {info}Session {self.session_id} ended{reset}")

    def log_packet(
        self,
        packet: Packet,
        from_client: bool,
    ):
        ts = self._timestamp()
        reset = self._color("reset")
        dim = self._color("dim")

        if from_client:
            direction = "<--"
            color = self._color("client")
        else:
            direction = "-->"
            color = self._color("server")

        # Format the raw packet for display
        raw_display = packet.raw.decode("latin-1")

        # Get dissection
        is_response = not from_client
        dissection = self.dissector.dissect(packet, is_response=is_response)

        # Log the packet
        self._write(f"{ts}   {color}{direction}{reset} {raw_display}")
        self._write(f"           {dim}{dissection}{reset}")

        # Verbose mode: show raw bytes
        if self.verbose and packet.type == PacketType.PACKET:
            hex_bytes = packet.data.hex()
            if len(hex_bytes) > 64:
                hex_bytes = hex_bytes[:64] + "..."
            self._write(f"           {dim}Raw: {hex_bytes}{reset}")

    def log_error(self, message: str):
        ts = self._timestamp()
        error = self._color("error")
        reset = self._color("reset")
        self._write(f"{ts} {error}Error:{reset} {message}")


class Session:
    """Manages a single proxy session between client and server."""

    def __init__(
        self,
        session_id: int,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        server_host: str,
        server_port: int,
        logger: Logger,
    ):
        self.session_id = session_id
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.server_host = server_host
        self.server_port = server_port
        self.logger = logger
        self.server_reader: asyncio.StreamReader | None = None
        self.server_writer: asyncio.StreamWriter | None = None
        self._running = False

    async def run(self):
        """Run the proxy session."""
        client_addr = self.client_writer.get_extra_info("peername")

        try:
            # Connect to server
            self.server_reader, self.server_writer = await asyncio.open_connection(
                self.server_host, self.server_port
            )
            self.logger.session_started(client_addr, (self.server_host, self.server_port))
            self._running = True

            # Run both directions concurrently
            await asyncio.gather(
                self._forward_client_to_server(),
                self._forward_server_to_client(),
            )
        except ConnectionRefusedError:
            self.logger.log_error(
                f"Connection refused to {self.server_host}:{self.server_port}"
            )
        except Exception as e:
            self.logger.log_error(f"Session error: {e}")
        finally:
            self._running = False
            await self._cleanup()
            self.logger.session_ended()

    async def _forward_client_to_server(self):
        """Forward data from client to server, parsing and logging packets."""
        parser = PacketParser()
        try:
            while self._running:
                data = await self.client_reader.read(4096)
                if not data:
                    break

                # Parse and log packets
                for packet in parser.feed(data):
                    self.logger.log_packet(packet, from_client=True)

                # Forward raw data to server
                if self.server_writer:
                    self.server_writer.write(data)
                    await self.server_writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self._running:
                self.logger.log_error(f"Client->Server error: {e}")
        finally:
            self._running = False

    async def _forward_server_to_client(self):
        """Forward data from server to client, parsing and logging packets."""
        parser = PacketParser()
        try:
            while self._running and self.server_reader:
                data = await self.server_reader.read(4096)
                if not data:
                    break

                # Parse and log packets
                for packet in parser.feed(data):
                    self.logger.log_packet(packet, from_client=False)

                # Forward raw data to client
                self.client_writer.write(data)
                await self.client_writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self._running:
                self.logger.log_error(f"Server->Client error: {e}")
        finally:
            self._running = False

    async def _cleanup(self):
        """Clean up connections."""
        if self.server_writer:
            self.server_writer.close()
            try:
                await self.server_writer.wait_closed()
            except Exception:
                pass
        self.client_writer.close()
        try:
            await self.client_writer.wait_closed()
        except Exception:
            pass


class ProxyServer:
    """GDB RSP proxy server."""

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        server_host: str,
        server_port: int,
        verbose: bool = False,
        use_color: bool = True,
        log_dir: Path | None = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.verbose = verbose
        self.use_color = use_color
        self.log_dir = log_dir
        self._session_counter = 0
        self._server: asyncio.Server | None = None

    async def start(self):
        """Start the proxy server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        addr = self._server.sockets[0].getsockname()
        print(f"GDB proxy listening on {addr[0]}:{addr[1]}")
        print(f"Forwarding to {self.server_host}:{self.server_port}")
        print()

        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle a new client connection."""
        self._session_counter += 1
        session_id = self._session_counter

        # Create log file if log_dir is specified
        log_file = None
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            # Create .gitignore to exclude log files from version control
            gitignore_path = self.log_dir / ".gitignore"
            if not gitignore_path.exists():
                gitignore_path.write_text("*\n")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = self.log_dir / f"session_{session_id}_{timestamp}.log"
            log_file = open(log_path, "w")

        try:
            logger = Logger(
                session_id=session_id,
                verbose=self.verbose,
                use_color=self.use_color,
                log_file=log_file,
            )

            session = Session(
                session_id=session_id,
                client_reader=reader,
                client_writer=writer,
                server_host=self.server_host,
                server_port=self.server_port,
                logger=logger,
            )

            await session.run()
        finally:
            if log_file:
                log_file.close()

    def stop(self):
        """Stop the proxy server."""
        if self._server:
            self._server.close()


async def run_subprocess(command: list[str], use_color: bool = True) -> int:
    """Run a subprocess with stdout/stderr forwarded to console."""
    colors = {
        "reset": "\033[0m",
        "cmd": "\033[35m",  # Magenta
    }

    def color(name: str) -> str:
        return colors.get(name, "") if use_color else ""

    cmd_str = " ".join(command)
    print(f"{color('cmd')}[cmd]{color('reset')} Starting: {cmd_str}")
    print()

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def forward_stream(stream: asyncio.StreamReader, prefix: str):
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            print(f"{color('cmd')}[{prefix}]{color('reset')} {text}", flush=True)

    await asyncio.gather(
        forward_stream(process.stdout, "out"),
        forward_stream(process.stderr, "err"),
    )

    return await process.wait()


async def run_with_subprocess(
    server: ProxyServer,
    command: list[str],
) -> int:
    """Run proxy server alongside a subprocess."""
    # Start the subprocess
    subprocess_task = asyncio.create_task(
        run_subprocess(command, server.use_color)
    )

    # Start the proxy server
    server_task = asyncio.create_task(server.start())

    # Wait for subprocess to finish, then stop server
    try:
        return_code = await subprocess_task
        server.stop()
        return return_code
    except asyncio.CancelledError:
        subprocess_task.cancel()
        server.stop()
        raise
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
