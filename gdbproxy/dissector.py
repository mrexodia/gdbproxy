"""Human-readable packet decoding for GDB RSP."""

import re
from typing import Callable

from .constants import BREAKPOINT_TYPES, SIGNALS, STOP_REASONS, VCONT_ACTIONS
from .packet import Packet, PacketType


class Dissector:
    """Dissects GDB RSP packets into human-readable descriptions."""

    def __init__(self):
        self._last_command: str | None = None  # Track last command for response context
        self._command_handlers: dict[str, Callable[[str], str]] = {
            "m": self._dissect_read_memory,
            "M": self._dissect_write_memory,
            "x": self._dissect_read_memory_binary,
            "X": self._dissect_write_memory_binary,
            "g": self._dissect_read_registers,
            "G": self._dissect_write_registers,
            "p": self._dissect_read_register,
            "P": self._dissect_write_register,
            "c": self._dissect_continue,
            "C": self._dissect_continue_signal,
            "s": self._dissect_step,
            "S": self._dissect_step_signal,
            "Z": self._dissect_insert_breakpoint,
            "z": self._dissect_remove_breakpoint,
            "?": self._dissect_halt_reason,
            "k": self._dissect_kill,
            "D": self._dissect_detach,
            "!": self._dissect_extended_mode,
            "H": self._dissect_set_thread,
            "T": self._dissect_thread_alive,
            "R": self._dissect_restart,
        }
        self._v_handlers: dict[str, Callable[[str], str]] = {
            "vCont": self._dissect_vcont,
            "vCont?": self._dissect_vcont_query,
            "vKill": self._dissect_vkill,
            "vRun": self._dissect_vrun,
            "vAttach": self._dissect_vattach,
            "vStopped": self._dissect_vstopped,
            "vMustReplyEmpty": self._dissect_vmustreplyempty,
            "vFile:": self._dissect_vfile,
            "vFlashErase": self._dissect_vflash_erase,
            "vFlashWrite": self._dissect_vflash_write,
            "vFlashDone": self._dissect_vflash_done,
        }
        self._q_handlers: dict[str, Callable[[str], str]] = {
            "qSupported": self._dissect_qsupported,
            "qXfer": self._dissect_qxfer,
            "qRcmd": self._dissect_qrcmd,
            "qC": self._dissect_qc,
            "qAttached": self._dissect_qattached,
            "qOffsets": self._dissect_qoffsets,
            "qfThreadInfo": self._dissect_qthreadinfo,
            "qsThreadInfo": self._dissect_qthreadinfo,
            "qSymbol": self._dissect_qsymbol,
            "qTStatus": self._dissect_qtstatus,
            "qRegisterInfo": self._dissect_qregisterinfo,
            "qHostInfo": self._dissect_qhostinfo,
            "qProcessInfo": self._dissect_qprocessinfo,
            "qMemoryRegionInfo": self._dissect_qmemoryregioninfo,
        }

    def dissect(self, packet: Packet, is_response: bool = False) -> str:
        """Return human-readable description of packet."""
        if packet.type == PacketType.ACK:
            return "ACK"
        elif packet.type == PacketType.NACK:
            return "NACK (request retransmission)"
        elif packet.type == PacketType.INTERRUPT:
            return "Interrupt (Ctrl-C)"
        elif packet.type == PacketType.NOTIFICATION:
            return self._dissect_notification(packet.data_str)

        data = packet.data_str
        if not data:
            return "Empty packet"

        if is_response:
            result = self._dissect_response(data)
            return result
        else:
            # Track command for response context
            self._last_command = data
            return self._dissect_command(data)

    def _dissect_command(self, data: str) -> str:
        """Dissect a command packet from client."""
        if not data:
            return "Empty command"

        cmd = data[0]

        if cmd in self._command_handlers:
            return self._command_handlers[cmd](data)
        elif cmd == "v":
            return self._dissect_v_command(data)
        elif cmd == "q":
            return self._dissect_q_command(data)
        elif cmd == "Q":
            return self._dissect_Q_command(data)
        else:
            return f"Unknown command: {data}"

    def _dissect_response(self, data: str) -> str:
        """Dissect a response packet from server."""
        if not data:
            return "Empty response"

        if data == "OK":
            return "OK"
        elif data == "":
            return "Empty response (command not supported)"
        elif data == "l":
            return "End of list"
        elif data.startswith("l") and len(data) > 1:
            # qXfer final response: l<data>
            return self._dissect_qxfer_response(data[1:], final=True)
        elif data.startswith("m") and len(data) > 1:
            # Could be qXfer partial response or thread list
            rest = data[1:]
            # Check if it looks like a thread ID (mp01.01 format)
            if re.match(r"^p?[0-9a-fA-F]+(\.[0-9a-fA-F]+)?$", rest):
                return self._dissect_thread_id_response(rest)
            # Otherwise it's likely qXfer partial data
            return self._dissect_qxfer_response(rest, final=False)
        elif data.startswith("E"):
            return self._dissect_error(data)
        elif data[0] in ("S", "T"):
            return self._dissect_stop_reply(data)
        elif data[0] == "W":
            return self._dissect_exit_reply(data)
        elif data[0] == "X":
            return self._dissect_terminate_reply(data)
        elif data[0] == "O":
            return self._dissect_console_output(data)
        elif data[0] == "F":
            return self._dissect_file_io_response(data)
        elif data[0] == "b":
            return self._dissect_binary_memory_response(data)
        elif data.startswith("QC"):
            # Current thread response
            return f"Current thread: {data[2:]}"
        elif data.startswith("vCont"):
            # vCont? response listing supported actions
            return self._dissect_vcont_response(data)
        elif all(c in "0123456789abcdefABCDEF" for c in data):
            return self._dissect_hex_data(data)
        elif self._is_rle_hex_data(data):
            # RLE-encoded hex data (e.g., register values from 'g' command)
            return self._dissect_rle_hex_data(data)
        elif self._is_key_value_data(data):
            return self._dissect_key_value(data)
        else:
            return f"Response: {data}"

    def _dissect_notification(self, data: str) -> str:
        """Dissect an asynchronous notification."""
        if data.startswith("Stop:"):
            return f"Async stop notification: {data[5:]}"
        return f"Notification: {data}"

    def _dissect_read_memory(self, data: str) -> str:
        match = re.match(r"m([0-9a-fA-F]+),([0-9a-fA-F]+)", data)
        if match:
            addr, length = match.groups()
            return f"Read {int(length, 16)} bytes from 0x{addr}"
        return f"Read memory: {data}"

    def _dissect_write_memory(self, data: str) -> str:
        match = re.match(r"M([0-9a-fA-F]+),([0-9a-fA-F]+):", data)
        if match:
            addr, length = match.groups()
            return f"Write {int(length, 16)} bytes to 0x{addr}"
        return f"Write memory: {data}"

    def _dissect_read_memory_binary(self, data: str) -> str:
        match = re.match(r"x([0-9a-fA-F]+),([0-9a-fA-F]+)", data)
        if match:
            addr, length = match.groups()
            return f"Read {int(length, 16)} bytes (binary) from 0x{addr}"
        return f"Read memory (binary): {data}"

    def _dissect_write_memory_binary(self, data: str) -> str:
        match = re.match(r"X([0-9a-fA-F]+),([0-9a-fA-F]+):", data)
        if match:
            addr, length = match.groups()
            return f"Write {int(length, 16)} bytes (binary) to 0x{addr}"
        return f"Write memory (binary): {data}"

    def _dissect_read_registers(self, data: str) -> str:
        return "Read all registers"

    def _dissect_write_registers(self, data: str) -> str:
        return f"Write all registers ({len(data) - 1} hex chars)"

    def _dissect_read_register(self, data: str) -> str:
        reg = data[1:]
        try:
            reg_num = int(reg, 16)
            return f"Read register {reg_num}"
        except ValueError:
            return f"Read register: {reg}"

    def _dissect_write_register(self, data: str) -> str:
        match = re.match(r"P([0-9a-fA-F]+)=([0-9a-fA-F]+)", data)
        if match:
            reg, val = match.groups()
            return f"Write register {int(reg, 16)} = 0x{val}"
        return f"Write register: {data}"

    def _dissect_continue(self, data: str) -> str:
        if len(data) > 1:
            return f"Continue at 0x{data[1:]}"
        return "Continue"

    def _dissect_continue_signal(self, data: str) -> str:
        match = re.match(r"C([0-9a-fA-F]{2})(?:;([0-9a-fA-F]+))?", data)
        if match:
            sig = int(match.group(1), 16)
            sig_name = SIGNALS.get(sig, f"signal {sig}")
            addr = match.group(2)
            if addr:
                return f"Continue with {sig_name} at 0x{addr}"
            return f"Continue with {sig_name}"
        return f"Continue with signal: {data}"

    def _dissect_step(self, data: str) -> str:
        if len(data) > 1:
            return f"Single step at 0x{data[1:]}"
        return "Single step"

    def _dissect_step_signal(self, data: str) -> str:
        match = re.match(r"S([0-9a-fA-F]{2})(?:;([0-9a-fA-F]+))?", data)
        if match:
            sig = int(match.group(1), 16)
            sig_name = SIGNALS.get(sig, f"signal {sig}")
            addr = match.group(2)
            if addr:
                return f"Step with {sig_name} at 0x{addr}"
            return f"Step with {sig_name}"
        return f"Step with signal: {data}"

    def _dissect_insert_breakpoint(self, data: str) -> str:
        match = re.match(r"Z([0-4]),([0-9a-fA-F]+),([0-9a-fA-F]+)", data)
        if match:
            bp_type, addr, kind = match.groups()
            bp_name = BREAKPOINT_TYPES.get(int(bp_type), f"type {bp_type}")
            return f"Insert {bp_name} at 0x{addr}"
        return f"Insert breakpoint: {data}"

    def _dissect_remove_breakpoint(self, data: str) -> str:
        match = re.match(r"z([0-4]),([0-9a-fA-F]+),([0-9a-fA-F]+)", data)
        if match:
            bp_type, addr, kind = match.groups()
            bp_name = BREAKPOINT_TYPES.get(int(bp_type), f"type {bp_type}")
            return f"Remove {bp_name} at 0x{addr}"
        return f"Remove breakpoint: {data}"

    def _dissect_halt_reason(self, data: str) -> str:
        return "Query halt reason"

    def _dissect_kill(self, data: str) -> str:
        return "Kill target"

    def _dissect_detach(self, data: str) -> str:
        if len(data) > 1:
            pid = data[1:]
            # Handle D;pid format
            if pid.startswith(";"):
                pid = pid[1:]
            return f"Detach from process {pid}"
        return "Detach"

    def _dissect_extended_mode(self, data: str) -> str:
        return "Enable extended mode"

    def _dissect_set_thread(self, data: str) -> str:
        if len(data) > 1:
            op = data[1]
            thread = data[2:]
            op_name = "general ops" if op == "g" else "continue ops" if op == "c" else op
            if thread == "-1" or thread == "0":
                return f"Set thread for {op_name}: all threads"
            return f"Set thread for {op_name}: {thread}"
        return f"Set thread: {data}"

    def _dissect_thread_alive(self, data: str) -> str:
        return f"Check if thread {data[1:]} is alive"

    def _dissect_restart(self, data: str) -> str:
        return "Restart program"

    def _dissect_v_command(self, data: str) -> str:
        for cmd, handler in self._v_handlers.items():
            if data.startswith(cmd):
                return handler(data)
        return f"Extended command: {data}"

    def _dissect_vcont(self, data: str) -> str:
        if data == "vCont?":
            return "Query vCont support"
        actions = data[6:]  # Skip "vCont;"
        if not actions:
            return "vCont (no actions)"
        parts = []
        for action in actions.split(";"):
            if ":" in action:
                act, thread = action.split(":", 1)
            else:
                act, thread = action, None
            act_base = act[0] if act else ""
            act_name = VCONT_ACTIONS.get(act_base, act)
            if thread:
                parts.append(f"{act_name} thread {thread}")
            else:
                parts.append(act_name)
        return f"vCont: {', '.join(parts)}"

    def _dissect_vcont_query(self, data: str) -> str:
        return "Query vCont support"

    def _dissect_vkill(self, data: str) -> str:
        pid = data[6:] if len(data) > 6 else ""
        if pid:
            return f"Kill process {pid}"
        return "Kill process"

    def _dissect_vrun(self, data: str) -> str:
        args = data[5:]  # Skip "vRun;"
        return f"Run program: {args}"

    def _dissect_vattach(self, data: str) -> str:
        pid = data[8:]  # Skip "vAttach;"
        return f"Attach to process {pid}"

    def _dissect_vstopped(self, data: str) -> str:
        return "Acknowledge stop notification"

    def _dissect_vmustreplyempty(self, data: str) -> str:
        return "Must reply empty (probe)"

    def _dissect_vfile(self, data: str) -> str:
        # vFile:operation:args
        parts = data.split(":")
        if len(parts) < 2:
            return f"File operation: {data}"
        op = parts[1]
        args = ":".join(parts[2:]) if len(parts) > 2 else ""

        if op == "setfs":
            pid = args or "0"
            return f"Set file system to pid {pid}"
        elif op == "open":
            # open:filename,flags,mode
            open_parts = args.split(",")
            if len(open_parts) >= 1:
                filename_hex = open_parts[0]
                try:
                    filename = bytes.fromhex(filename_hex).decode("utf-8", errors="replace")
                except ValueError:
                    filename = filename_hex
                flags = open_parts[1] if len(open_parts) > 1 else "?"
                mode = open_parts[2] if len(open_parts) > 2 else "?"
                return f"Open file: {filename} (flags=0x{flags}, mode=0o{mode})"
            return f"Open file: {args}"
        elif op == "close":
            return f"Close file descriptor {args}"
        elif op == "pread":
            # pread:fd,count,offset
            pread_parts = args.split(",")
            if len(pread_parts) >= 3:
                fd, count, offset = pread_parts[0], pread_parts[1], pread_parts[2]
                return f"Read {int(count, 16)} bytes from fd {fd} at offset {int(offset, 16)}"
            return f"Read from file: {args}"
        elif op == "pwrite":
            # pwrite:fd,offset,data
            pwrite_parts = args.split(",")
            if len(pwrite_parts) >= 2:
                fd, offset = pwrite_parts[0], pwrite_parts[1]
                return f"Write to fd {fd} at offset {int(offset, 16)}"
            return f"Write to file: {args}"
        elif op == "fstat":
            return f"Get file status for fd {args}"
        elif op == "stat":
            try:
                filename = bytes.fromhex(args).decode("utf-8", errors="replace")
            except ValueError:
                filename = args
            return f"Get file status: {filename}"
        elif op == "unlink":
            try:
                filename = bytes.fromhex(args).decode("utf-8", errors="replace")
            except ValueError:
                filename = args
            return f"Delete file: {filename}"
        elif op == "readlink":
            try:
                filename = bytes.fromhex(args).decode("utf-8", errors="replace")
            except ValueError:
                filename = args
            return f"Read symlink: {filename}"
        elif op == "mkdir":
            mkdir_parts = args.split(",")
            if mkdir_parts:
                try:
                    dirname = bytes.fromhex(mkdir_parts[0]).decode("utf-8", errors="replace")
                except ValueError:
                    dirname = mkdir_parts[0]
                return f"Create directory: {dirname}"
            return f"Create directory: {args}"
        else:
            return f"File operation {op}: {args}"

    def _dissect_vflash_erase(self, data: str) -> str:
        # vFlashErase:addr,length
        match = re.match(r"vFlashErase:([0-9a-fA-F]+),([0-9a-fA-F]+)", data)
        if match:
            addr, length = match.groups()
            return f"Flash erase {int(length, 16)} bytes at 0x{addr}"
        return f"Flash erase: {data[12:]}"

    def _dissect_vflash_write(self, data: str) -> str:
        # vFlashWrite:addr:data
        match = re.match(r"vFlashWrite:([0-9a-fA-F]+):", data)
        if match:
            addr = match.group(1)
            return f"Flash write at 0x{addr}"
        return f"Flash write: {data[12:]}"

    def _dissect_vflash_done(self, data: str) -> str:
        return "Flash write complete"

    def _dissect_q_command(self, data: str) -> str:
        for cmd, handler in self._q_handlers.items():
            if data.startswith(cmd):
                return handler(data)
        if data.startswith("qL"):
            return "Query thread list"
        return f"Query: {data}"

    def _dissect_Q_command(self, data: str) -> str:
        if data.startswith("QStartNoAckMode"):
            return "Enable no-ack mode"
        elif data.startswith("QNonStop"):
            val = data[9:] if len(data) > 9 else ""
            return f"Set non-stop mode: {'enabled' if val == '1' else 'disabled' if val == '0' else val}"
        elif data.startswith("QPassSignals"):
            signals = data[13:] if len(data) > 13 else ""
            if signals:
                return f"Pass signals to program: {signals}"
            return "Clear pass signals"
        elif data.startswith("QProgramSignals"):
            signals = data[16:] if len(data) > 16 else ""
            if signals:
                return f"Program signals: {signals}"
            return "Clear program signals"
        elif data.startswith("QThreadEvents"):
            val = data[14:] if len(data) > 14 else ""
            return f"Thread events: {'enabled' if val == '1' else 'disabled' if val == '0' else val}"
        elif data.startswith("QCatchSyscalls"):
            val = data[15:] if len(data) > 15 else ""
            if val == "0":
                return "Disable syscall catching"
            return f"Catch syscalls: {val}"
        elif data.startswith("QSetWorkingDir"):
            dir_hex = data[15:] if len(data) > 15 else ""
            if dir_hex:
                try:
                    dirname = bytes.fromhex(dir_hex).decode("utf-8", errors="replace")
                    return f"Set working directory: {dirname}"
                except ValueError:
                    pass
            return "Clear working directory"
        elif data.startswith("QEnvironmentHexEncoded"):
            env_hex = data[23:] if len(data) > 23 else ""
            try:
                env = bytes.fromhex(env_hex).decode("utf-8", errors="replace")
                return f"Set environment: {env}"
            except ValueError:
                return f"Set environment (hex): {env_hex}"
        elif data.startswith("QEnvironmentReset"):
            return "Reset environment"
        elif data.startswith("QDisableRandomization"):
            val = data[22:] if len(data) > 22 else ""
            return f"ASLR: {'disabled' if val == '1' else 'enabled' if val == '0' else val}"
        return f"Set: {data}"

    def _dissect_qsupported(self, data: str) -> str:
        features = data[11:] if len(data) > 11 else ""
        if features:
            feat_list = features.split(";")
            return f"Query supported features: {', '.join(feat_list)}"
        return "Query supported features"

    def _dissect_qxfer(self, data: str) -> str:
        match = re.match(r"qXfer:([^:]+):read:([^:]*):([0-9a-fA-F]+),([0-9a-fA-F]+)", data)
        if match:
            obj, annex, offset, length = match.groups()
            obj_desc = {
                "features": "target features",
                "libraries": "loaded libraries",
                "memory-map": "memory map",
                "threads": "thread info",
                "auxv": "auxiliary vector",
                "exec-file": "executable filename",
                "osdata": "OS data",
                "siginfo": "signal info",
                "spu": "SPU data",
                "traceframe-info": "traceframe info",
            }.get(obj, obj)
            if annex:
                return f"Read {obj_desc}:{annex} (offset=0x{offset}, len=0x{length})"
            return f"Read {obj_desc} (offset=0x{offset}, len=0x{length})"
        # Check for write operation
        match = re.match(r"qXfer:([^:]+):write:([^:]*):([0-9a-fA-F]+):", data)
        if match:
            obj, annex, offset = match.groups()
            return f"Write {obj}:{annex} at offset 0x{offset}"
        return f"Transfer: {data[6:]}"

    def _dissect_qrcmd(self, data: str) -> str:
        cmd_hex = data[6:]
        try:
            cmd = bytes.fromhex(cmd_hex).decode("ascii")
            return f"Remote command: {cmd}"
        except (ValueError, UnicodeDecodeError):
            return f"Remote command (hex): {cmd_hex}"

    def _dissect_qc(self, data: str) -> str:
        return "Query current thread ID"

    def _dissect_qattached(self, data: str) -> str:
        if len(data) > 9:
            return f"Query if attached to process {data[10:]}"
        return "Query if attached to existing process"

    def _dissect_qoffsets(self, data: str) -> str:
        return "Query section offsets"

    def _dissect_qthreadinfo(self, data: str) -> str:
        if data.startswith("qf"):
            return "Query first thread info"
        return "Query next thread info"

    def _dissect_qsymbol(self, data: str) -> str:
        if data == "qSymbol::":
            return "Symbol lookup ready"
        return f"Symbol query: {data[8:]}"

    def _dissect_qtstatus(self, data: str) -> str:
        return "Query trace status"

    def _dissect_qregisterinfo(self, data: str) -> str:
        reg = data[13:]
        return f"Query register {reg} info"

    def _dissect_qhostinfo(self, data: str) -> str:
        return "Query host info"

    def _dissect_qprocessinfo(self, data: str) -> str:
        return "Query process info"

    def _dissect_qmemoryregioninfo(self, data: str) -> str:
        addr = data[18:]
        return f"Query memory region at 0x{addr}"

    def _dissect_error(self, data: str) -> str:
        code = data[1:3] if len(data) >= 3 else data[1:]
        try:
            code_num = int(code, 16)
            return f"Error {code_num}"
        except ValueError:
            return f"Error: {data}"

    def _dissect_stop_reply(self, data: str) -> str:
        reason = data[0]
        if reason == "S":
            sig = int(data[1:3], 16)
            sig_name = SIGNALS.get(sig, f"signal {sig}")
            return f"Stopped: {sig_name}"
        elif reason == "T":
            sig = int(data[1:3], 16)
            sig_name = SIGNALS.get(sig, f"signal {sig}")
            extra = data[3:]
            if extra:
                details = self._parse_stop_reply_details(extra)
                if details:
                    return f"Stopped: {sig_name} ({details})"
            return f"Stopped: {sig_name}"
        return f"Stop reply: {data}"

    def _parse_stop_reply_details(self, extra: str) -> str:
        """Parse the key:value pairs in a T stop reply."""
        # Common register numbers for x86-64
        reg_names = {
            "00": "rax", "01": "rbx", "02": "rcx", "03": "rdx",
            "04": "rsi", "05": "rdi", "06": "rbp", "07": "rsp",
            "08": "r8", "09": "r9", "0a": "r10", "0b": "r11",
            "0c": "r12", "0d": "r13", "0e": "r14", "0f": "r15",
            "10": "rip", "11": "eflags", "12": "cs", "13": "ss",
            "14": "ds", "15": "es", "16": "fs", "17": "gs",
        }

        parts = []
        thread_id = None
        stop_reason = None

        for item in extra.rstrip(";").split(";"):
            if not item:
                continue
            if ":" not in item:
                parts.append(item)
                continue

            key, value = item.split(":", 1)
            key_lower = key.lower()

            # Thread ID
            if key_lower == "thread":
                thread_id = value
            # Stop reasons
            elif key_lower == "watch":
                stop_reason = f"write watchpoint at 0x{value}"
            elif key_lower == "rwatch":
                stop_reason = f"read watchpoint at 0x{value}"
            elif key_lower == "awatch":
                stop_reason = f"access watchpoint at 0x{value}"
            elif key_lower == "swbreak":
                stop_reason = "software breakpoint"
            elif key_lower == "hwbreak":
                stop_reason = "hardware breakpoint"
            elif key_lower == "library":
                stop_reason = "library event"
            elif key_lower == "fork":
                stop_reason = f"fork (child={value})"
            elif key_lower == "vfork":
                stop_reason = f"vfork (child={value})"
            elif key_lower == "vforkdone":
                stop_reason = "vfork done"
            elif key_lower == "exec":
                try:
                    exec_name = bytes.fromhex(value).decode("utf-8", errors="replace")
                    stop_reason = f"exec ({exec_name})"
                except ValueError:
                    stop_reason = f"exec ({value})"
            elif key_lower == "create":
                stop_reason = "thread created"
            elif key_lower == "core":
                parts.append(f"core {value}")
            # Register values (numeric keys)
            elif key_lower in reg_names:
                # Don't include raw register values in summary - too verbose
                pass
            elif re.match(r"^[0-9a-f]{1,2}$", key_lower):
                # Other numeric register - skip
                pass
            else:
                parts.append(f"{key}={value}")

        # Build result
        result_parts = []
        if stop_reason:
            result_parts.append(stop_reason)
        if thread_id:
            result_parts.append(f"thread {thread_id}")
        result_parts.extend(parts)

        return ", ".join(result_parts) if result_parts else ""

    def _dissect_exit_reply(self, data: str) -> str:
        code = data[1:]
        try:
            code_num = int(code, 16)
            return f"Process exited with code {code_num}"
        except ValueError:
            return f"Process exited: {data}"

    def _dissect_terminate_reply(self, data: str) -> str:
        sig = data[1:3] if len(data) >= 3 else data[1:]
        try:
            sig_num = int(sig, 16)
            sig_name = SIGNALS.get(sig_num, f"signal {sig_num}")
            return f"Process terminated by {sig_name}"
        except ValueError:
            return f"Process terminated: {data}"

    def _dissect_console_output(self, data: str) -> str:
        output_hex = data[1:]
        try:
            output = bytes.fromhex(output_hex).decode("utf-8", errors="replace")
            return f"Console: {output}"
        except ValueError:
            return f"Console output (hex): {output_hex}"

    def _dissect_file_io(self, data: str) -> str:
        return f"File I/O request: {data[1:]}"

    def _dissect_binary_memory_response(self, data: str) -> str:
        """Dissect binary memory read response (b prefix)."""
        # Response is 'b' followed by binary data (with escape sequences)
        binary_data = data[1:]  # Skip 'b' prefix
        # Count actual bytes (accounting for escape sequences)
        byte_count = 0
        i = 0
        while i < len(binary_data):
            if binary_data[i] == '}' and i + 1 < len(binary_data):
                # Escaped byte: } followed by char XOR 0x20
                byte_count += 1
                i += 2
            else:
                byte_count += 1
                i += 1
        return f"Binary data: {byte_count} bytes"

    def _dissect_file_io_response(self, data: str) -> str:
        """Dissect vFile response: F result[,errno][;data] or F-1,errno"""
        if data.startswith("F-1"):
            parts = data[1:].split(",")
            if len(parts) >= 2:
                errno = parts[1].split(";")[0]  # errno before any data
                return f"File error: errno {errno}"
            return "File error"
        elif data.startswith("F"):
            # Format: F<result>[,errno][;data]
            rest = data[1:]
            # Split on ; first to separate result from data
            if ";" in rest:
                result_part, file_data = rest.split(";", 1)
            else:
                result_part = rest
                file_data = None

            # Parse result[,errno]
            result_parts = result_part.split(",")
            result = result_parts[0] if result_parts else "?"

            try:
                result_int = int(result, 16)
                if file_data is not None:
                    # Has data attached
                    data_desc = self._describe_file_data(file_data, result_int)
                    return f"File result: {result_int}{data_desc}"
                return f"File result: {result_int}"
            except ValueError:
                return f"File result: {result}"
        return f"File response: {data}"

    def _describe_file_data(self, file_data: str, byte_count: int) -> str:
        """Describe the data portion of a file I/O response."""
        if not file_data:
            return ""
        # Check for PE header
        if file_data.startswith("MZ"):
            return " (PE header)"
        # Check for ELF header
        if file_data.startswith("\x7fELF") or file_data.startswith("\x7f" + "ELF"):
            return " (ELF header)"
        # Generic binary data
        if byte_count > 0:
            return f" ({byte_count} bytes)"
        return ""

    def _dissect_qxfer_response(self, data: str, final: bool) -> str:
        """Dissect qXfer response data."""
        status = "final" if final else "partial"
        # Check if it looks like XML
        if data.lstrip().startswith("<?xml") or data.lstrip().startswith("<"):
            # Find the root element name
            match = re.search(r"<(\w+)[\s>]", data)
            if match:
                root = match.group(1)
                return f"XML data ({status}): <{root}> ({len(data)} bytes)"
            return f"XML data ({status}): {len(data)} bytes"
        return f"Transfer data ({status}): {len(data)} bytes"

    def _dissect_thread_id_response(self, data: str) -> str:
        """Dissect thread ID in response (e.g., from qfThreadInfo)."""
        # Handle comma-separated list of threads
        if "," in data:
            threads = data.split(",")
            return f"Threads: {', '.join(threads)}"
        return f"Thread: {data}"

    def _dissect_vcont_response(self, data: str) -> str:
        """Dissect vCont? response listing supported actions."""
        # vCont[;action]...
        if data == "vCont":
            return "vCont supported (no actions listed)"
        actions = data[6:] if data.startswith("vCont;") else data[5:]
        action_list = actions.split(";") if actions else []
        descriptions = []
        for act in action_list:
            if act == "c":
                descriptions.append("continue")
            elif act == "C":
                descriptions.append("continue with signal")
            elif act == "s":
                descriptions.append("step")
            elif act == "S":
                descriptions.append("step with signal")
            elif act == "t":
                descriptions.append("stop")
            elif act == "r":
                descriptions.append("range step")
            else:
                descriptions.append(act)
        return f"vCont supported: {', '.join(descriptions)}"

    def _is_rle_hex_data(self, data: str) -> bool:
        """Check if data looks like RLE-encoded hex (e.g., register dump).

        RLE encoding uses * followed by a printable ASCII char as repeat count.
        Pattern: hex digits interspersed with *<char> sequences.
        """
        if "*" not in data:
            return False
        # Check if it follows hex + RLE pattern
        # Valid chars: hex digits, *, and any printable char after *
        i = 0
        while i < len(data):
            c = data[i]
            if c in "0123456789abcdefABCDEF":
                i += 1
            elif c == "*" and i + 1 < len(data):
                # RLE: * followed by repeat count char (ASCII 32-126)
                next_char = data[i + 1]
                if 32 <= ord(next_char) <= 126:
                    i += 2
                else:
                    return False
            else:
                return False
        return True

    def _dissect_rle_hex_data(self, data: str) -> str:
        """Dissect RLE-encoded hex data (memory or register values)."""
        # Calculate approximate decoded size
        decoded_len = 0
        i = 0
        while i < len(data):
            if i + 1 < len(data) and data[i + 1] == "*":
                # This char is repeated
                if i + 2 < len(data):
                    repeat = ord(data[i + 2]) - 29  # RLE decode
                    decoded_len += repeat
                    i += 3
                else:
                    decoded_len += 1
                    i += 1
            elif data[i] == "*":
                # Standalone * with repeat count
                i += 2
            else:
                decoded_len += 1
                i += 1

        byte_count = decoded_len // 2

        # Use command context to provide better label
        if self._last_command:
            cmd = self._last_command[0] if self._last_command else ""
            if cmd == "g":
                return f"Registers: {byte_count} bytes"
            elif cmd in ("m", "x"):
                return f"Memory: {byte_count} bytes"
            elif cmd == "p":
                return f"Register value: {byte_count} bytes"

        return f"Data: {byte_count} bytes"

    def _is_key_value_data(self, data: str) -> bool:
        """Check if data looks like key=value or key:value pairs."""
        if ":" not in data and ";" not in data:
            return False
        # If it has * characters, it's likely RLE data not key-value
        if "*" in data:
            return False
        # Check for actual key:value or key=value patterns
        # Key-value data typically has word characters before : or =
        if re.search(r"\b\w+[:=]", data):
            return True
        return False

    def _dissect_hex_data(self, data: str) -> str:
        byte_count = len(data) // 2

        # Use command context to provide better label
        label = "Data"
        if self._last_command:
            cmd = self._last_command[0] if self._last_command else ""
            if cmd == "g":
                label = "Registers"
            elif cmd in ("m", "x"):
                label = "Memory"
            elif cmd == "p":
                label = "Register value"

        if byte_count <= 16:
            formatted = " ".join(data[i:i+2] for i in range(0, len(data), 2))
            return f"{label}: {formatted}"
        return f"{label}: {byte_count} bytes"

    def _dissect_key_value(self, data: str) -> str:
        pairs = []
        for item in re.split(r"[;,]", data):
            if ":" in item:
                key, val = item.split(":", 1)
                pairs.append(f"{key}={val}")
            elif "=" in item:
                pairs.append(item)
            else:
                pairs.append(item)
        return f"Features: {', '.join(pairs)}"
