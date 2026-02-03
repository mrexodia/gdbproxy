"""Protocol constants for GDB Remote Serial Protocol."""

# POSIX signals
SIGNALS = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    16: "SIGSTKFLT",
    17: "SIGCHLD",
    18: "SIGCONT",
    19: "SIGSTOP",
    20: "SIGTSTP",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGURG",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGIO",
    30: "SIGPWR",
    31: "SIGSYS",
}

# Breakpoint types for Z/z commands
BREAKPOINT_TYPES = {
    0: "software breakpoint",
    1: "hardware breakpoint",
    2: "write watchpoint",
    3: "read watchpoint",
    4: "access watchpoint",
}

# Common query names
QUERY_NAMES = {
    "qSupported": "Query supported features",
    "qfThreadInfo": "Query first thread info",
    "qsThreadInfo": "Query subsequent thread info",
    "qC": "Query current thread ID",
    "qAttached": "Query if attached to existing process",
    "qOffsets": "Query section offsets",
    "qSymbol": "Query symbol lookup",
    "qTStatus": "Query trace status",
    "qTfV": "Query first trace variable",
    "qTsV": "Query subsequent trace variable",
    "qTfP": "Query first tracepoint",
    "qTsP": "Query subsequent tracepoint",
    "qXfer": "Data transfer",
    "qRcmd": "Remote command",
    "qSearch": "Memory search",
    "qRegisterInfo": "Query register info",
    "qHostInfo": "Query host info",
    "qProcessInfo": "Query process info",
    "qMemoryRegionInfo": "Query memory region info",
}

# vCont actions
VCONT_ACTIONS = {
    "c": "continue",
    "C": "continue with signal",
    "s": "step",
    "S": "step with signal",
    "t": "stop",
    "r": "range step",
}

# Stop reasons
STOP_REASONS = {
    "T": "Signal",
    "S": "Signal (deprecated)",
    "W": "Process exited",
    "X": "Process terminated",
    "O": "Console output",
    "F": "File I/O request",
    "N": "Notification",
}

# Special characters
PACKET_START = ord("$")
PACKET_END = ord("#")
NOTIFICATION_START = ord("%")
ACK = ord("+")
NACK = ord("-")
INTERRUPT = 0x03
ESCAPE = ord("}")
ESCAPE_XOR = 0x20
