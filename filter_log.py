#!/usr/bin/env python3
"""Filter gdbproxy logs to show only interesting GDB RSP packets."""
import sys
import re

# Patterns to always show
INTERESTING = [
    r'vCont',           # continue/step commands
    r'\$[Tt]\d',        # stop replies (T05, t00, etc.)
    r'[Zz][0-4],',      # breakpoint/watchpoint set/remove
    r'\$[Pp][0-9a-f]',  # register read/write
    r'\$[Gg]#',         # bulk register read/write
    r'qSupported',      # feature negotiation
    r'qXfer:libraries',  # module discovery
    r'Session \d',      # session start
    r'qRcmd',           # monitor commands
    r'swbreak|hwbreak',  # breakpoint stop reasons
    r'qOffsets',        # text segment offset
    r'\$\?#',           # halt reason query
    r'\$[kD]#',         # kill/detach
    r'vCont\?',         # vCont feature query
]

# Patterns to suppress (noisy, low-value)
SUPPRESS = [
    r'Read \d+ bytes from',  # memory reads (m packet)
    r'Memory: ',              # memory read results
    r'Read thread info',      # qXfer:threads (shown separately)
    r'XML data.*threads',     # thread XML responses
    r'^\s+ACK$',              # ACK lines
    r'Error \d+$',            # memory read errors
    r'File result:',          # misidentified memory reads
    r'qTStatus|qTfV|qTfP',   # trace queries
    r'qSymbol',              # symbol queries
    r'qAttached',            # attach queries
    r'vMustReplyEmpty',      # probes
    r'QStartNoAckMode',      # ack mode (shown in session start)
    r'Empty response',       # unsupported commands
    r'^\s+OK$',              # bare OK
]

INTERESTING_RE = re.compile('|'.join(INTERESTING))
SUPPRESS_RE = re.compile('|'.join(SUPPRESS))

def filter_log(path):
    prev_interesting = False
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            if INTERESTING_RE.search(line):
                print(line)
                prev_interesting = True
            elif SUPPRESS_RE.search(line):
                prev_interesting = False
            elif prev_interesting:
                # Show annotation lines after interesting packets
                print(line)
                prev_interesting = False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <logfile> [| tail -100]")
        sys.exit(1)
    filter_log(sys.argv[1])
