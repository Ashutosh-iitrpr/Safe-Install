# Limitations

SafeInstall performs dynamic behavioral analysis on one sandboxed execution.
A result describes observed behavior only; it is not a proof that a package is
safe.

## Observation window

The install and smoke-test phases share the configured timeout. A payload that
runs after the window expires is not observed. The sleepy demo waits 45 seconds:
a 120-second run provides a 60-second smoke window and catches the marker, while
a 60-second run provides only a 30-second smoke window and does not.

## Sandbox and environment detection

Packages may detect containers, virtual environments, low resource limits,
specific usernames, hostnames, operating systems, or CI variables. They can
change behavior or remain dormant when they detect the sandbox.

## Network visibility

The sandbox is placed on an internal Docker network and can reach the gateway
only. The gateway allows package registries and sinkholes unknown plain HTTP
requests. Raw external socket connections are unavailable.

HTTPS inspection is limited: the gateway can observe CONNECT destinations, but
it does not currently terminate TLS or inspect encrypted request bodies.

DNS and plain HTTP request bodies are logged for the gateway side, subject to
the same single-run limitations.

## Container isolation

Docker isolation protects the host less strongly than a virtual machine or
microVM. All containers share the host kernel. gVisor or another stronger
runtime is an optional future benchmark, not an existing guarantee.

## Tracing and parser visibility

`strace` records only selected system calls and may miss behavior implemented
through unsupported APIs or heavily obfuscated execution. Tracing overhead can
also be detected. Filtering and normalization reduce noise but are not perfect.

## Native packages

Native shared libraries require writable and executable temporary storage. The
`/tmp` tmpfs is therefore executable but remains isolated with `nosuid`,
`nodev`, size limits, and a read-only container root filesystem.

## Report wording

The project uses "BLOCK", "WARNING", or "NO SUSPICIOUS BEHAVIOR OBSERVED".
It must not use "safe" or claim comprehensive protection.
