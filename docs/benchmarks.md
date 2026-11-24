# Benchmarks

No runc versus gVisor benchmark is currently recorded. gVisor was scoped as a
stretch goal and `runsc` availability was not verified in the project
environment.

## Planned benchmark

When runsc is available, run the same pinned package and timeout with:

- Docker runc
- Docker runsc
- the same memory, CPU, PID, network, and rootfs settings

Record at least:

- container startup time
- install time
- smoke-test time
- total wall-clock time
- peak memory
- observed event count
- install success and smoke-test success
- verdict result

Repeat each measurement at least three times and report medians rather than
single-run timings.

Do not add benchmark claims until raw results are saved and reproducible.
