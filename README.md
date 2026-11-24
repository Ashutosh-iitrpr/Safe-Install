# SafeInstall — Pre-Flight Security Sandbox for Packages & Repos

> **Living document.** This file is the single source of truth for project status.
> Update the **Status Dashboard**, **Task Checklist** and **Session Log** after every completed task.

---

## 0. READ THIS FIRST (instructions for any AI agent or human resuming work)

1. Read this entire file before doing anything.
2. Go to **Section 3 (Status Dashboard)** to see the current phase and the next task.
3. Check the **Task Checklist (Section 8)**. Work on the first unchecked task, in order, unless the user redirects you.
4. Before ending a session, or after finishing any task:
   - tick the checkbox (`[x]`) and add a one-line note if something non-obvious happened,
   - update the Status Dashboard (current phase, next task, blockers),
   - append an entry to the **Session Log (Section 12)**,
   - record any new decision in **Section 11 (Decision Log)**.
5. Do not change the architecture or the event schema (Section 5) without logging the decision.
6. If something here contradicts the actual code, trust the code, then fix this file.

---

## 1. Project Summary

| | |
|---|---|
| **Name** | SafeInstall |
| **One-liner** | `safeinstall <pip-pkg | npm-pkg | github-url>` runs the install in a disposable, network-jailed sandbox seeded with decoy secrets, records everything it does, and prints a Trust Report. |
| **Context** | Course project: Contemporary Computing Platforms (virtualization / cloud computing focus). |
| **Team** | 3 people, working together with AI agents (no per-person task split). |
| **Time budget** | About 2 days (48 hours) from kickoff. Kickoff date: 2026-11-23. Hard deadline: **TBD, fill in** |
| **Goal** | An impactful, resume-worthy project with a reliable live demo. |

### The problem
`pip install` (`setup.py`) and `npm install` (`postinstall`) can execute arbitrary code at install time, usually on a developer's main machine next to `~/.ssh`, `.env` files and cloud credentials. Supply-chain attacks via malicious packages are common.

### The solution
A CLI + report viewer that performs **dynamic behavioral analysis** before the package ever touches the real machine:

- Disposable container sandbox (non-root, read-only rootfs, cgroup limits, no direct internet).
- Pre-planted **decoy secrets** containing unique **canary tokens**.
- Full tracing of file access, process spawns and network attempts.
- A rules engine that turns raw events into a **verdict**.

### What it is NOT
It does not prove a package is safe. It flags suspicious behavior observed during one run. Wording in the UI and README must always say "no suspicious behavior observed", never "safe". Known evasions (sandbox detection, time bombs, environment-specific triggers) are documented in Section 13.

---

## 2. Demo (the thing we must be able to show)

1. **Clean package** (`demo/clean-pkg`): green verdict, small event list.
2. **Malicious package** (`demo/evil-pkg`): reads decoy `.env` / `id_rsa`, base64-encodes it, POSTs it to an external host. Red verdict within seconds, showing:
   - which decoy file was read,
   - which process read it,
   - the destination host/IP,
   - confirmation that the canary token appeared in the outbound payload.
3. **Delayed-trigger package** (`demo/sleepy-pkg`): payload fires after a sleep. Shows we catch it when the observation window is long enough, and discusses the limits honestly.
4. (Stretch) Benchmark table: Docker (runc) vs gVisor (runsc) startup/install overhead.

All demo malware is **harmless by design**: it only touches our fake decoy files and talks to our own sink. Never include real malicious code.

---

## 3. Status Dashboard (UPDATE THIS)

| Field | Value |
|---|---|
| **Current phase** | Phase 5: Report |
| **Overall progress** | 26 / 38 tasks |
| **Last updated** | 2026-11-24 |
| **Next task** | T-027: Implement Rich terminal report |
| **Blockers** | None known |
| **Environment confirmed?** | Yes (see Section 10) |
| **Demo ready?** | No |

---

## 4. Architecture

```
                    ┌──────────────────────────────────────────┐
 safeinstall <pkg>  │              Orchestrator (Python)       │
 ───────────────►   │  1 resolve  2 provision  3 run  4 analyze│
     CLI            └───────┬───────────────────────────┬──────┘
                            │ docker SDK                │ artifacts
                            ▼                           ▼
        ┌─────────── isolated Docker network (internal) ───────────┐
        │                                                          │
        │  ┌──────────────────────┐      ┌─────────────────────┐   │
        │  │ SANDBOX container    │      │ GATEWAY container   │   │
        │  │ non-root, ro rootfs  │ ───► │ DNS logger + HTTP   │   │
        │  │ cgroups, seccomp     │      │ proxy w/ allowlist  │   │
        │  │ decoy $HOME + canary │      │ (registry passes,   │   │
        │  │ strace -f wrapper    │      │  all else sinkholed)│   │
        │  └──────────────────────┘      └──────────┬──────────┘   │
        └───────────────────────────────────────────┼──────────────┘
                                                    ▼
                                      real internet (registries only)
```

**Key idea:** the sandbox has no route to the internet. Its only reachable peer is the gateway. The gateway forwards allowlisted package registries (so installs work) and answers everything else with a fake success from a sinkhole, so malware continues and reveals full behavior, while nothing real leaves.

### Components

| Component | Responsibility |
|---|---|
| **CLI** (`cli.py`) | Parse input, call orchestrator, print terminal report, exit code (0 ok, 1 warning, 2 block). |
| **Orchestrator** (`orchestrator.py`) | Run lifecycle: resolve, provision, start containers, wait/timeout, collect artifacts, teardown, call analyzer + renderer. |
| **Sandbox image** (`sandbox/`) | Dockerfile with python + node + strace; `entrypoint.sh` runs install and import phases under strace; decoy generator. |
| **Gateway** (`gateway/`) | Logging proxy + DNS logging; registry allowlist; sinkhole for the rest. |
| **Parsers** (`parsers/`) | Convert `strace.log`, `gateway.jsonl`, filesystem diff into normalized events. |
| **Rules engine** (`rules/`) | Match events to findings with severity; compute verdict. |
| **Report** (`report/`) | JSON + HTML (Jinja2) + Rich terminal output. |

---

## 5. Contracts (do not break without logging a decision)

### 5.1 Normalized event schema
Every parser outputs a list of events in this shape (JSON):

```json
{
  "ts": 1732350000.123,
  "source": "strace | gateway | fsdiff",
  "type": "file_read | file_write | exec | net_connect | dns | http_request | resource_limit",
  "pid": 123,
  "process": "python3",
  "detail": {
    "path": "/home/sandbox/.env",
    "host": "185.1.2.3",
    "port": 80,
    "cmdline": ["curl", "-X", "POST", "..."],
    "method": "POST",
    "url": "http://evil.example/upload",
    "body_excerpt": "..."
  }
}
```
Only include the `detail` keys relevant to the event type.

### 5.2 Finding schema (rules engine output)

```json
{
  "rule_id": "DECOY_READ",
  "severity": "critical | high | medium | info",
  "title": "Read decoy credential file",
  "evidence": [ { "event_ref": 17, "summary": "python3 opened /home/sandbox/.env" } ]
}
```

### 5.3 Run artifacts folder
`runs/<run_id>/` contains:

```
meta.json          # input, resolved version, timestamps, limits, exit code, peak mem
strace.log
gateway.jsonl
fsdiff.txt
canaries.json      # canary tokens + which decoy file they were placed in
events.json        # normalized events
findings.json
report.json
report.html
```

### 5.4 Verdict logic
- Any **critical** finding: `BLOCK`
- Any **high** finding (and no critical): `WARNING`
- Otherwise: `NO SUSPICIOUS BEHAVIOR OBSERVED`

### 5.5 Rules (starter set)

| rule_id | Trigger | Severity |
|---|---|---|
| `DECOY_READ` | `openat` on a decoy path (`id_rsa`, `.env`, `.aws/credentials`, etc.) by a non-installer process | critical |
| `CANARY_EXFIL` | A canary token (raw, base64, hex, url-encoded) appears in any outbound request body/URL/DNS name | critical |
| `UNKNOWN_NET` | Connect/DNS/HTTP to a host outside the registry allowlist | high |
| `SUSPICIOUS_EXEC` | Spawned `curl`, `wget`, `nc`, `bash -c`, `sh -c`, `base64`, `powershell` | medium |
| `OUTSIDE_WRITE` | Write outside the workspace, or to shell rc files, cron, `.ssh/authorized_keys` | medium |
| `RESOURCE_ABUSE` | Hit pids/memory/CPU/timeout limit | medium |
| `INFO_*` | Notable but benign (e.g. compiles native extension) | info |

Note: legitimate installers may read some files. Keep an allowlist of expected paths/processes and tune on the clean demo package so it stays green.

---

## 6. Tech Stack

| Area | Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | Whole orchestrator, parsers, rules, CLI |
| CLI | Typer + Rich | Colored terminal report |
| Containers | Docker (Docker SDK for Python) | Optional gVisor (`--runtime=runsc`) for benchmark |
| Tracing | `strace -f -ttt -e trace=openat,execve,connect,sendto,unlinkat,rename` | Try without `CAP_SYS_PTRACE` first, add only if required and log it |
| Gateway | mitmproxy (scripted) or small `aiohttp` proxy, + `dnsmasq` | Plain HTTP bodies fully visible; HTTPS = host/SNI only (see limits) |
| Report | Jinja2 HTML + Rich | |
| Storage | JSON files per run (+ optional SQLite history) | |
| Tests | pytest | Parsers and rules tested on saved sample artifacts |
| Host | Linux or WSL2 with Docker | No KVM required |

---

## 7. Repo Layout (target)

```
safeinstall/
  README.md                # this file
  pyproject.toml
  safeinstall/
    cli.py
    orchestrator.py
    config.py              # limits, allowlist, timeouts
    sandbox/
      Dockerfile
      entrypoint.sh
      make_decoys.py
    gateway/
      Dockerfile
      proxy.py             # or mitm_addon.py
      dnsmasq.conf
    parsers/
      strace_parser.py
      gateway_parser.py
      fsdiff_parser.py
    rules/
      rules.yaml
      engine.py
    report/
      template.html
      render.py
  demo/
    clean-pkg/
    evil-pkg/
    sleepy-pkg/
    sink/                  # tiny logging HTTP server used as exfil target
  tests/
    fixtures/              # saved real artifacts from sample runs
    test_parsers.py
    test_rules.py
  runs/                    # generated, gitignored
  docs/
    benchmarks.md
    limitations.md
```

---

## 8. Task Checklist (work top to bottom; tick as you go)

Legend: `[ ]` todo, `[x]` done, `[~]` in progress / partial, add a note after the task if needed.

### Phase 0: Setup & contracts (target: hours 0 to 3)
- [x] **T-001** Verify Docker works (`docker run hello-world`); record OS/Docker version in Section 10
- [~] **T-002** gVisor check: deferred (optional, stretch goal only)
- [x] **T-003** Create repo skeleton from Section 7, `pyproject.toml`, `.gitignore` (ignore `runs/`)
- [x] **T-004** Commit the event/finding/artifact contracts as code (pydantic models or dataclasses) matching Section 5
- [x] **T-005** Write 20 fake events + expected findings in `tests/fixtures/` so rules/report can be built independently

### Phase 1: Sandbox core (hours 3 to 10)
- [x] **T-006** Build sandbox image (python, node/npm, strace, non-root user `sandbox`)
- [x] **T-007** Write `make_decoys.py`: generate fake `~/.ssh/id_rsa`, `.env`, `~/.aws/credentials`, each with unique canary token; write `canaries.json`
- [x] **T-008** Write `entrypoint.sh`: phase A install under strace, phase B import/smoke test under strace, honor timeout
- [x] **T-009** Container hardening flags: read-only rootfs, tmpfs `/work` and `/tmp` (tmpfs `/tmp` permits exec for native extensions), `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/cpu/pids limits
- [x] **T-010** Manually run a clean pip package in the sandbox with no network; confirm `strace.log` is produced
- [x] **T-011** Check installs work with read-only rootfs (use venv/`--target` in tmpfs); fix as needed

### Phase 2: Gateway (hours 10 to 16)
- [x] **T-012** Create internal Docker network (`--internal`); gateway attached to internal + default network
- [x] **T-013** Implement proxy with registry allowlist (pypi.org, files.pythonhosted.org, registry.npmjs.org); log every request to `gateway.jsonl`
- [x] **T-014** Implement sinkhole: non-allowlisted plain HTTP gets a fake 200 and the request (incl. body) is logged
- [x] **T-015** DNS logging (dnsmasq query log) merged into `gateway.jsonl`
- [x] **T-016** Configure sandbox env (`HTTP_PROXY`, `HTTPS_PROXY`, `PIP_INDEX_URL` if needed, npm registry/proxy); verify clean package installs through gateway
- [x] **T-017** Verify raw-socket connect to an external IP fails inside sandbox and shows in `strace.log`

### Phase 3: Orchestrator + CLI end to end (hours 16 to 22)
- [x] **T-018** Orchestrator: create run dir, start gateway + sandbox, wait/timeout, collect artifacts, teardown (always clean up containers/networks even on failure)
- [x] **T-019** CLI: `safeinstall pip <name>[==ver]` end to end, producing artifacts
- [x] **T-020** Capture `docker diff` and peak memory/exit code into `meta.json` / `fsdiff.txt`

### Phase 4: Parsers + rules engine (hours 22 to 30)
- [x] **T-021** `strace_parser.py` to events (file_read, exec, net_connect); filter system noise
- [x] **T-022** `gateway_parser.py` to events (dns, http_request with body excerpt)
- [x] **T-023** `fsdiff_parser.py` to file_write events
- [x] **T-024** Rules engine reading `rules.yaml`; implement DECOY_READ, CANARY_EXFIL (raw/base64/hex/urlencoded), UNKNOWN_NET, SUSPICIOUS_EXEC, OUTSIDE_WRITE, RESOURCE_ABUSE
- [x] **T-025** Tune allowlists so `clean-pkg` and 2 to 3 popular real packages (e.g. `requests`, `numpy`) stay green
- [x] **T-026** pytest coverage for parsers and rules using saved fixtures

### Phase 5: Report (hours 30 to 34)
- [ ] **T-027** Rich terminal report: verdict banner, findings table, timeline
- [ ] **T-028** HTML report (Jinja2): verdict, findings with evidence, event timeline, network summary
- [ ] **T-029** Exit codes and `--json` output flag

### Phase 6: npm support + demo packages (hours 34 to 42)
- [ ] **T-030** npm path in entrypoint/orchestrator (`npm install`, then `require()` smoke test)
- [ ] **T-031** Write `demo/sink/` (tiny HTTP server logging POST bodies) and `demo/clean-pkg`
- [ ] **T-032** Write `demo/evil-pkg` (reads decoys, base64, POSTs to external IP/host) and make the verdict BLOCK reliably
- [ ] **T-033** Write `demo/sleepy-pkg` (delayed trigger) and decide observation window; document result honestly
- [ ] **T-034** (Optional) GitHub repo input: clone inside sandbox, detect `requirements.txt`/`package.json`/`setup.py`

### Phase 7: Polish, docs, rehearsal (hours 42 to 48)
- [ ] **T-035** Write `docs/limitations.md` (evasions: sandbox detection, time bombs, env-specific triggers, HTTPS body blind spot)
- [ ] **T-036** (Stretch) gVisor vs runc benchmark table in `docs/benchmarks.md`
- [ ] **T-037** Record the demo end to end 2 times; write a 60-second demo script in Section 14
- [ ] **T-038** Final README pass (install, usage, screenshots), resume bullets finalized in Section 15

---

## 9. Execution Notes & Known Gotchas

- Do the **clean package through the gateway first** (T-016) before anything fancy; everything else depends on it.
- `strace -f` output is huge. Filter to decoy paths, non-system `execve`, and `connect` to non-loopback addresses.
- Many malicious payloads run at **import** time, not install time. That is why phase B exists.
- A read-only rootfs breaks installers that write to `site-packages`. Install into a venv in tmpfs.
- HTTPS to non-allowlisted hosts: we can only see the CONNECT host/SNI unless we MITM. Demo exfil uses plain HTTP to a sink. Treat HTTPS body inspection as a documented limitation or stretch.
- Always `docker rm -f` containers and remove the network in a `finally` block. Leaked networks will break later runs.
- Keep each run under a hard wall-clock timeout (e.g. 120 s) so demos never hang.
- Pin exact package versions for the demo packages so results are reproducible.
- If `strace` fails with `ptrace: Operation not permitted`, see Section 6 note; log whichever fix you apply as a decision.

---

## 10. Environment Facts (fill in when known)

| Item | Value |
|---|---|
| Host OS | Windows + WSL2, Ubuntu (Python 3.12.3) |
| Docker version | 29.10.0 |
| gVisor available | Not checked (deferred) |
| Python version | 3.12.3 |
| Node version | Not installed on host (not needed; sandbox image has its own) |

---

## 11. Decision Log

| # | Date | Decision | Why |
|---|---|---|---|
| D-001 | 2026-11-23 | Chose SafeInstall over code-sandbox, TryMyRepo, RepoJudge | Best impact-to-risk ratio for 2 days; reliable, dramatic demo; strong virtualization story |
| D-002 | 2026-11-23 | Docker-based sandbox (gVisor optional), no Firecracker | No KVM guarantee; time budget |
| D-003 | 2026-11-23 | strace inside container for tracing | Simplest reliable option; eBPF too heavy for 2 days |
| D-004 | 2026-11-23 | Gateway with registry allowlist + sinkhole instead of fully offline sandbox | Installs need the registry; sinkhole keeps malware running so we see full behavior |
| D-005 | 2026-11-23 | Canary tokens in decoy files | Turns "maybe exfil" into confirmed exfil when the token appears in outbound data |
| D-006 | 2026-11-23 | pip + npm first, GitHub repos as stretch | Scope control |
| D-007 | 2026-11-23 | strace runs in container WITHOUT CAP_SYS_PTRACE | Verified on Docker 29.10.0 / WSL2 as root; re-verify when non-root hardened |
_Add new decisions below as D-007, D-008, ..._

| D-008 | 2026-11-24 | Mount `/tmp` as `exec,nosuid,nodev` for package virtual environments | Native shared libraries in NumPy `.so` files require executable mapping; `noexec` tmpfs caused import failure |

---

## 12. Session Log (append newest at the bottom)

| Date | What was done | State at end | Next step |
|---|---|---|---|
| 2026-11-23 | Compared 4 project ideas, chose SafeInstall, defined architecture, created this plan | Nothing built yet | T-001 |
| 2026-11-23 | Verified env: Docker works, internal network has no egress, strace works in-container w/o extra caps | Phase 0 in progress | T-003 |
| 2026-11-23 | Created the repository skeleton, Python package metadata, and generated-artifact ignores | Phase 0 in progress | T-004 |
| 2026-11-23 | Added typed Pydantic contracts for normalized events, findings, run metadata, and artifacts with validation tests | Phase 0 in progress | T-005 |
| 2026-11-23 | Added 20 normalized fixture events and expected findings for decoy reads, exfiltration, network, execution, writes, and resource limits | Phase 0 complete | T-006 |
| 2026-11-23 | Built and verified the sandbox image with Python 3.11, Node/npm, strace, and non-root user `sandbox` | Phase 1 in progress | T-007 |
| 2026-11-23 | Implemented decoy generation for `.env`, `id_rsa`, and AWS credentials with unique canary tokens and a JSON manifest | Phase 1 in progress | T-008 |
| 2026-11-23 | Added pip/npm install and smoke-test phases under strace, split timeout handling, decoy setup, and strace artifacts | Phase 1 in progress | T-009 |
| 2026-11-23 | Added reusable Docker SDK hardening options for read-only rootfs, writable tmpfs mounts, dropped capabilities, no-new-privileges, and resource limits | Phase 1 in progress | T-010 |
| 2026-11-23 | Verified a clean local pip package installs and imports in the hardened network-disabled sandbox; produced a 6503-line strace log and canary manifest | Phase 1 in progress | T-011 |
| 2026-11-23 | Confirmed read-only rootfs rejects writes, while `/tmp` and `/work` support venv installation and artifact collection | Phase 1 complete | T-012 |
| 2026-11-23 | Added the internal-network topology contract: sandbox attached only internally, gateway attached to internal and bridge networks | Phase 2 in progress | T-013 |
| 2026-11-23 | Implemented the HTTP gateway proxy with registry allowlist and JSONL request logging | Phase 2 in progress | T-014 |
| 2026-11-23 | Added plain-HTTP sinkhole responses and JSONL evidence including body excerpt, length, SHA-256, and selected headers | Phase 2 in progress | T-015 |
| 2026-11-23 | Added UDP DNS sink logging with JSONL records containing queried host, query type, and source address | Phase 2 in progress | T-016 |
| 2026-11-23 | Added shared pip/npm/HTTP proxy environment configuration and verified sandbox-to-gateway routing over the internal Docker network | Phase 2 in progress | T-017 |
| 2026-11-23 | Verified a raw socket to 1.1.1.1:80 fails with ENETUNREACH in the internal network and is captured by strace | Phase 2 complete | T-018 |
| 2026-11-24 | Implemented and smoke-tested the Docker run orchestrator with run directories, internal/gateway topology, timeout, metadata, container logs, fsdiff, and guaranteed cleanup | Phase 3 in progress | T-019 |
| 2026-11-24 | Added Typer `pip` and `npm` CLI commands, tested command parsing and real local pip execution through the orchestrator | Phase 3 in progress | T-020 |
| 2026-11-24 | Added Docker diff normalization and live peak-memory sampling, persisted in `fsdiff.txt` and `meta.json` | Phase 3 complete | T-021 |
| 2026-11-24 | Fixed NumPy native-extension imports by changing `/tmp` from `noexec` to explicit `exec,nosuid,nodev`; NumPy 2.4.6 installed and imported successfully | Phase 3 complete | T-021 |
| 2026-11-24 | Implemented strace normalization for exec, file read/write, and network connects; filtered system noise and retained failed connect evidence | Phase 4 in progress | T-022 |
| 2026-11-24 | Implemented gateway JSONL parsing for DNS, HTTP, and CONNECT records; malformed lines are skipped | Phase 4 in progress | T-023 |
| 2026-11-24 | Implemented Docker fsdiff parsing for added, changed, and deleted paths | Phase 4 in progress | T-024 |
| 2026-11-24 | Implemented YAML-backed rules engine for decoy reads, canary exfiltration variants, unknown network, suspicious execution, outside writes, and resource abuse | Phase 4 in progress | T-025 |
| 2026-11-24 | Tuned clean-package filtering; Requests, NumPy, Flask, Pillow, and Pandas runs remain green with no suspicious findings | Phase 4 in progress | T-026 |
| 2026-11-24 | Expanded pytest parser/rules coverage with combined malicious and clean fixtures plus YAML severity consistency | Phase 5 in progress | T-027 |
---

## 13. Limitations (to be stated honestly in the final write-up)

- **Not a safety proof.** One observed run only.
- **Time bombs / delayed payloads** beyond the observation window are missed.
- **Sandbox detection:** malware that checks for containers/VMs/low resources may behave benignly.
- **Environment-specific triggers** (specific hostname, username, date, CI env var) may never fire.
- **HTTPS payload blind spot:** without TLS interception we see destinations, not bodies.
- **strace overhead and visibility:** syscall tracing slows execution and can be detected or evaded by determined malware.
- **Container isolation is weaker than a microVM.** Containers share the host kernel; gVisor improves this at a performance cost.

---

## 14. Demo Script (fill in during T-037)

_Target: 60 to 90 seconds._

1. Show the problem in one sentence.
2. Run `safeinstall pip demo-clean`, then show the green report.
3. Run `safeinstall pip demo-evil`, then show the red report: decoy read, outbound POST, canary confirmed.
4. Open the HTML report, show the timeline.
5. Mention limitations and the gVisor benchmark.

---

## 15. Resume / Presentation Bullets (finalize in T-038)

Draft:
- Built **SafeInstall**, a dynamic-analysis sandbox that detects credential theft and suspicious network activity in `pip`/`npm` installs using container isolation (namespaces, cgroups, seccomp), syscall tracing, and canary-token exfiltration detection.
- Designed a network-jailed gateway (allowlisted registry proxy + sinkhole + DNS logging) enabling safe observation of malicious behavior without real data leaving the host.
- (If done) Benchmarked runc vs gVisor isolation overhead and documented the security/performance trade-offs.

---

## 16. Appendix: Quick Commands (fill in as the project takes shape)

```bash
# setup
python -m venv .venv && source .venv/bin/activate
pip install -e .

# run
safeinstall pip requests
safeinstall pip ./demo/evil-pkg
safeinstall npm left-pad

# tests
pytest -q
```
