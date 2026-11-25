#!/bin/sh

set -u

WORK_DIR="${SAFEINSTALL_WORK_DIR:-/work}"
HOME_DIR="${SAFEINSTALL_HOME_DIR:-/home/sandbox}"
STRACE_LOG="${SAFEINSTALL_STRACE_LOG:-$WORK_DIR/strace.log}"
TIMEOUT_SECONDS="${SAFEINSTALL_TIMEOUT:-120}"
ECOSYSTEM=""
TARGET=""
SMOKE=""

usage() {
    echo "usage: safeinstall-entrypoint [--timeout seconds] <pip|npm> <target> [smoke-module]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --timeout)
            [ "$#" -ge 2 ] || { usage; exit 64; }
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        pip|npm)
            [ -z "$ECOSYSTEM" ] || { usage; exit 64; }
            ECOSYSTEM="$1"
            shift
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            elif [ -z "$SMOKE" ]; then
                SMOKE="$1"
            else
                usage
                exit 64
            fi
            shift
            ;;
    esac
done

if [ -z "$ECOSYSTEM" ] || [ -z "$TARGET" ]; then
    usage
    exit 64
fi

case "$TIMEOUT_SECONDS" in
    ''|*[!0-9]*|0) echo "invalid timeout: $TIMEOUT_SECONDS" >&2; exit 64 ;;
esac

mkdir -p "$WORK_DIR"
: > "$STRACE_LOG"
INSTALL_TRACE="$WORK_DIR/strace-install.log"
SMOKE_TRACE="$WORK_DIR/strace-smoke.log"
: > "$INSTALL_TRACE"
: > "$SMOKE_TRACE"

make-decoys --home "$HOME_DIR" --manifest "$WORK_DIR/canaries.json" \
    || exit 70

PROXY_URL="${SAFEINSTALL_PROXY_URL:-}"
if [ -n "$PROXY_URL" ]; then
    export HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" ALL_PROXY="$PROXY_URL"
    export http_proxy="$PROXY_URL" https_proxy="$PROXY_URL" all_proxy="$PROXY_URL"
    export PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}"
    export PIP_NO_CACHE_DIR=1
    export PIP_DISABLE_PIP_VERSION_CHECK=1
    export NPM_CONFIG_REGISTRY="${NPM_CONFIG_REGISTRY:-https://registry.npmjs.org/}"
    export npm_config_proxy="$PROXY_URL"
    export npm_config_https_proxy="$PROXY_URL"
    export NO_PROXY="${NO_PROXY:-127.0.0.1,localhost}"
    export no_proxy="${no_proxy:-127.0.0.1,localhost}"
fi

TRACE_FILTER="-s 4096 -e trace=openat,execve,connect,sendto,unlinkat,rename,clone,clone3,vfork,fork"

pip_module_name() {
    name=${TARGET%%[<>=!~]*}
    name=${name##*/}
    printf '%s\n' "$name" | tr -cd '[:alnum:]_.-' | tr '.-' '_'
}

npm_module_name() {
    name=${TARGET##*/}
    if [ -n "$SMOKE" ]; then
        printf '%s\n' "$SMOKE"
    else
        printf '%s\n' "$name"
    fi
}

install_phase_seconds=$((TIMEOUT_SECONDS / 2))
[ "$install_phase_seconds" -gt 0 ] || install_phase_seconds=1
smoke_phase_seconds=$((TIMEOUT_SECONDS - install_phase_seconds))

if [ "$ECOSYSTEM" = "pip" ]; then
    strace -f -ttt -o "$INSTALL_TRACE" $TRACE_FILTER \
        timeout --foreground "$install_phase_seconds" sh -c \
        'python3 -m venv --system-site-packages /tmp/safeinstall-venv &&
         /tmp/safeinstall-venv/bin/python -m pip install --disable-pip-version-check --no-build-isolation "$1"' \
        sh "$TARGET"
else
    mkdir -p "$WORK_DIR/npm"
    strace -f -ttt -o "$INSTALL_TRACE" $TRACE_FILTER \
        timeout --foreground "$install_phase_seconds" sh -c \
        'cd "$1" && npm install --ignore-scripts=false "$2"' \
        sh "$WORK_DIR/npm" "$TARGET"
fi
install_status=$?
cat "$INSTALL_TRACE" >> "$STRACE_LOG"

if [ "$install_status" -ne 0 ]; then
    printf 'SAFEINSTALL_PHASE=install\nSAFEINSTALL_EXIT_CODE=%s\n' "$install_status" \
        >> "$STRACE_LOG"
fi

if [ "$ECOSYSTEM" = "pip" ]; then
    DISCOVER_PY=$(cat <<'PY'
import importlib.metadata as md, sys
SKIP = {"pip", "setuptools", "wheel", "distribute"}
mods = set()
for d in md.distributions():
    if sys.prefix not in str(d.locate_file("")):
        continue  # only distributions the install added to the venv
    if (d.metadata["Name"] or "").lower() in SKIP:
        continue
    top = (d.read_text("top_level.txt") or "").split()
    if not top:
        for f in d.files or []:
            part = f.parts[0]
            if part != ".." and not part.endswith((".dist-info", ".egg-info", ".data")):
                top.append(part.removesuffix(".py"))
    mods.update(t for t in top if t.isidentifier() and not t.startswith("_"))
print("\n".join(sorted(mods)))
PY
)
    FALLBACK=$(pip_module_name)
    strace -f -ttt -o "$SMOKE_TRACE" $TRACE_FILTER \
        timeout --foreground "$smoke_phase_seconds" sh -c '
            mods=$1
            [ -n "$mods" ] || mods=$(/tmp/safeinstall-venv/bin/python -c "$2")
            [ -n "$mods" ] || mods=$3
            rc=0
            for m in $mods; do /tmp/safeinstall-venv/bin/python -c "import $m" || rc=1; done
            exit $rc' sh "$SMOKE" "$DISCOVER_PY" "$FALLBACK"
else
    module_name=$(npm_module_name)
    strace -f -ttt -o "$SMOKE_TRACE" $TRACE_FILTER \
        timeout --foreground "$smoke_phase_seconds" sh -c \
        'cd "$1" && node -e "require(process.argv[1])" "$2"' \
        sh "$WORK_DIR/npm" "$module_name"
fi
smoke_status=$?
cat "$SMOKE_TRACE" >> "$STRACE_LOG"

printf 'SAFEINSTALL_PHASE=smoke\nSAFEINSTALL_EXIT_CODE=%s\n' "$smoke_status" \
    >> "$STRACE_LOG"

if [ "$install_status" -ne 0 ]; then
    exit "$install_status"
fi
exit "$smoke_status"
