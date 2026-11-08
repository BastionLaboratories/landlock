#!/usr/bin/env bash
# Run the test suite the way a stranger's machine would: inside a bubblewrap
# child with an empty home, the project tree bound read-only, a tmpfs for
# pytest's cache and scratch space, and no network. The exit code is pytest's.
#
# Usage:   bash tools/clean_machine.sh [pytest arguments...]
# Env:     LANDLOCK_TREE   the folder to test (default: the folder above tools/)
#
# Exit codes: pytest's own code when it ran; 2 and one "REFUSED: ..." line
# when bubblewrap or pytest is missing, or bubblewrap cannot start a sandbox.

set -u

if ! command -v bwrap >/dev/null 2>&1; then
    echo "REFUSED: bubblewrap (bwrap) is required for the clean-machine run and was not found on PATH."
    exit 2
fi

self="${BASH_SOURCE[0]}"
case "$self" in
    */*) selfdir="${self%/*}" ;;
    *) selfdir="." ;;
esac
here="$(cd "$selfdir" && pwd)"
tree="${LANDLOCK_TREE:-${here%/*}}"

if [ ! -d "$tree" ]; then
    echo "REFUSED: the tree to test is not a directory."
    exit 2
fi
tree="$(cd "$tree" && pwd)"

py="$(command -v python3 || true)"
if [ -z "$py" ]; then
    echo "REFUSED: python3 was not found on PATH."
    exit 2
fi

# Where the interpreter and pytest live on this machine (outside the tree).
if ! found="$("$py" -c 'import os, sys, pytest; print(sys.prefix); print(sys.base_prefix); print(os.path.dirname(os.path.dirname(pytest.__file__)))' 2>/dev/null)"; then
    echo "REFUSED: pytest is not importable by python3 on this machine."
    exit 2
fi

# The system folders the interpreter needs, read-only. On a merged-/usr
# machine /bin, /lib, /lib64 and /sbin are links into /usr; keep them links.
args=(--unshare-all --die-with-parent --new-session --clearenv)
args+=(--ro-bind /usr /usr)
for d in bin lib lib64 sbin; do
    if [ -L "/$d" ]; then
        args+=(--symlink "$(readlink "/$d")" "/$d")
    elif [ -d "/$d" ]; then
        args+=(--ro-bind "/$d" "/$d")
    fi
done
if [ -d /etc/alternatives ]; then
    args+=(--ro-bind /etc/alternatives /etc/alternatives)
fi
if [ -f /etc/ld.so.cache ]; then
    args+=(--ro-bind /etc/ld.so.cache /etc/ld.so.cache)
fi

# An interpreter or pytest installed outside /usr (a toolcache, a venv) is
# bound read-only at its own path so the same command works inside.
seen=" "
while IFS= read -r p; do
    case "$p" in
        /usr|/usr/*|"") continue ;;
    esac
    case "$seen" in
        *" $p "*) continue ;;
    esac
    seen="$seen$p "
    args+=(--ro-bind "$p" "$p")
done <<EOF
$found
EOF

# A fresh, empty world: no real home, a tmpfs for /tmp (pytest's cache and
# temporary folders live there), the tree read-only at /tree, and no network
# (--unshare-all above includes the network).
args+=(--proc /proc --dev /dev --tmpfs /tmp --tmpfs /home/tester)
args+=(--ro-bind "$tree" /tree --chdir /tree)
args+=(--setenv HOME /home/tester --setenv USER tester --setenv LOGNAME tester)
args+=(--setenv PATH "${py%/*}:/usr/local/bin:/usr/bin:/bin")
args+=(--setenv LANG C.UTF-8)
args+=(--setenv PYTHONPATH /tree)
args+=(--setenv PYTHONDONTWRITEBYTECODE 1)
# Never read bytecode compiled on the host: the cache prefix points at the
# empty tmpfs, so a __pycache__ standing inside the tree is ignored.
args+=(--setenv PYTHONPYCACHEPREFIX /tmp/pycache)
args+=(--setenv CUDA_VISIBLE_DEVICES "")

# A sandbox that cannot start at all is a refusal, not a test failure.
if ! bwrap "${args[@]}" /usr/bin/env true >/dev/null 2>&1; then
    echo "REFUSED: bubblewrap could not start a sandbox on this machine."
    exit 2
fi

exec bwrap "${args[@]}" "$py" -B -m pytest -q -o cache_dir=/tmp/pytest_cache "$@" </dev/null
