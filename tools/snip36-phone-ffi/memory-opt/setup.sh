#!/usr/bin/env bash
# Creates or updates the PHONE-ONLY memory-optimized SNIP-36 prover build and builds it.
#
#   tools/snip36-phone-ffi/memory-opt/setup.sh [prepare|ios|mac|both]    (default: ios)
#
# It only ever writes to
#   .prover/patched-phone/{stwo,proving-utils}   upstream checkouts + the patches here
#   .prover/sequencer-phone                      sequencer checkout + sequencer.patch + the FFI crate
# and creates .prover/sequencer_venv if it is missing. It never touches .prover/sequencer
# (the desktop build).
#
# prepare -> checkouts and patches only, no build
# ios     -> .prover/sequencer-phone/target/aarch64-apple-ios/release/libsnip36_phone_ffi.a
# mac     -> .prover/sequencer-phone/target/release/examples/prove_cli (host check)
#
# Safe to re-run. It never resets, cleans or deletes: a checkout at the wrong revision is
# moved only if its working tree is clean, a patch already applied is left alone, and a
# patch applied by an earlier run of this script is reversed before its new version is
# applied. Anything else (local edits that conflict) stops the script with a message.
#
# SNIP36_MEMOPT=0 in the environment builds with the optimizations compiled out (baseline).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# .prover lives in the main checkout, also when this runs from a git worktree.
main=$(dirname "$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)")
prover="${ZKMSG_PROVER_DIR:-$main/.prover}"
patched="$prover/patched-phone"
seq="$prover/sequencer-phone"
mode=${1:-ios}

toolchain=nightly-2026-01-15
sequencer_rev=e6b6fd2e9932909107833579e5b6efd6c75fa0af      # PRIVACY-0.14.3-RC.2
stwo_rev=489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08
proving_utils_rev=3035dd00421daa541894297bd754db6e2787807b  # v0.14.3-rust-bump

die() { echo "error: $*" >&2; exit 1; }

case "$seq" in */.prover/sequencer-phone) ;; *) die "unexpected build dir $seq" ;; esac

# checkout <dir> <url> <rev>: clone if missing; otherwise make sure HEAD is <rev>.
checkout() {
    local dir=$1 url=$2 rev=$3
    if [ ! -e "$dir" ]; then
        echo "cloning $url -> $dir"
        git clone --quiet --no-checkout "$url" "$dir"
        git -C "$dir" cat-file -e "$rev^{commit}" 2>/dev/null || git -C "$dir" fetch --quiet origin "$rev"
        git -C "$dir" checkout --quiet --detach "$rev"
        return
    fi
    [ -d "$dir/.git" ] || die "$dir exists but is not a git checkout"
    if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$rev" ]; then
        return
    fi
    git -C "$dir" cat-file -e "$rev^{commit}" 2>/dev/null || git -C "$dir" fetch --quiet origin "$rev"
    if git -C "$dir" rev-parse -q --verify HEAD >/dev/null &&
        [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
        die "$dir is not at $rev and has local changes; commit, stash or revert them, then re-run"
    fi
    git -C "$dir" checkout --quiet --detach "$rev"
}

# apply <dir> <patch>: idempotent. The applied copy is kept in .git so that a newer version
# of the patch can replace it.
apply() {
    local dir=$1 patch=$2
    local stamp
    stamp="$dir/.git/zkmsg-$(basename "$patch")"
    if git -C "$dir" apply --reverse --check "$patch" 2>/dev/null; then
        cp "$patch" "$stamp"
        return
    fi
    if [ -f "$stamp" ] && git -C "$dir" apply --reverse --check "$stamp" 2>/dev/null; then
        echo "replacing the earlier $(basename "$patch") in $dir"
        git -C "$dir" apply --reverse "$stamp"
    fi
    git -C "$dir" apply --check "$patch" 2>/dev/null ||
        die "$(basename "$patch") does not apply to $dir (local edits?); revert them and re-run"
    git -C "$dir" apply "$patch"
    cp "$patch" "$stamp"
    echo "applied $(basename "$patch") to $dir"
}

mkdir -p "$patched"
checkout "$patched/stwo" https://github.com/starkware-libs/stwo.git "$stwo_rev"
checkout "$patched/proving-utils" https://github.com/starkware-libs/proving-utils.git "$proving_utils_rev"
checkout "$seq" https://github.com/starkware-libs/sequencer.git "$sequencer_rev"

apply "$patched/stwo" "$here/stwo.patch"
apply "$patched/proving-utils" "$here/proving-utils.patch"
# Adds snip36_phone_ffi to the workspace and points stwo and proving-utils at patched-phone.
apply "$seq" "$here/sequencer.patch"

# Copy the FFI crate in. Updates files; never deletes extra ones in the destination.
mkdir -p "$seq/crates/snip36_phone_ffi"
rsync -a --exclude target --exclude memory-opt \
    "$repo/tools/snip36-phone-ffi/" "$seq/crates/snip36_phone_ffi/"

[ "$mode" = prepare ] && { echo "done (prepare)"; exit 0; }

# The virtual OS program is compiled by a build script that needs Cairo 0. Shared with the
# desktop build; only created when missing.
if [ ! -x "$prover/sequencer_venv/bin/python" ]; then
    uv venv --python 3.12 "$prover/sequencer_venv"
    VIRTUAL_ENV="$prover/sequencer_venv" uv pip install -r "$seq/scripts/requirements.txt"
fi

rustup toolchain install "$toolchain" --profile minimal --target aarch64-apple-ios

build() {
    (cd "$seq" &&
        PATH="$prover/sequencer_venv/bin:$PATH" RUSTC_WRAPPER= cargo "+$toolchain" build --release "$@")
}
case "$mode" in
    ios) build --target aarch64-apple-ios -p snip36_phone_ffi --lib ;;
    mac) build -p snip36_phone_ffi --example prove_cli ;;
    both)
        build --target aarch64-apple-ios -p snip36_phone_ffi --lib
        build -p snip36_phone_ffi --example prove_cli
        ;;
    *) die "usage: $0 [prepare|ios|mac|both]" ;;
esac
echo "done ($mode, SNIP36_MEMOPT=${SNIP36_MEMOPT:-on})"
