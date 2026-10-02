#!/usr/bin/env bash
# Sets up .prover/ with the memory-optimized SNIP-36 prover and builds it.
#
#   tools/snip36-phone-ffi/memory-opt/setup.sh [ios|mac|both]    (default: ios)
#
# ios  -> .prover/sequencer/target/aarch64-apple-ios/release/libsnip36_phone_ffi.a,
#         the path zkmsg-ios links (App/project.yml, LIBRARY_SEARCH_PATHS).
# mac  -> .prover/sequencer/target/release/examples/prove_cli, the same code path
#         on the Mac (see README.md, "Check on a Mac").
#
# Re-running resets the four checkouts to their pinned revisions and re-applies
# the patches; build outputs (target/) are kept.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
prover="$repo/.prover"
mode=${1:-ios}

toolchain=nightly-2026-01-15
sequencer_rev=e6b6fd2e9932909107833579e5b6efd6c75fa0af      # PRIVACY-0.14.3-RC.2
stwo_rev=489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08
stwo_circuits_rev=5ef951a12727e3489a2ee991c580a5b925c59c69
proving_utils_rev=3035dd00421daa541894297bd754db6e2787807b  # v0.14.3-rust-bump

# checkout <dir> <url> <rev>: clone once, then pin and reset to <rev>.
checkout() {
    local dir=$1 url=$2 rev=$3
    if [ -e "$dir" ] && [ ! -d "$dir/.git" ]; then
        echo "error: $dir exists but is not a git checkout; move it aside and re-run" >&2
        exit 1
    fi
    if [ ! -d "$dir" ]; then
        echo "cloning $url"
        git clone --quiet "$url" "$dir"
    fi
    git -C "$dir" cat-file -e "$rev^{commit}" 2>/dev/null || git -C "$dir" fetch --quiet origin "$rev"
    git -C "$dir" checkout --quiet --force --detach "$rev"
    git -C "$dir" reset --quiet --hard
    git -C "$dir" clean -fdq   # untracked files only; ignored build outputs stay
}

mkdir -p "$prover/patched"

checkout "$prover/patched/stwo" https://github.com/starkware-libs/stwo.git "$stwo_rev"
checkout "$prover/patched/stwo-circuits" https://github.com/starkware-libs/stwo-circuits.git "$stwo_circuits_rev"
checkout "$prover/patched/proving-utils" https://github.com/starkware-libs/proving-utils.git "$proving_utils_rev"
checkout "$prover/sequencer" https://github.com/starkware-libs/sequencer.git "$sequencer_rev"

git -C "$prover/patched/stwo" apply "$here/stwo.patch"
git -C "$prover/patched/stwo-circuits" apply "$here/stwo-circuits.patch"
git -C "$prover/patched/proving-utils" apply "$here/proving-utils.patch"
# Adds snip36_phone_ffi to the workspace and points stwo, stwo-circuits and
# proving-utils at the patched checkouts above.
git -C "$prover/sequencer" apply "$here/sequencer.patch"
rsync -a --delete --exclude target --exclude memory-opt "$repo/tools/snip36-phone-ffi/" "$prover/sequencer/crates/snip36_phone_ffi/"

# The virtual OS program is compiled by a build script that needs Cairo 0.
if [ ! -x "$prover/sequencer_venv/bin/python" ]; then
    uv venv --python 3.12 "$prover/sequencer_venv"
    VIRTUAL_ENV="$prover/sequencer_venv" uv pip install -r "$prover/sequencer/scripts/requirements.txt"
fi

rustup toolchain install "$toolchain" --profile minimal --target aarch64-apple-ios

build() {
    (cd "$prover/sequencer" &&
        PATH="$prover/sequencer_venv/bin:$PATH" RUSTC_WRAPPER= cargo "+$toolchain" build --release "$@")
}
case "$mode" in
    ios) build --target aarch64-apple-ios -p snip36_phone_ffi --lib ;;
    mac) build -p snip36_phone_ffi --example prove_cli ;;
    both)
        build --target aarch64-apple-ios -p snip36_phone_ffi --lib
        build -p snip36_phone_ffi --example prove_cli
        ;;
    *) echo "usage: $0 [ios|mac|both]" >&2; exit 2 ;;
esac
echo "done ($mode)"
