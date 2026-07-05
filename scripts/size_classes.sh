#!/usr/bin/env bash
# Class-size report for stwo_full_verifier_phases against the three declare
# caps: 81,920 Sierra felts, 4,089,446 class-JSON bytes, 81,920 CASM felts.
# Usage:
#   scripts/size_classes.sh                # poseidon (default) build
#   scripts/size_classes.sh --blake        # qm31/blake pivot build
# Requires scarb 2.18 on PATH and universal-sierra-compiler (USC) for CASM.
set -euo pipefail
cd "$(dirname "$0")/../contracts/stwo_full_verifier_phases"

FEATURES=()
if [[ "${1:-}" == "--blake" ]]; then
    FEATURES=(--no-default-features --features qm31_opcode,blake_outputs_packing)
    echo "build: qm31/blake pivot"
else
    echo "build: poseidon (default)"
fi

scarb build "${FEATURES[@]}" >/dev/null

SIERRA_CAP=81920
BYTE_CAP=4089446
CASM_CAP=81920

printf "%-28s %10s %10s %10s  %s\n" class sierra bytes casm verdict
for f in target/dev/stwo_full_verifier_phases_*.contract_class.json; do
    name=$(basename "$f" .contract_class.json | sed 's/^stwo_full_verifier_phases_//')
    sierra=$(jq '.sierra_program|length' "$f")
    # Byte cap applies to the class JSON without debug info (as declared).
    bytes=$(jq -c 'del(.sierra_program_debug_info)' "$f" | wc -c | tr -d ' ')
    casm=$(universal-sierra-compiler compile-contract --sierra-path "$f" 2>/dev/null \
        | jq '.bytecode|length' || echo "-")
    verdict=OK
    [[ "$sierra" -gt $SIERRA_CAP ]] && verdict="OVER-SIERRA"
    [[ "$bytes" -gt $BYTE_CAP ]] && verdict="$verdict,OVER-BYTES"
    [[ "$casm" != "-" && "$casm" -gt $CASM_CAP ]] && verdict="$verdict,OVER-CASM"
    printf "%-28s %10s %10s %10s  %s\n" "$name" "$sierra" "$bytes" "$casm" "$verdict"
done
