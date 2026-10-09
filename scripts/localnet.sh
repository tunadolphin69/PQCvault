#!/usr/bin/env bash
# Build the program and run a throwaway local validator with it loaded.
# Needs the Solana CLI (https://docs.anza.xyz/cli/install).
set -euo pipefail
cd "$(dirname "$0")/.."

(cd program && cargo build-sbf --arch v3)
PROGRAM_ID=$(solana-keygen pubkey program/target/deploy/qp_vault-keypair.json)

echo
echo "program id: $PROGRAM_ID"
echo "in another terminal:"
echo "  cd client && QPV_PROGRAM=$PROGRAM_ID npm run e2e"
echo

exec solana-test-validator --reset --quiet \
  --ledger "${TMPDIR:-/tmp}/qp-vault-ledger" \
  --bpf-program "$PROGRAM_ID" program/target/deploy/qp_vault.so
