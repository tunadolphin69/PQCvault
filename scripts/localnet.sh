#!/usr/bin/env bash
# Build the program, run a throwaway local validator, and deploy the program
# to it the same way it would be deployed for real: final, with no upgrade
# authority. Needs the Solana CLI (https://docs.anza.xyz/cli/install).
set -euo pipefail
cd "$(dirname "$0")/.."

URL=http://127.0.0.1:8899
WORK="${TMPDIR:-/tmp}/qp-vault-localnet"
mkdir -p "$WORK"

(cd program && cargo build-sbf --arch v3)

solana-test-validator --reset --quiet --ledger "$WORK/ledger" &
VALIDATOR=$!
trap 'kill $VALIDATOR 2>/dev/null' EXIT

echo "waiting for the validator..."
until solana -u "$URL" cluster-version >/dev/null 2>&1; do sleep 1; done

# A fresh program address each run, so nothing is left over from the last one.
solana-keygen new --no-bip39-passphrase --silent --force -o "$WORK/deployer.json" >/dev/null
solana-keygen new --no-bip39-passphrase --silent --force -o "$WORK/program.json" >/dev/null
solana -u "$URL" airdrop 5 "$WORK/deployer.json" >/dev/null
solana -u "$URL" -k "$WORK/deployer.json" program deploy program/target/deploy/qp_vault.so \
  --program-id "$WORK/program.json" --final >/dev/null
PROGRAM_ID=$(solana-keygen pubkey "$WORK/program.json")

cat <<MSG

program id: $PROGRAM_ID   (deployed final: nobody can change it)

in another terminal, from client/:
  QPV_PROGRAM=$PROGRAM_ID npm run e2e
  npm run web:build && QPV_PROGRAM=$PROGRAM_ID npm run web:e2e
  npm run web:dev      then open  http://127.0.0.1:5173/?program=$PROGRAM_ID&rpc=$URL

Ctrl-C stops the validator.
MSG
wait $VALIDATOR
