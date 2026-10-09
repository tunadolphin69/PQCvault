# QP Vault

> **Read this first**
>
> - **Experimental and unaudited.** No independent security review has been
>   done. It passes the tests described below on a local validator, and that
>   is all that can be said for it. Bugs in this kind of software can lose
>   funds permanently.
> - **Not deployed.** The program is not live on Solana mainnet. This
>   repository is source code. Anyone who deploys it does so themselves and
>   at their own risk.
> - **Not affiliated.** This is an independent project. It is not made by,
>   endorsed by, or connected to pqc.market, pump.fun, the Solana Foundation,
>   or any other project or company. It is unrelated to the `pqc-vault`
>   repository published by pqc.market.
> - **No token is part of this software.** Nothing here needs a token to
>   work. A token that links to this repository does not make the code
>   audited, safe, or finished, and gives no rights to it.
> - **No warranty.** Provided as is. Nothing here is financial advice.
>   Use devnet. Do not put in money you are not prepared to lose.

A Solana vault for SOL and tokens that no elliptic-curve key can open. Funds
leave only when the on-chain program verifies a hash-based (Winternitz)
one-time signature, so recovering an ed25519 private key, by quantum computer
or any other way, gets an attacker nothing.

It holds SOL, SPL tokens and Token-2022 tokens (the kind pump.fun coins use)
at one permanent address, and every payment is a single transaction.

## How it works

- Your wallet holds a 32-byte master seed. From it, it derives an endless
  series of one-time keys: #0, #1, #2, ...
- The vault is one account at one permanent address. It stores the hash of
  the *current* key and a counter. Tokens sit in ordinary token accounts
  owned by that address.
- To pay someone, the wallet signs "pay X of asset A to Y, and the next key
  is K" with the current key. The program checks the signature, pays, and
  switches the vault to key K, all in one transaction.
- The signature that was just published is useless from that moment: the key
  it belongs to no longer controls anything. It cannot be replayed.
- Every signed payment also carries a commitment to a cancel secret. If a
  payment gets stuck, the owner can reveal the secret to retire that key
  without paying, and carry on with the next one.

The address is derived from the hash of key #0, so it has no private key at
all, and it never changes. Deposit to it as often as you like, from anywhere.

Only SHA-256 is involved in authorising a payment. Forging a signature means
inverting SHA-256 truncated to 192 bits: on the order of 2^192 work
classically, and about 2^96 with Grover's algorithm, the best known quantum
attack on hash preimages. The signature sizes are those of NIST SP 800-208's
`LMOTS_SHA256_N24_W8`; the hash input layout is this project's own. 192 bits
is what lets a token transfer, the recipient's new token account and the
signature fit in one transaction.

## What it does not protect

- **The network itself.** Solana validators sign blocks and votes with
  ed25519. The vault stops someone stealing from your address; it cannot stop
  an attacker who is strong enough to disrupt the chain.
- **The fee payer.** Every transaction needs an ordinary Solana keypair to
  pay the fee (and the rent for a recipient's new token account). It has no
  power over the vault. Keep only small change in it.
- **An upgradeable deployment.** If the program can be upgraded, whoever
  holds the (ed25519) upgrade key can replace it and drain every vault.
  Deploy with `--final`, as shown below, and check `Authority: none`.
- **Your seed file.** It sits on disk in plain text with owner-only
  permissions, like a Solana CLI keypair. Anyone who copies it can spend.
- **What a token's issuer can do.** If a token can be frozen, paused or
  clawed back by its issuer, it still can be while it sits in the vault.

## What it cannot do

- Swap, trade, or connect to a dapp. It holds and sends.
- Send tokens that use a Token-2022 transfer hook, or non-transferable
  tokens. The wallet refuses these before signing.
- Close its own empty token accounts. Their rent (about 0.002 SOL each, paid
  by whoever created them) stays put.

## Try it locally

Needs Rust, Node 20+, and the [Solana CLI](https://docs.anza.xyz/cli/install).

```sh
./scripts/localnet.sh              # builds the program, starts a local validator, prints the program id

# in a second terminal
cd client
npm install
npm test                           # offline unit tests
QPV_PROGRAM=<program id> npm run e2e
```

`cargo test` in `program/` runs the native signature tests.

## Use it on devnet

```sh
solana config set --url devnet
solana airdrop 2                              # deploying costs about 0.27 SOL in rent

cd program
cargo build-sbf --arch v3
solana program deploy target/deploy/qp_vault.so --final
solana program show <program id>              # must say "Authority: none"

cd ../client
npm install
npm link                                      # or use: node src/cli.js

qpv init --program <program id>               # prints your seed (back it up) and vault address
solana transfer <vault address> 1 --allow-unfunded-recipient
qpv balance
qpv send <recipient address> 0.25
```

Tokens:

```sh
qpv token-address <mint>                      # once per token: creates the vault's token account
                                              # then send the token to the vault from any wallet
qpv balance
qpv send-token <mint> <recipient address> 250
qpv send-token <mint> <recipient address> all
```

The recipient is a normal wallet address. If they have no account for that
token yet, it is created in the same transaction.

If a cluster refuses the deploy with `sbpf_version ... not enabled`, it does
not accept that bytecode version yet: build with plain `cargo build-sbf`
instead.

To restore on another machine: `qpv init --program <id> --seed <your seed>`.
The wallet reads the vault's counter from the chain and carries on from the
right key.

## Rules for safe use

A one-time key that signs two *different* messages leaks enough for someone
else to forge a third. The wallet is built so that this cannot happen in
normal use:

- Before it signs, it writes the exact payment to disk. From then on the
  current key will only ever sign that same payment again.
- If a payment does not confirm, `qpv resume` re-sends the identical payment
  and `qpv cancel` calls it off. Until one of those succeeds, nothing else
  can leave the vault, SOL included.
- A cancel is a race with the payment it cancels: if the payment was already
  broadcast it may still land first. The wallet reports which one happened,
  from the vault's own on-chain record.
- It refuses to sign if the RPC node shows an older vault state than it has
  already seen, or if the vault's current key is not one your seed produces.
- It checks for the failures it can foresee before signing: frozen token
  accounts, unsupported tokens, recipients that are programs or mints, and
  amounts Solana would reject.

What you must not do:

- Do not edit the wallet file by hand or roll it back to an old copy while a
  payment is pending.
- Do not send from two machines with the same seed at the same moment.

## Costs and sizes (measured on a local validator, Agave 4.3.0)

| | |
|---|---|
| SOL payment | 989 of 1,232 bytes |
| Token payment | 1,206 bytes including the recipient's new token account and a priority fee |
| Compute per payment | 359k to 521k CU in one run of 40 SOL payments, mean 445k; token payments 380k and 475k in the two measured; worst possible case about 0.85M of the 1.4M limit |
| Fee per payment | 0.000005 SOL (one fee-payer signature), plus any priority fee you add |
| Rent reserve | 0.0016356 SOL stays in the vault permanently, so the account can never be deleted |
| Program size | 38,320 bytes; 0.27 SOL to deploy |
| Signature | 624 bytes (26 hash chains of 24 bytes, Winternitz w = 256) |

## Layout

```
program/src/wots.rs     signature verification
program/src/lib.rs      Open, SpendSol, SpendToken, Cancel; vault state
program/tests/          native tests, including a vector shared with the client
client/src/wots.js      key derivation and signing (mirror of wots.rs)
client/src/vault.js     addresses, instructions, transactions
client/src/wallet.js    seed file, planning, and the one-signature-per-key bookkeeping
client/src/cli.js       the qpv command
client/test/            offline unit tests and the end-to-end test
```

## What the tests cover

End-to-end, on a real validator, against a program deployed immutably
through the normal loader (78 checks):

- A payment is rejected if the recipient, amount, asset, next key or cancel
  commitment is changed; if any signature bit is flipped; if a hash chain is
  walked forward (the classic Winternitz forgery attempt); if the signature
  comes from another vault, another sequence number, a later key or a
  retired key; if a SOL signature is used for tokens or the reverse; if it is
  replayed; and if it would dip into the rent reserve.
- Token payments are rejected with a made-up token program, the wrong real
  one, a non-mint in the mint slot, another mint the vault holds, or an
  attacker's destination account. Both SPL Token and Token-2022 are run.
- A stranger relaying a valid signature causes exactly the signed outcome.
- Cancel needs the secret: the public commitment, a wrong secret, or a
  changed amount, destination or next key all fail. A payment stuck on a
  frozen token account is cancelled and the next key then works.
- Forty consecutive payments from one vault all succeed within the client's
  compute estimate.

Offline (26 checks): the JavaScript and Rust implementations agree on a
shared test vector; the wallet locks before signing, re-signs identically
after failures, recognises its own payment after a crash or when a third
party relays it, reports a payment as not sent when another copy of the
wallet used the key first, refuses stale RPC data, and refuses frozen,
hooked, paused and non-transferable tokens and misdirected recipients before
signing.
