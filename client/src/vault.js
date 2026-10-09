// Vault address, on-chain state, and the instructions the program accepts.

import { Buffer } from 'buffer';
import {
  ComputeBudgetProgram,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from '@solana/web3.js';
import {
  SEED_LEN,
  SIG_LEN,
  cancelHash,
  deriveCancelSecret,
  deriveKey,
  digitsOf,
  messageDigest,
  publicKeyHash,
  sign,
  verifyCost,
} from './wots.js';

export const VAULT_SEED = Buffer.from('qpvault');
export const IX_OPEN = 0;
export const IX_SPEND_SOL = 1;
export const IX_SPEND_TOKEN = 2;
export const IX_CANCEL = 3;

export const STATE_LEN = 107;
export const STATE_VERSION = 1;
export const OUTCOME_PAID = 1;
export const OUTCOME_CANCELLED = 2;

/** Stands in for a mint when the asset is SOL. */
export const SOL_ASSET = new PublicKey(Buffer.alloc(32));

/** Largest transaction Solana will carry. */
export const MAX_TX_BYTES = 1232;
/** Largest compute budget one transaction may request. */
export const MAX_COMPUTE_UNITS = 1_400_000;

// Compute cost, measured on a local validator (test/e2e.mjs prints the fit):
// about 131 CU per hash plus a few thousand fixed. A token send adds the
// token program's transfer and, when needed, creating the recipient's token
// account in the same transaction. These constants round all of that up, and
// the e2e test fails if a real transaction ever uses more than the estimate.
export const CU_FIXED = 10_000;
export const CU_PER_HASH = 140;
export const CU_TOKEN_EXTRA = 70_000;

/** Compute units to request for a transaction that verifies `hashes` hashes. */
export const computeLimit = (hashes, { token = false } = {}) =>
  CU_FIXED + CU_PER_HASH * hashes + (token ? CU_TOKEN_EXTRA : 0);

/** One-time key number `index`, with its on-chain hash and its cancel secret. */
export function deriveVaultKey(masterSeed, index) {
  const key = deriveKey(masterSeed, index);
  return {
    index,
    ...key,
    keyHash: publicKeyHash(key.pubSeed, key.secrets),
    cancelSecret: deriveCancelSecret(masterSeed, index),
  };
}

/** The permanent address of the vault whose first key has this hash. */
export function vaultAddress(programId, firstKeyHash) {
  return PublicKey.findProgramAddressSync([VAULT_SEED, firstKeyHash], programId)[0];
}

/** Parse a vault account's data, or return null if it is not an opened vault. */
export function decodeState(data) {
  if (!data || data.length !== STATE_LEN || data[0] !== STATE_VERSION) return null;
  const b = Buffer.from(data);
  return {
    bump: b[1],
    firstKeyHash: b.subarray(2, 34),
    keyHash: b.subarray(34, 66),
    sequence: b.readBigUInt64LE(66),
    outcome: b[74],
    lastMessage: b.subarray(75, 107),
  };
}

/** Create the vault account. Anyone can send this; `payer` covers the rent reserve. */
export function openInstruction({ programId, payer, vault, firstKeyHash }) {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([IX_OPEN]), firstKeyHash]),
  });
}

/**
 * The message key `key` would sign, without signing it.
 *
 * `asset` is a mint PublicKey, or SOL_ASSET. `destination` is the recipient
 * wallet for SOL and the recipient *token account* for tokens.
 */
export function describeMessage({ programId, vault, sequence, key, nextKeyHash, asset, destination, amount }) {
  const commitment = cancelHash(vault.toBuffer(), sequence, key.cancelSecret);
  const digest = messageDigest(key.pubSeed, {
    programId: programId.toBuffer(),
    vault: vault.toBuffer(),
    sequence,
    asset: asset.toBuffer(),
    amount,
    destination: destination.toBuffer(),
    nextKeyHash,
    cancelHash: commitment,
  });
  return { digest, cancelHash: commitment };
}

/**
 * Sign one message with one key.
 *
 * A key that signs two different messages leaks enough for someone else to
 * forge a third. The wallet layer (wallet.js) is what guarantees that never
 * happens; call this directly only if you do the same bookkeeping yourself.
 */
export function signMessage(message) {
  const { key, nextKeyHash, amount } = message;
  const { digest, cancelHash: commitment } = describeMessage(message);
  const digits = digitsOf(digest);
  return {
    amount,
    pubSeed: key.pubSeed,
    nextKeyHash,
    cancelHash: commitment,
    cancelSecret: key.cancelSecret,
    signature: sign(key.pubSeed, key.secrets, digits),
    digest,
    digits,
    hashes: verifyCost(digits),
  };
}

/** amount | public seed | next key hash | cancel hash (or secret) | signature */
function signedFields(s, cancelField) {
  if (s.pubSeed.length !== SEED_LEN) throw new Error('bad public seed length');
  if (s.nextKeyHash.length !== 32) throw new Error('bad next key hash length');
  if (cancelField.length !== 32) throw new Error('bad cancel field length');
  if (s.signature.length !== SIG_LEN) throw new Error('bad signature length');
  const amount = Buffer.alloc(8);
  amount.writeBigUInt64LE(s.amount);
  return Buffer.concat([amount, s.pubSeed, s.nextKeyHash, cancelField, s.signature]);
}

/** Pay SOL to `recipient`. */
export function spendSolInstruction({ programId, vault, recipient, signed }) {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([Buffer.from([IX_SPEND_SOL]), signedFields(signed, signed.cancelHash)]),
  });
}

/** Pay tokens from the vault's token account `source` to the token account `destination`. */
export function spendTokenInstruction({ programId, vault, source, destination, mint, tokenProgram, signed }) {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([IX_SPEND_TOKEN]), signedFields(signed, signed.cancelHash)]),
  });
}

/** Use up the key that signed `signed` without paying. Reveals the cancel secret. */
export function cancelInstruction({ programId, vault, asset, destination, signed }) {
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: vault, isSigner: false, isWritable: true }],
    data: Buffer.concat([
      Buffer.from([IX_CANCEL]),
      asset.toBuffer(),
      destination.toBuffer(),
      signedFields(signed, signed.cancelSecret),
    ]),
  });
}

/**
 * Wrap vault instructions in a transaction. The fee payer is an ordinary
 * Solana keypair: it pays the network fee (and rent for a recipient's new
 * token account) and nothing else, and it has no power over the vault.
 */
export function buildTransaction({ instructions, units, feePayer, blockhash, lastValidBlockHeight, microLamportsPerCu }) {
  const tx = new Transaction({ feePayer, blockhash, lastValidBlockHeight });
  tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units }));
  if (microLamportsPerCu) {
    tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: microLamportsPerCu }));
  }
  tx.add(...instructions);
  return tx;
}
