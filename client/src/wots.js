// Winternitz one-time signatures (w = 256) over SHA-256 truncated to 192 bits.
//
// This file must stay byte-for-byte in step with program/src/wots.rs. The
// shared test vector in test/vector.json is checked by both sides.
//
// It runs unchanged in Node and in a browser: hashing comes from
// @noble/hashes, not from either platform's built-ins.

import { Buffer } from 'buffer';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

export const N = 24; // bytes kept from each SHA-256 output
export const MSG_DIGITS = 24; // signed message digest bytes, one chain each
export const CSUM_DIGITS = 2; // checksum bytes, one chain each
export const CHAINS = MSG_DIGITS + CSUM_DIGITS;
export const CHAIN_STEPS = 255; // steps from a chain's secret to its public end
export const SEED_LEN = 16; // per-key public seed
export const SIG_LEN = CHAINS * N; // 624

const TAG_CHAIN = 0;
const TAG_PUBKEY = 1;
const TAG_MESSAGE = 2;
const TAG_CANCEL = 3;

const bytes = (part) => (typeof part === 'string' ? Buffer.from(part, 'utf8') : part);

const sha256 = (...parts) => {
  const h = nobleSha256.create();
  for (const p of parts) h.update(bytes(p));
  return Buffer.from(h.digest());
};

const hmac = (key, ...parts) => {
  const h = nobleHmac.create(nobleSha256, key);
  for (const p of parts) h.update(bytes(p));
  return Buffer.from(h.digest());
};

const u32be = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};

const u64le = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
};

/** Walk chain `i` from step `from` up to (not including) step `to`. */
export function walkChain(pubSeed, i, value, from, to) {
  const buf = Buffer.alloc(SEED_LEN + 3 + N);
  pubSeed.copy(buf, 0);
  buf[SEED_LEN] = TAG_CHAIN;
  buf[SEED_LEN + 1] = i;
  value.copy(buf, SEED_LEN + 3, 0, N);
  for (let j = from; j < to; j++) {
    buf[SEED_LEN + 2] = j;
    sha256(buf).copy(buf, SEED_LEN + 3, 0, N);
  }
  return Buffer.from(buf.subarray(SEED_LEN + 3));
}

const checkIndex = (masterSeed, index) => {
  if (!Buffer.isBuffer(masterSeed) || masterSeed.length !== 32) {
    throw new Error('master seed must be 32 bytes');
  }
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
    throw new Error('key index out of range');
  }
};

/**
 * Derive one-time key number `index` from the master seed. Each index yields
 * an independent key; knowing one reveals nothing about another without the
 * master seed.
 */
export function deriveKey(masterSeed, index) {
  checkIndex(masterSeed, index);
  const idx = u32be(index);
  const pubSeed = hmac(masterSeed, 'qpvault/v1/public-seed', idx).subarray(0, SEED_LEN);
  const secrets = [];
  for (let i = 0; i < CHAINS; i++) {
    secrets.push(hmac(masterSeed, 'qpvault/v1/chain-secret', idx, Buffer.from([i])).subarray(0, N));
  }
  return { pubSeed: Buffer.from(pubSeed), secrets };
}

/** The secret that cancels the payment signed by key number `index`. */
export function deriveCancelSecret(masterSeed, index) {
  checkIndex(masterSeed, index);
  return hmac(masterSeed, 'qpvault/v1/cancel-secret', u32be(index));
}

/** What a payment commits to so that only its signer can cancel it. */
export function cancelHash(vault, sequence, secret) {
  return sha256(Buffer.from([TAG_CANCEL]), vault, u64le(sequence), secret);
}

/** SHA-256 of the full public key (the ends of all 26 chains). */
export function publicKeyHash(pubSeed, secrets) {
  const ends = secrets.map((sk, i) => walkChain(pubSeed, i, sk, 0, CHAIN_STEPS));
  return sha256(pubSeed, Buffer.from([TAG_PUBKEY]), ...ends);
}

/**
 * 32-byte digest of "pay `amount` of `asset` from `vault` to `destination`
 * as its spend number `sequence`, then hand the vault to `nextKeyHash`;
 * cancellable by whoever knows the preimage of `cancelHash`".
 *
 * `asset` is the mint, or 32 zero bytes for SOL. `destination` is the
 * recipient wallet for SOL and the recipient token account for tokens. All
 * keys and hashes are 32-byte buffers; `sequence` and `amount` are BigInts.
 */
export function messageDigest(pubSeed, { programId, vault, sequence, asset, amount, destination, nextKeyHash, cancelHash }) {
  return sha256(
    pubSeed,
    Buffer.from([TAG_MESSAGE]),
    programId,
    vault,
    u64le(sequence),
    asset,
    u64le(amount),
    destination,
    nextKeyHash,
    cancelHash,
  );
}

/** The 26 chain positions a signature of `digest` opens. */
export function digitsOf(digest) {
  const digits = Buffer.alloc(CHAINS);
  digest.copy(digits, 0, 0, MSG_DIGITS);
  let sum = 0;
  for (let i = 0; i < MSG_DIGITS; i++) sum += CHAIN_STEPS - digits[i];
  digits[MSG_DIGITS] = sum >> 8;
  digits[MSG_DIGITS + 1] = sum & 0xff;
  return digits;
}

/** Sign: reveal chain `i` at position `digits[i]`. Use each key ONCE. */
export function sign(pubSeed, secrets, digits) {
  const sig = Buffer.alloc(SIG_LEN);
  for (let i = 0; i < CHAINS; i++) {
    walkChain(pubSeed, i, secrets[i], 0, digits[i]).copy(sig, i * N);
  }
  return sig;
}

/** What the on-chain program computes from a signature. */
export function recoverPublicKeyHash(pubSeed, digits, signature) {
  if (signature.length !== SIG_LEN) throw new Error('bad signature length');
  const ends = [];
  for (let i = 0; i < CHAINS; i++) {
    ends.push(walkChain(pubSeed, i, signature.subarray(i * N, (i + 1) * N), digits[i], CHAIN_STEPS));
  }
  return sha256(pubSeed, Buffer.from([TAG_PUBKEY]), ...ends);
}

/** Number of SHA-256 calls the program makes to check these digits. */
export function verifyCost(digits) {
  let n = 0;
  for (const d of digits) n += CHAIN_STEPS - d;
  return n;
}
