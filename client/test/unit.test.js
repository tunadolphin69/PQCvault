// Offline tests: `npm test`. No network, no validator.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AccountLayout,
  MintLayout,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import bs58 from 'bs58';
import {
  IX_CANCEL,
  IX_OPEN,
  IX_SPEND_SOL,
  IX_SPEND_TOKEN,
  MAX_COMPUTE_UNITS,
  MAX_TX_BYTES,
  SOL_ASSET,
  STATE_LEN,
  buildTransaction,
  computeLimit,
  decodeState,
  deriveVaultKey,
  signMessage,
  spendTokenInstruction,
  vaultAddress,
} from '../src/vault.js';
import { createFileWallet, loadFileWallet } from '../src/file-wallet.js';
import { explainError, formatSol, formatUnits, keypairSigner, parseSol, parseUnits, requireImmutableProgram } from '../src/wallet.js';
import {
  CHAINS,
  CHAIN_STEPS,
  SIG_LEN,
  cancelHash,
  deriveCancelSecret,
  deriveKey,
  digitsOf,
  messageDigest,
  publicKeyHash,
  recoverPublicKeyHash,
  sign,
  verifyCost,
} from '../src/wots.js';

const vector = JSON.parse(readFileSync(new URL('./vector.json', import.meta.url), 'utf8'));
const hex = (s) => Buffer.from(s, 'hex');
const programId = Keypair.generate().publicKey;
const someone = () => Keypair.generate().publicKey.toBase58();

const randomMessage = (over = {}) => ({
  programId: randomBytes(32),
  vault: randomBytes(32),
  sequence: 0n,
  asset: randomBytes(32),
  amount: 1n,
  destination: randomBytes(32),
  nextKeyHash: randomBytes(32),
  cancelHash: randomBytes(32),
  ...over,
});

test('matches the committed test vector (shared with the Rust program)', () => {
  const { pubSeed, secrets } = deriveKey(hex(vector.master), vector.index);
  assert.equal(pubSeed.toString('hex'), vector.pubSeed);
  assert.equal(publicKeyHash(pubSeed, secrets).toString('hex'), vector.pubkeyHash);
  const secret = deriveCancelSecret(hex(vector.master), vector.index);
  assert.equal(secret.toString('hex'), vector.cancelSecret);
  assert.equal(cancelHash(hex(vector.vault), BigInt(vector.index), secret).toString('hex'), vector.cancelHash);
  const digest = messageDigest(pubSeed, {
    programId: hex(vector.programId), vault: hex(vector.vault), sequence: BigInt(vector.index), asset: hex(vector.asset),
    amount: BigInt(vector.amount), destination: hex(vector.destination), nextKeyHash: hex(vector.nextKeyHash),
    cancelHash: hex(vector.cancelHash),
  });
  assert.equal(digest.toString('hex'), vector.digest);
  const digits = digitsOf(digest);
  assert.equal(digits.toString('hex'), vector.digits);
  assert.equal(verifyCost(digits), vector.hashes);
  assert.equal(sign(pubSeed, secrets, digits).toString('hex'), vector.signature);
});

test('a signature recovers the public key; any other message does not', () => {
  for (let round = 0; round < 5; round++) {
    const { pubSeed, secrets } = deriveKey(randomBytes(32), round);
    const pkh = publicKeyHash(pubSeed, secrets);
    const digits = digitsOf(messageDigest(pubSeed, randomMessage()));
    const sig = sign(pubSeed, secrets, digits);
    assert.equal(sig.length, SIG_LEN);
    assert.deepEqual(recoverPublicKeyHash(pubSeed, digits, sig), pkh);
    assert.notDeepEqual(recoverPublicKeyHash(pubSeed, digitsOf(messageDigest(pubSeed, randomMessage())), sig), pkh);
  }
});

test('a second message always needs some chain opened earlier', () => {
  const pubSeed = randomBytes(16);
  const signed = digitsOf(messageDigest(pubSeed, randomMessage()));
  for (let k = 0; k < 20000; k++) {
    const other = digitsOf(messageDigest(pubSeed, randomMessage({ amount: BigInt(k) })));
    let earlier = false;
    for (let i = 0; i < CHAINS; i++) earlier ||= other[i] < signed[i];
    assert(earlier);
  }
});

test('each key index gives unrelated key material', () => {
  const master = randomBytes(32);
  const seen = new Set();
  for (let i = 0; i < 20; i++) {
    const k = deriveVaultKey(master, i);
    for (const part of [k.keyHash, k.pubSeed, k.cancelSecret, ...k.secrets]) seen.add(part.toString('hex'));
    assert.deepEqual(deriveVaultKey(master, i).keyHash, k.keyHash);
  }
  assert.equal(seen.size, 20 * (3 + CHAINS));
});

test('the largest transaction the wallet builds fits in one packet', () => {
  // Token payment + creating the recipient's token account + priority fee.
  const master = randomBytes(32);
  const feePayer = Keypair.generate();
  const vault = vaultAddress(programId, deriveVaultKey(master, 0).keyHash);
  const mint = Keypair.generate().publicKey;
  const recipient = Keypair.generate().publicKey;
  const destination = getAssociatedTokenAddressSync(mint, recipient, true, TOKEN_2022_PROGRAM_ID);
  const signed = signMessage({
    programId, vault, sequence: 0n, key: deriveVaultKey(master, 0), nextKeyHash: deriveVaultKey(master, 1).keyHash,
    asset: mint, destination, amount: 5n,
  });
  const create = {
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [feePayer.publicKey, destination, recipient, mint, SystemProgram.programId, TOKEN_2022_PROGRAM_ID].map((pubkey, i) => ({
      pubkey, isSigner: i === 0, isWritable: i < 2,
    })),
    data: Buffer.from([1]),
  };
  const tx = buildTransaction({
    instructions: [
      create,
      spendTokenInstruction({
        programId, vault, source: getAssociatedTokenAddressSync(mint, vault, true, TOKEN_2022_PROGRAM_ID),
        destination, mint, tokenProgram: TOKEN_2022_PROGRAM_ID, signed,
      }),
    ],
    units: 1, feePayer: feePayer.publicKey,
    blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1, microLamportsPerCu: 1000,
  });
  tx.sign(feePayer);
  assert(tx.serialize().length <= MAX_TX_BYTES, `${tx.serialize().length} bytes`);
});

test('the worst possible digest still fits the compute limit', () => {
  assert(computeLimit(CHAINS * CHAIN_STEPS, { token: true }) < MAX_COMPUTE_UNITS);
});

test('amounts convert exactly', () => {
  assert.equal(parseSol('1'), 1_000_000_000n);
  assert.equal(parseSol('0.000000001'), 1n);
  assert.equal(parseSol('123.456'), 123_456_000_000n);
  assert.equal(formatSol(123_456_000_000n), '123.456');
  assert.equal(formatSol(1n), '0.000000001');
  assert.equal(parseUnits('250.5', 6), 250_500_000n);
  assert.equal(formatUnits(250_500_000n, 6), '250.5');
  assert.equal(parseUnits('7', 0), 7n);
  assert.equal(formatUnits(7n, 0), '7');
  for (const bad of ['', '1.', '.5', '1e3', '-1', '0.0000000001', 'abc']) assert.throws(() => parseSol(bad));
  assert.throws(() => parseUnits('1.0000001', 6));
  assert.throws(() => parseUnits('1.5', 0));
});

// ------------------------------------------------------------------ wallet
//
// A small in-memory stand-in for the chain. It applies the vault's
// instructions with the same rules as the on-chain program (re-implemented
// here in JS), so these tests also prove that what the wallet signs is what
// the rules accept.

const RESERVE = BigInt((128 + STATE_LEN) * 6960);

function fakeChain() {
  const accounts = new Map(); // base58 -> { lamports, owner, data, executable }
  const get = (pk) => accounts.get(pk.toBase58());
  const put = (pk, a) => accounts.set(pk.toBase58(), { lamports: 2_000_000n, executable: false, ...a });
  const tokenAccount = (pk) => AccountLayout.decode(get(pk).data);
  const setTokens = (pk, fields) => {
    const a = get(pk);
    AccountLayout.encode({ ...AccountLayout.decode(a.data), ...fields }, a.data);
  };
  const chain = {
    accounts,
    sent: [],
    landed: new Set(), // transaction ids that took effect
    failNextSend: null, // throw this from sendRawTransaction...
    dropNextSend: false, // ...and do not apply the transaction either
    stale: null, // serve this old snapshot of an account instead of the real one

    fund(pk, lamports) {
      const a = get(pk) ?? { lamports: 0n, owner: SystemProgram.programId, data: Buffer.alloc(0), executable: false };
      a.lamports += lamports;
      accounts.set(pk.toBase58(), a);
    },
    /** Create a mint. `data` lets a test attach Token-2022 extensions. */
    mint(tokenProgram = TOKEN_PROGRAM_ID, decimals = 6) {
      const mint = Keypair.generate().publicKey;
      const data = Buffer.alloc(MintLayout.span);
      MintLayout.encode({ mintAuthorityOption: 0, mintAuthority: PublicKey.default, supply: 0n, decimals, isInitialized: true, freezeAuthorityOption: 0, freezeAuthority: PublicKey.default }, data);
      put(mint, { owner: tokenProgram, data });
      return mint;
    },
    /** Give `owner` some of `mint` in its associated token account; returns that account. */
    tokens(mint, owner, amount, { frozen = false } = {}) {
      const tokenProgram = get(mint).owner;
      const account = getAssociatedTokenAddressSync(mint, owner, true, tokenProgram);
      const data = Buffer.alloc(AccountLayout.span);
      AccountLayout.encode({ mint, owner, amount, delegateOption: 0, delegate: PublicKey.default, state: frozen ? 2 : 1, isNativeOption: 0, isNative: 0n, delegatedAmount: 0n, closeAuthorityOption: 0, closeAuthority: PublicKey.default }, data);
      put(account, { owner: tokenProgram, data });
      return account;
    },
    freeze: (account, frozen = true) => setTokens(account, { state: frozen ? 2 : 1 }),
    balanceOf: (account) => (get(account) ? tokenAccount(account).amount : 0n),

    getBalance: async (pk) => Number(get(pk)?.lamports ?? 0n),
    getAccountInfo: async (pk) => {
      const a = chain.stale?.[pk.toBase58()] ?? get(pk);
      return a ? { ...a, lamports: Number(a.lamports), data: Buffer.from(a.data) } : null;
    },
    getMinimumBalanceForRentExemption: async (size) => (128 + size) * 6960,
    getLatestBlockhash: async () => ({ blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 100 }),
    confirmTransaction: async () => ({ value: { err: null } }),
    getSignatureStatuses: async (ids) => ({
      value: ids.map((id) => (chain.landed.has(id) ? { err: null, confirmationStatus: 'confirmed' } : null)),
    }),
    getParsedTokenAccountsByOwner: async (owner, { programId: tokenProgram }) => ({
      value: [...accounts].flatMap(([address, a]) => {
        if (!a.owner.equals(tokenProgram) || a.data.length !== AccountLayout.span) return [];
        const t = AccountLayout.decode(a.data);
        if (!t.owner.equals(owner)) return [];
        const decimals = MintLayout.decode(get(t.mint).data).decimals;
        const info = { mint: t.mint.toBase58(), state: t.state === 2 ? 'frozen' : 'initialized', tokenAmount: { amount: t.amount.toString(), decimals } };
        return [{ pubkey: new PublicKey(address), account: { data: { parsed: { info } } } }];
      }),
    }),
    sendRawTransaction: async (raw) => {
      chain.sent.push(Buffer.from(raw));
      const tx = Transaction.from(raw);
      const txid = bs58.encode(tx.signature);
      const drop = chain.dropNextSend;
      chain.dropNextSend = false;
      if (!drop) {
        // All or nothing, like a real transaction.
        const snapshot = new Map([...accounts].map(([k, a]) => [k, { ...a, data: Buffer.from(a.data) }]));
        try {
          for (const ix of tx.instructions) apply(ix);
          chain.landed.add(txid);
        } catch (e) {
          accounts.clear();
          for (const [k, a] of snapshot) accounts.set(k, a);
          throw e;
        }
      }
      if (chain.failNextSend) {
        const e = chain.failNextSend;
        chain.failNextSend = null;
        throw e;
      }
      return txid;
    },
  };

  /** The program's one gate: check the signature, then rotate. */
  function authorize(vault, asset, destination, fields, commitment, outcome) {
    const a = get(vault);
    const st = decodeState(a.data);
    const amount = fields.readBigUInt64LE(0);
    const pubSeed = fields.subarray(8, 24);
    const next = fields.subarray(24, 56);
    const digest = messageDigest(pubSeed, {
      programId: programId.toBuffer(), vault: vault.toBuffer(), sequence: st.sequence, asset: asset.toBuffer(), amount,
      destination: destination.toBuffer(), nextKeyHash: next, cancelHash: commitment,
    });
    if (!recoverPublicKeyHash(pubSeed, digitsOf(digest), fields.subarray(88)).equals(st.keyHash)) throw new Error('BadSignature');
    next.copy(a.data, 34);
    a.data.writeBigUInt64LE(st.sequence + 1n, 66);
    a.data[74] = outcome;
    digest.copy(a.data, 75);
    return amount;
  }

  function apply(ix) {
    if (ix.programId.equals(ASSOCIATED_TOKEN_PROGRAM_ID)) {
      const [, account, owner, mint] = ix.keys.map((k) => k.pubkey);
      if (!get(account)) chain.tokens(mint, owner, 0n);
      return;
    }
    if (!ix.programId.equals(programId)) return;
    const keys = ix.keys.map((k) => k.pubkey);
    const body = ix.data.subarray(1);
    switch (ix.data[0]) {
      case IX_OPEN: {
        const vault = keys[1];
        assert(vault.equals(vaultAddress(programId, body)), 'open: wrong address');
        const a = get(vault) ?? { lamports: 0n };
        assert(!a.data?.length, 'open: already opened');
        const data = Buffer.alloc(STATE_LEN);
        data[0] = 1;
        body.copy(data, 2);
        body.copy(data, 34);
        put(vault, { lamports: a.lamports < RESERVE ? RESERVE : a.lamports, owner: programId, data });
        return;
      }
      case IX_SPEND_SOL: {
        const [vault, recipient] = keys;
        const amount = authorize(vault, SOL_ASSET, recipient, body, body.subarray(56, 88), 1);
        if (amount > get(vault).lamports - RESERVE) throw new Error('InsufficientFunds');
        get(vault).lamports -= amount;
        chain.fund(recipient, amount);
        return;
      }
      case IX_SPEND_TOKEN: {
        const [vault, source, destination, mint] = keys;
        const amount = authorize(vault, mint, destination, body, body.subarray(56, 88), 1);
        const from = tokenAccount(source);
        const to = tokenAccount(destination);
        if (from.state === 2 || to.state === 2) throw Object.assign(new Error('frozen'), { logs: ['Program log: Error: Account is frozen'] });
        if (!from.owner.equals(vault) || !from.mint.equals(mint) || !to.mint.equals(mint)) throw new Error('token program refused');
        if (amount > from.amount) throw new Error('insufficient tokens');
        setTokens(source, { amount: from.amount - amount });
        setTokens(destination, { amount: tokenAccount(destination).amount + amount });
        return;
      }
      case IX_CANCEL: {
        const [vault] = keys;
        const asset = new PublicKey(body.subarray(0, 32));
        const destination = new PublicKey(body.subarray(32, 64));
        const fields = body.subarray(64);
        const sequence = decodeState(get(vault).data).sequence;
        authorize(vault, asset, destination, fields, cancelHash(vault.toBuffer(), sequence, fields.subarray(56, 88)), 2);
        return;
      }
      default:
        throw new Error('unknown instruction');
    }
  }
  return chain;
}

/** The vault instruction's signed fields inside a serialized transaction (its last 712 bytes). */
const signedBytes = (raw) => raw.subarray(raw.length - 712).toString('hex');

const newPath = () => join(mkdtempSync(join(tmpdir(), 'qpv-')), 'wallet.json');
const newWallet = (masterSeed) => createFileWallet(newPath(), { programId, url: 'http://unused', masterSeed });
/** The same wallet file opened again, as after a restart. */
const reopen = (w) => loadFileWallet(w.store.path);

/** A wallet whose vault is open on `chain` and holds `sol` spendable SOL. */
async function funded(chain, sol = 2n) {
  const w = newWallet();
  await w.open(chain, payer());
  chain.fund(w.address, sol * 1_000_000_000n);
  chain.sent.length = 0;
  return w;
}

const payer = () => keypairSigner(Keypair.generate());

test('wallet file is private and refuses to be overwritten', () => {
  const w = newWallet();
  assert.equal(statSync(w.store.path).mode & 0o777, 0o600);
  assert.throws(() => createFileWallet(w.store.path, { programId, url: 'x' }));
  // The seed is in the file, and survives saves that only touch the state.
  w.save();
  assert.deepEqual(reopen(w).masterSeed, w.masterSeed);
  assert.equal('masterSeed' in w.state, false);
});

test('open creates the vault; early deposits survive; nothing is spendable from the reserve', async () => {
  const chain = fakeChain();
  const w = newWallet();
  assert.deepEqual(await w.sync(chain), { opened: false, lamports: 0n, sequence: 0, reserve: RESERVE, spendable: 0n });
  await assert.rejects(w.planSol(chain, someone(), '1'), /not been opened/);
  chain.fund(w.address, 5_000_000_000n);
  await w.open(chain, payer());
  const v = await w.sync(chain);
  assert.equal(v.opened, true);
  assert.equal(v.spendable, 5_000_000_000n - RESERVE);
});

test('a normal SOL payment: locked on disk before signing, then moves to the next key', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const to = Keypair.generate().publicKey;

  const plan = await w.planSol(chain, to.toBase58(), '0.5');
  assert.equal(plan.index, 0);
  assert.equal(plan.amount, 500_000_000n);
  assert.equal(plan.left, 1_500_000_000n);
  assert.equal(chain.sent.length, 0);
  assert.equal(w.pending, null); // planning never locks anything

  w.commit(plan);
  // The lock is on disk before any signature exists.
  assert.equal(reopen(w).pending.recipient, to.toBase58());
  assert.equal(chain.sent.length, 0);

  const result = await w.sendPending(chain, payer());
  assert.equal(result.outcome, 'sent');
  assert(chain.landed.has(result.txid));
  assert.equal(await chain.getBalance(to), 500_000_000);
  const reloaded = reopen(w);
  assert.equal(reloaded.pending, null);
  assert.equal(reloaded.state.sequence, 1);
  assert.deepEqual(
    { ...reloaded.state.history[0], finishedAt: null },
    { index: 0, asset: 'SOL', decimals: 9, recipient: to.toBase58(), amount: '500000000', outcome: 'sent', txid: result.txid, finishedAt: null },
  );

  // And again with key #1, from the same address.
  const second = await reloaded.planSol(chain, to.toBase58(), 'all');
  assert.equal(second.index, 1);
  reloaded.commit(second);
  assert.equal((await reloaded.sendPending(chain, payer())).outcome, 'sent');
  assert.equal(BigInt(await chain.getBalance(reloaded.address)), RESERVE);
  assert.equal(await chain.getBalance(to), 2_000_000_000);
});

test('a failed send keeps the lock, and every retry signs the identical message', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  w.commit(await w.planSol(chain, someone(), '1'));

  chain.dropNextSend = true;
  chain.failNextSend = new Error('rpc went away');
  const first = await w.sendPending(chain, payer());
  assert.equal(first.outcome, 'pending');
  assert.match(first.error.message, /rpc went away/);

  // Still locked, across a restart, and a different payment is refused.
  const again = reopen(w);
  assert.equal(again.pending.amount, '1000000000');
  assert.equal(again.state.sequence, 0);
  await assert.rejects(again.planSol(chain, someone(), '0.1'), /already pending/);
  assert.throws(() => again.commit({ index: 0 }), /already pending/);

  // Retries with other fee payers and blockhashes: same vault signature, byte for byte.
  chain.dropNextSend = true;
  chain.failNextSend = new Error('still down');
  await again.sendPending(chain, payer());
  assert.equal((await again.sendPending(chain, payer())).outcome, 'sent');
  assert.equal(chain.sent.length, 3);
  assert.equal(new Set(chain.sent.map(signedBytes)).size, 1);
  assert.equal(reopen(w).state.sequence, 1);
});

test('a send reported as failed that actually landed is recorded, not repeated', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const to = Keypair.generate().publicKey;
  w.commit(await w.planSol(chain, to.toBase58(), '1'));
  chain.failNextSend = new Error('timeout'); // applied on-chain, but the RPC call errors
  const result = await w.sendPending(chain, payer());
  assert.equal(result.outcome, 'sent');
  assert(chain.landed.has(result.txid));
  assert.equal(w.pending, null);
  assert.equal(w.state.sequence, 1);
  assert.equal(await chain.getBalance(to), 1_000_000_000);
  assert.equal(chain.sent.length, 1);
  await assert.rejects(w.sendPending(chain, payer()), /nothing is pending/);
});

test('if the wallet died right after broadcasting, resume finds the payment and signs nothing', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  w.commit(await w.planSol(chain, someone(), '1'));
  const locked = structuredClone(w.state.pending);
  const { txid } = await w.sendPending(chain, payer());

  // Rewind the file to what was on disk at the moment of broadcast.
  const reopened = reopen(w);
  reopened.state.pending = { ...locked, txids: [{ id: txid, kind: 'pay' }] };
  reopened.state.sequence = 0;
  reopened.state.history = [];
  reopened.save();
  assert.deepEqual(await reopened.sendPending(chain, payer()), { outcome: 'sent', txid });
  assert.equal(chain.sent.length, 1);
  assert.equal(reopened.state.sequence, 1);
});

test('a payment relayed by someone else is still recognised as sent', async () => {
  // Our broadcast never lands, but a third party resubmits the signed
  // instruction in their own transaction. The vault's record settles it.
  const chain = fakeChain();
  const w = await funded(chain);
  const to = Keypair.generate().publicKey;
  w.commit(await w.planSol(chain, to.toBase58(), '1'));
  chain.dropNextSend = true;
  chain.failNextSend = new Error('dropped');
  assert.equal((await w.sendPending(chain, payer())).outcome, 'pending');

  const ours = Transaction.from(chain.sent[0]);
  const relayer = Keypair.generate();
  const relayed = new Transaction({ feePayer: relayer.publicKey, blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1 }).add(ours.instructions.at(-1));
  relayed.sign(relayer);
  await chain.sendRawTransaction(relayed.serialize());

  assert.deepEqual(await w.sendPending(chain, payer()), { outcome: 'sent', txid: null });
  assert.equal(await chain.getBalance(to), 1_000_000_000);
  assert.equal(chain.sent.length, 2); // we did not sign or send again
});

test('if another copy of the wallet used the key first, the payment is reported as NOT sent', async () => {
  const chain = fakeChain();
  const a = await funded(chain, 5n);
  const b = newWallet(a.masterSeed); // same seed in a different wallet file, e.g. a second machine

  const mine = Keypair.generate().publicKey;
  b.commit(await b.planSol(chain, mine.toBase58(), '2')); // B is about to pay with key #0...
  a.commit(await a.planSol(chain, someone(), '1'));
  assert.equal((await a.sendPending(chain, payer())).outcome, 'sent'); // ...but A gets there first

  const sentBefore = chain.sent.length;
  assert.deepEqual(await b.sendPending(chain, payer()), { outcome: 'superseded', txid: null });
  assert.equal(chain.sent.length, sentBefore); // B never signed with the used key
  assert.equal(await chain.getBalance(mine), 0);
  assert.equal(b.pending, null);

  // B is free to pay again, with the next key.
  const retry = await b.planSol(chain, mine.toBase58(), '2');
  assert.equal(retry.index, 1);
  b.commit(retry);
  assert.equal((await b.sendPending(chain, payer())).outcome, 'sent');
  assert.equal(await chain.getBalance(mine), 2_000_000_000);
});

test('a stale RPC node cannot trick the wallet into reusing a key', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const live = chain.accounts.get(w.address.toBase58());
  const before = { [w.address.toBase58()]: { ...live, data: Buffer.from(live.data) } };
  w.commit(await w.planSol(chain, someone(), '1'));
  await w.sendPending(chain, payer());
  assert.equal(w.state.sequence, 1);

  chain.stale = before; // node now serves the vault as it was before the payment
  await assert.rejects(w.planSol(chain, someone(), '0.5'), /out of date/);
  await assert.rejects(w.sync(chain), /out of date/);
  assert.equal(chain.sent.length, 1);
});

test('a second device (or a restore from seed) catches up from the chain', async () => {
  const chain = fakeChain();
  const a = await funded(chain, 5n);
  for (let i = 0; i < 3; i++) {
    a.commit(await a.planSol(chain, someone(), '1'));
    await a.sendPending(chain, payer());
  }
  const b = newWallet(a.masterSeed);
  assert.equal(b.address.toBase58(), a.address.toBase58());
  assert.equal(b.state.sequence, 0);
  const plan = await b.planSol(chain, someone(), '1');
  assert.equal(plan.index, 3);
  b.commit(plan);
  assert.equal((await b.sendPending(chain, payer())).outcome, 'sent');

  // Device A had no idea; it catches up too instead of signing with key #3 again.
  assert.equal((await a.planSol(chain, someone(), '0.5')).index, 4);
});

test("a vault whose current key is not from this seed is refused", async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  randomBytes(32).copy(chain.accounts.get(w.address.toBase58()).data, 34);
  await assert.rejects(w.planSol(chain, someone(), '1'), /does not come from this wallet/);
});

test('SOL planning refuses payments that would fail on-chain', async () => {
  const chain = fakeChain();
  const w = await funded(chain, 1n);
  const to = someone();
  await assert.rejects(w.planSol(chain, to, '2'), /cannot send/);
  await assert.rejects(w.planSol(chain, to, '0'), /greater than zero/);
  await assert.rejects(w.planSol(chain, w.address.toBase58(), '0.5'), /vault itself/);
  await assert.rejects(w.planSol(chain, to, '0.0001'), /needs at least/); // new account below rent minimum
  await assert.rejects(w.planSol(chain, 'not-an-address', '0.5'));
  await assert.rejects(w.planSol(chain, chain.mint().toBase58(), '0.5'), /not an ordinary wallet/);

  const existing = Keypair.generate().publicKey;
  chain.fund(existing, 5_000_000n);
  assert.equal((await w.planSol(chain, existing.toBase58(), '0.0001')).amount, 100_000n);
  const all = await w.planSol(chain, to, 'all');
  assert.equal(all.amount, 1_000_000_000n);
  assert.equal(all.left, 0n);
  assert.equal(w.pending, null);

  const empty = newWallet();
  await empty.open(chain, payer());
  await assert.rejects(empty.planSol(chain, to, 'all'), /no SOL to spend/);
});

// ------------------------------------------------------------------ tokens

for (const [label, tokenProgram] of [['SPL Token', TOKEN_PROGRAM_ID], ['Token-2022', TOKEN_2022_PROGRAM_ID]]) {
  test(`${label}: receive, list, pay a new recipient, pay the rest`, async () => {
    const chain = fakeChain();
    const w = await funded(chain);
    const mint = chain.mint(tokenProgram, 6);

    assert.deepEqual(await w.holdings(chain), []);
    await assert.rejects(w.planToken(chain, mint.toBase58(), someone(), '1'), /holds none/);
    const opened = await w.openTokenAccount(chain, payer(), mint.toBase58());
    assert.equal(opened.created, true);
    assert.equal(opened.account.toBase58(), w.tokenAccount(mint, tokenProgram).toBase58());
    assert.equal((await w.openTokenAccount(chain, payer(), mint.toBase58())).created, false);
    await assert.rejects(w.planToken(chain, mint.toBase58(), someone(), '1'), /holds none/);

    const source = chain.tokens(mint, w.address, 1000_000000n);
    assert.deepEqual(await w.holdings(chain), [
      { mint: mint.toBase58(), account: source.toBase58(), amount: 1000_000000n, decimals: 6, frozen: false },
    ]);

    const friend = Keypair.generate().publicKey;
    const friendAccount = getAssociatedTokenAddressSync(mint, friend, true, tokenProgram);
    const plan = await w.planToken(chain, mint.toBase58(), friend.toBase58(), '250.5');
    assert.equal(plan.amount, 250_500000n);
    assert.equal(plan.left, 749_500000n);
    assert.equal(plan.destination.toBase58(), friendAccount.toBase58());
    assert.equal(plan.createAccount, true);
    w.commit(plan);
    assert.equal((await w.sendPending(chain, payer())).outcome, 'sent');
    assert.equal(chain.balanceOf(friendAccount), 250_500000n);
    assert.equal(chain.balanceOf(source), 749_500000n);

    // The recipient can also be given as their token account; nothing to create this time.
    const rest = await w.planToken(chain, mint.toBase58(), friendAccount.toBase58(), 'all');
    assert.equal(rest.createAccount, false);
    assert.equal(rest.destination.toBase58(), friendAccount.toBase58());
    w.commit(rest);
    assert.equal((await w.sendPending(chain, payer())).outcome, 'sent');
    assert.equal(chain.balanceOf(friendAccount), 1000_000000n);
    assert.equal(w.state.sequence, 2);
    assert.deepEqual(w.state.history.map((h) => [h.asset, h.amount, h.outcome]), [
      [mint.toBase58(), '250500000', 'sent'],
      [mint.toBase58(), '749500000', 'sent'],
    ]);
  });
}

test('token planning refuses payments that would fail or go astray', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const mint = chain.mint();
  const source = chain.tokens(mint, w.address, 100_000000n);
  const m = mint.toBase58();
  const to = someone();

  await assert.rejects(w.planToken(chain, m, to, '101'), /cannot send/);
  await assert.rejects(w.planToken(chain, m, to, '0'), /greater than zero/);
  await assert.rejects(w.planToken(chain, m, to, '1.0000001'), /decimal places/);
  await assert.rejects(w.planToken(chain, someone(), to, '1'), /no token mint/);
  await assert.rejects(w.planToken(chain, to, to, '1'), /no token mint/);
  await assert.rejects(w.planToken(chain, w.address.toBase58(), to, '1'), /not a token mint/);
  await assert.rejects(w.planToken(chain, m, w.address.toBase58(), '1'), /vault itself/);
  await assert.rejects(w.planToken(chain, m, source.toBase58(), '1'), /vault itself/);
  // A mint address pasted where the recipient goes.
  await assert.rejects(w.planToken(chain, m, m, '1'), /not a wallet/);
  // A token account for some other token.
  const otherMint = chain.mint();
  const wrong = chain.tokens(otherMint, Keypair.generate().publicKey, 0n);
  await assert.rejects(w.planToken(chain, m, wrong.toBase58(), '1'), /different token/);

  // Frozen on either side.
  const friend = Keypair.generate().publicKey;
  const friendAccount = chain.tokens(mint, friend, 0n, { frozen: true });
  await assert.rejects(w.planToken(chain, m, friend.toBase58(), '1'), /recipient's token account is frozen/);
  await assert.rejects(w.planToken(chain, m, friendAccount.toBase58(), '1'), /recipient's token account is frozen/);
  chain.freeze(friendAccount, false);
  chain.freeze(source);
  await assert.rejects(w.planToken(chain, m, friend.toBase58(), '1'), /frozen by the token's issuer/);
  assert.equal((await w.holdings(chain))[0].frozen, true);
  assert.equal(w.pending, null);
});

test('Token-2022 mints the vault cannot send are refused before signing', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  // Mint data = 82-byte mint, padding to 165, account type 1, then TLV extensions.
  const withExtension = (type, value) => {
    const mint = chain.mint(TOKEN_2022_PROGRAM_ID);
    const base = chain.accounts.get(mint.toBase58());
    const tlv = Buffer.alloc(4 + value.length);
    tlv.writeUInt16LE(type, 0);
    tlv.writeUInt16LE(value.length, 2);
    value.copy(tlv, 4);
    base.data = Buffer.concat([base.data, Buffer.alloc(165 - 82), Buffer.from([1]), tlv]);
    chain.tokens(mint, w.address, 5_000000n);
    return mint.toBase58();
  };
  const hookProgram = Keypair.generate().publicKey;
  const hooked = withExtension(14, Buffer.concat([Buffer.alloc(32), hookProgram.toBuffer()])); // TransferHook
  await assert.rejects(w.planToken(chain, hooked, someone(), '1'), /transfer hook/);
  const soulbound = withExtension(9, Buffer.alloc(0)); // NonTransferable
  await assert.rejects(w.planToken(chain, soulbound, someone(), '1'), /non-transferable/);
  const paused = withExtension(26, Buffer.concat([Buffer.alloc(32), Buffer.from([1])])); // PausableConfig, paused
  await assert.rejects(w.planToken(chain, paused, someone(), '1'), /paused/);
  // A hook extension with no program set is harmless.
  const inert = withExtension(14, Buffer.alloc(64));
  assert.equal((await w.planToken(chain, inert, someone(), '1')).amount, 1_000000n);
});

// ------------------------------------------------------------------ cancel

test('cancelling before anything was broadcast just drops the lock and keeps the key', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  w.commit(await w.planSol(chain, someone(), '1'));
  assert.deepEqual(await w.cancelPending(chain, payer()), { outcome: 'cancelled', txid: null });
  assert.equal(chain.sent.length, 0);
  assert.equal(w.pending, null);
  assert.equal(w.state.sequence, 0);
  // Key #0 was never used, so it signs the next payment.
  const plan = await w.planSol(chain, someone(), '0.5');
  assert.equal(plan.index, 0);
  w.commit(plan);
  assert.equal((await w.sendPending(chain, payer())).outcome, 'sent');
});

test('a payment stuck on a frozen token account is cancelled on-chain, and the vault carries on', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const mint = chain.mint(TOKEN_2022_PROGRAM_ID);
  const source = chain.tokens(mint, w.address, 100_000000n);
  const friend = Keypair.generate().publicKey;
  w.commit(await w.planToken(chain, mint.toBase58(), friend.toBase58(), '40'));
  chain.freeze(source); // the issuer freezes the vault's account after the lock

  const stuck = await w.sendPending(chain, payer());
  assert.equal(stuck.outcome, 'pending');
  assert.equal(w.state.sequence, 0);
  await assert.rejects(w.planSol(chain, someone(), '0.1'), /already pending/); // SOL is locked too

  const cancelled = await w.cancelPending(chain, payer());
  assert.equal(cancelled.outcome, 'cancelled');
  assert(chain.landed.has(cancelled.txid));
  assert.equal(w.state.sequence, 1);
  assert.equal(chain.balanceOf(source), 100_000000n);
  assert.equal(decodeState(chain.accounts.get(w.address.toBase58()).data).outcome, 2);

  // SOL moves again straight away; tokens once thawed.
  w.commit(await w.planSol(chain, someone(), '0.5'));
  assert.equal((await w.sendPending(chain, payer())).outcome, 'sent');
  chain.freeze(source, false);
  w.commit(await w.planToken(chain, mint.toBase58(), friend.toBase58(), '40'));
  assert.equal((await w.sendPending(chain, payer())).outcome, 'sent');
  assert.deepEqual(w.state.history.map((h) => h.outcome), ['cancelled', 'sent', 'sent']);
});

test('if the payment lands before the cancel does, it is reported as sent', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const to = Keypair.generate().publicKey;
  w.commit(await w.planSol(chain, to.toBase58(), '1'));
  chain.dropNextSend = true;
  chain.failNextSend = new Error('dropped');
  await w.sendPending(chain, payer());
  // The dropped transaction turns up after all, just before the user cancels.
  await chain.sendRawTransaction(chain.sent[0]);

  const result = await w.cancelPending(chain, payer());
  assert.equal(result.outcome, 'sent');
  assert.equal(await chain.getBalance(to), 1_000_000_000);
  assert.equal(chain.sent.length, 2); // no cancel was signed or sent
});

// --------------------------------------------------- fee wallets and tabs

test('a fee wallet that refuses to sign has still seen the signature, so the payment stays locked', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const to = Keypair.generate().publicKey;
  w.commit(await w.planSol(chain, to.toBase58(), '1'));
  assert.equal(w.pending.exposed, false);

  const refusing = { publicKey: Keypair.generate().publicKey, signTransaction: async () => { throw new Error('User rejected the request.'); } };
  const result = await w.sendPending(chain, refusing);
  assert.equal(result.outcome, 'pending');
  assert.match(result.error.message, /rejected/);
  assert.equal(chain.sent.length, 0);
  assert.equal(reopen(w).pending.exposed, true); // recorded on disk before the fee wallet was asked

  // So calling it off takes a real on-chain cancel, not just dropping the lock.
  const cancelled = await w.cancelPending(chain, payer());
  assert.equal(cancelled.outcome, 'cancelled');
  assert(chain.landed.has(cancelled.txid));
  assert.equal(w.state.sequence, 1);
  assert.equal(await chain.getBalance(to), 0);
});

test('a fee wallet may add to the transaction but not change the vault instruction', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const to = Keypair.generate().publicKey;
  w.commit(await w.planSol(chain, to.toBase58(), '1'));

  const kp = Keypair.generate();
  const tampering = {
    publicKey: kp.publicKey,
    signTransaction: async (tx) => {
      const ix = tx.instructions.at(-1);
      ix.data = Buffer.from(ix.data);
      ix.data[5] ^= 1; // nudge the amount
      tx.partialSign(kp);
      return tx;
    },
  };
  const bad = await w.sendPending(chain, tampering);
  assert.equal(bad.outcome, 'pending');
  assert.match(bad.error.message, /different transaction/);
  assert.equal(chain.sent.length, 0);

  // One that prepends its own instruction, as some wallets do, is fine.
  const adding = {
    publicKey: kp.publicKey,
    signTransaction: async (tx) => {
      tx.instructions.unshift(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: 0 }));
      tx.partialSign(kp);
      return tx;
    },
  };
  assert.equal((await w.sendPending(chain, adding)).outcome, 'sent');
  assert.equal(await chain.getBalance(to), 1_000_000_000);
});

test('two copies sharing one store (two browser tabs) cannot both lock the same key', async () => {
  const chain = fakeChain();
  const a = await funded(chain);
  const b = reopen(a); // same file, loaded separately
  const planA = await a.planSol(chain, someone(), '0.5');
  const planB = await b.planSol(chain, someone(), '0.7');
  a.commit(planA);
  assert.throws(() => b.commit(planB), /already pending/);
  await assert.rejects(b.planSol(chain, someone(), '0.1'), /already pending/);

  // B can finish A's payment, and both then agree on where the vault is.
  assert.equal((await b.sendPending(chain, payer())).outcome, 'sent');
  assert.equal((await a.planSol(chain, someone(), '0.1')).index, 1);
  assert.equal(chain.sent.length, 1);
});

test('a fee wallet that cannot afford the payment is caught before the key is locked', async () => {
  const chain = fakeChain();
  const w = await funded(chain);
  const fee = Keypair.generate().publicKey;
  const sol = await w.planSol(chain, someone(), '1');
  await assert.rejects(w.requireFeeFunds(chain, fee, sol), /fee wallet needs at least 0.00001 SOL .* has 0/);
  chain.fund(fee, 10_000n);
  await w.requireFeeFunds(chain, fee, sol);

  // Creating the recipient's token account needs rent as well.
  const mint = chain.mint();
  chain.tokens(mint, w.address, 5_000000n);
  const token = await w.planToken(chain, mint.toBase58(), someone(), '1');
  assert.equal(token.createAccount, true);
  await assert.rejects(w.requireFeeFunds(chain, fee, token), /needs at least 0.00221 SOL/);
  chain.fund(fee, 2_200_000n);
  await w.requireFeeFunds(chain, fee, token);
  assert.equal(w.pending, null);
});

// ------------------------------------------------------- program checks

test('a program that can still be upgraded is refused', async () => {
  const chain = fakeChain();
  const loader = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
  const deploy = (authority) => {
    const program = Keypair.generate().publicKey;
    const programData = Keypair.generate().publicKey;
    const head = Buffer.alloc(36);
    head.writeUInt32LE(2, 0);
    programData.toBuffer().copy(head, 4);
    chain.accounts.set(program.toBase58(), { lamports: 1n, owner: loader, data: head, executable: true });
    const data = Buffer.alloc(45 + 100);
    data.writeUInt32LE(3, 0);
    if (authority) {
      data[12] = 1;
      authority.toBuffer().copy(data, 13);
    }
    chain.accounts.set(programData.toBase58(), { lamports: 1n, owner: loader, data, executable: false });
    return program;
  };

  await requireImmutableProgram(chain, deploy(null)); // final: fine
  const authority = Keypair.generate().publicKey;
  await assert.rejects(requireImmutableProgram(chain, deploy(authority)), new RegExp(`can still be changed by whoever holds ${authority.toBase58()}`));
  await assert.rejects(requireImmutableProgram(chain, Keypair.generate().publicKey), /no program at/);
  const wallet = Keypair.generate().publicKey;
  chain.fund(wallet, 5n);
  await assert.rejects(requireImmutableProgram(chain, wallet), /is not a program/);
  // An old-style loader has no upgrade mechanism at all.
  const old = Keypair.generate().publicKey;
  chain.accounts.set(old.toBase58(), { lamports: 1n, owner: new PublicKey('BPFLoader2111111111111111111111111111111111'), data: Buffer.alloc(8), executable: true });
  await requireImmutableProgram(chain, old);
  const odd = Keypair.generate().publicKey;
  chain.accounts.set(odd.toBase58(), { lamports: 1n, owner: Keypair.generate().publicKey, data: Buffer.alloc(8), executable: true });
  await assert.rejects(requireImmutableProgram(chain, odd), /cannot check/);
});

test('errors are turned into one readable line', () => {
  assert.equal(explainError({ message: 'x', logs: ['Program log: Instruction: TransferChecked', 'Program log: Error: Account is frozen'] }), 'Account is frozen');
  assert.match(explainError({ message: 'Simulation failed. ', transactionError: { message: 'Attempt to debit an account but found no record of a prior credit.' } }), /fee wallet does not have enough SOL/);
  assert.match(explainError(new TypeError('Failed to fetch')), /Could not reach the Solana network/);
  assert.match(explainError(Object.assign(new Error('User rejected the request.'), { code: 4001 })), /declined/);
  assert.equal(explainError(new Error('first line\nsecond line')), 'first line');
  assert.equal(explainError(new Error('y'.repeat(500))).length, 301);
});
