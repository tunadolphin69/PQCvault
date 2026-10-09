// End-to-end test against a real validator.
//
//   ./scripts/localnet.sh            (terminal 1, from the repo root)
//   npm run e2e                      (terminal 2, from client/)
//
// Env: QPV_URL (default http://127.0.0.1:8899), QPV_PROGRAM (program id).
//
// This file signs several different messages with the same key on purpose,
// to prove the program rejects everything except the real thing. That is
// only acceptable in a test. The wallet (src/wallet.js) never does it.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  createMint,
  freezeAccount,
  getAccount,
  getAssociatedTokenAddressSync,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  thawAccount,
} from '@solana/spl-token';
import {
  MAX_COMPUTE_UNITS,
  MAX_TX_BYTES,
  OUTCOME_CANCELLED,
  OUTCOME_PAID,
  SOL_ASSET,
  STATE_LEN,
  buildTransaction,
  cancelInstruction,
  computeLimit,
  decodeState,
  deriveVaultKey,
  openInstruction,
  signMessage,
  spendSolInstruction,
  spendTokenInstruction,
  vaultAddress,
} from '../src/vault.js';
import { CHAINS, CHAIN_STEPS, N, walkChain } from '../src/wots.js';

const url = process.env.QPV_URL ?? 'http://127.0.0.1:8899';
if (!process.env.QPV_PROGRAM) throw new Error('set QPV_PROGRAM to the deployed program id');
const programId = new PublicKey(process.env.QPV_PROGRAM);
const conn = new Connection(url, 'confirmed');

const SOL = BigInt(LAMPORTS_PER_SOL);
const FEE = 5000n; // one ed25519 signature (the fee payer)
const ERR = { BadSignature: 0, SelfTransfer: 1, KeyReuse: 2, UnknownTokenProgram: 3, BadMint: 4 };

const payer = Keypair.generate();
const balance = async (pk) => BigInt(await conn.getBalance(pk));
const state = async (pk) => decodeState((await conn.getAccountInfo(pk))?.data);
const fresh = () => Keypair.generate().publicKey;

/** A vault identity: master seed, keys on demand, permanent address. */
function newVault() {
  const master = randomBytes(32);
  const key = (i) => deriveVaultKey(master, i);
  return { key, address: vaultAddress(programId, key(0).keyHash) };
}

let passed = 0;
const ok = (name) => {
  passed++;
  console.log(`  ok  ${name}`);
};

async function airdrop(pk, sol) {
  const sig = await conn.requestAirdrop(pk, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction({ signature: sig, ...(await conn.getLatestBlockhash()) });
}

async function deposit(to, lamports) {
  const tx = new Transaction().add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: to, lamports }));
  await sendAndConfirmTransaction(conn, tx, [payer]);
}

/** Send a transaction, wait, and return what happened. Never throws on program errors. */
async function run(tx, signers) {
  const bh = await conn.getLatestBlockhash();
  tx.feePayer = signers[0].publicKey;
  tx.recentBlockhash = bh.blockhash;
  tx.sign(...signers);
  const raw = tx.serialize();
  const signature = await conn.sendRawTransaction(raw, { skipPreflight: true });
  await conn.confirmTransaction({ signature, ...bh });
  let info = null;
  for (let i = 0; i < 50 && !info; i++) {
    info = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0 });
    if (!info) await new Promise((r) => setTimeout(r, 100));
  }
  assert(info, 'transaction not found');
  // The innermost program to fail logs first.
  const failure = info.meta.logMessages.find((l) => / failed: /.test(l)) ?? '';
  return {
    err: info.meta.err,
    units: info.meta.computeUnitsConsumed,
    bytes: raw.length,
    // Which program raised the error (the vault itself, or one it called).
    failedIn: failure.split(' ')[1],
  };
}

const open = (v, firstKeyHash = v.key(0).keyHash, address = v.address) =>
  run(new Transaction().add(openInstruction({ programId, payer: payer.publicKey, vault: address, firstKeyHash })), [payer]);

/** Send vault instructions under a compute budget. */
const submit = (instructions, units, feePayer = payer, extra = {}) =>
  run(buildTransaction({ instructions: [instructions].flat(), units, feePayer: feePayer.publicKey, ...extra }), [feePayer]);

/** Sign message number `seq` of vault `v` the way the wallet would. */
const signed = (v, seq, asset, destination, amount, over = {}) =>
  signMessage({
    programId,
    vault: v.address,
    sequence: BigInt(seq),
    key: v.key(seq),
    nextKeyHash: v.key(seq + 1).keyHash,
    asset,
    destination,
    amount,
    ...over,
  });

const payIx = (v, s, recipient) => spendSolInstruction({ programId, vault: v.address, recipient, signed: s });

const errorOf = (res) => {
  const e = res.err?.InstructionError?.[1];
  return e && typeof e === 'object' ? e.Custom : e;
};

/**
 * Assert a transaction was rejected by the vault program with `expect`, and
 * that nothing about the vault changed.
 */
async function rejected(name, v, send, expect, watch = async () => null) {
  const before = [await balance(v.address), await state(v.address), await watch()];
  const res = await send();
  assert(res.err, `${name}: transaction unexpectedly succeeded`);
  assert.equal(errorOf(res), expect, `${name}: ${JSON.stringify(res.err)}`);
  assert.equal(res.failedIn, programId.toBase58(), `${name}: failed in ${res.failedIn}`);
  assert.deepEqual([await balance(v.address), await state(v.address), await watch()], before, `${name}: vault changed`);
  ok(name);
}
// Full compute budget for rejections, so the only thing that can fail is the program's own check.
const max = (ix) => () => submit(ix, MAX_COMPUTE_UNITS);

console.log(`program ${programId.toBase58()} on ${url}`);
await airdrop(payer.publicKey, 100);
const reserve = BigInt(await conn.getMinimumBalanceForRentExemption(STATE_LEN));

// ------------------------------------------------------------------ open
console.log('\nopening');
const v = newVault();
{
  const stranger = newVault();
  await rejected('spend from an address that was never opened', v, max(payIx(v, signed(v, 0, SOL_ASSET, fresh(), 1n), fresh())), 'IllegalOwner');
  await rejected('open with a key that does not match the address', v, () => open(v, stranger.key(0).keyHash), 'InvalidSeeds');

  const before = await balance(payer.publicKey);
  const res = await open(v);
  assert.equal(res.err, null, JSON.stringify(res));
  assert.equal(await balance(v.address), reserve);
  assert.equal(before - (await balance(payer.publicKey)), reserve + FEE);
  const s = await state(v.address);
  assert.deepEqual(s.keyHash, v.key(0).keyHash);
  assert.deepEqual(s.firstKeyHash, v.key(0).keyHash);
  assert.equal(s.sequence, 0n);
  assert.equal(s.outcome, 0);
  assert((await conn.getAccountInfo(v.address)).owner.equals(programId));
  ok(`open creates the vault with key #0 and the rent reserve (${res.units} CU)`);

  await rejected('opening twice', v, () => open(v), 'AccountAlreadyInitialized');
}
{
  // SOL sent before the vault is opened is kept, and counts toward the reserve.
  const early = newVault();
  await deposit(early.address, SOL);
  const before = await balance(payer.publicKey);
  assert.equal((await open(early)).err, null);
  assert.equal(await balance(early.address), SOL);
  assert.equal(before - (await balance(payer.publicKey)), FEE);
  ok('SOL sent before opening is kept');
}
{
  const w = newVault();
  const bad = openInstruction({ programId, payer: payer.publicKey, vault: w.address, firstKeyHash: w.key(0).keyHash });
  bad.keys[2].pubkey = fresh();
  await rejected('open with a fake system program', w, () => run(new Transaction().add(bad), [payer]), 'IncorrectProgramId');
  const short = openInstruction({ programId, payer: payer.publicKey, vault: w.address, firstKeyHash: w.key(0).keyHash });
  short.data = short.data.subarray(0, 32);
  await rejected('open with short data', w, () => run(new Transaction().add(short), [payer]), 'InvalidInstructionData');
}

// ------------------------------------------------------ SOL: rejections
console.log('\nSOL payments: rejections (the vault holds 2 SOL and key #0 throughout)');
await deposit(v.address, 2n * SOL);
const alice = fresh();
const mallory = fresh();
const amount = SOL / 2n;
const good = signed(v, 0, SOL_ASSET, alice, amount);
const tamper = (over) => ({ ...good, ...over });

await rejected('recipient swapped for an attacker', v, max(payIx(v, good, mallory)), ERR.BadSignature);
await rejected('amount raised', v, max(payIx(v, tamper({ amount: amount + 1n }), alice)), ERR.BadSignature);
await rejected('amount lowered', v, max(payIx(v, tamper({ amount: amount - 1n }), alice)), ERR.BadSignature);
await rejected("next key swapped for an attacker's", v, max(payIx(v, tamper({ nextKeyHash: newVault().key(0).keyHash }), alice)), ERR.BadSignature);
await rejected('cancel commitment swapped', v, max(payIx(v, tamper({ cancelHash: randomBytes(32) }), alice)), ERR.BadSignature);
for (const at of [0, 311, 623]) {
  const bad = Buffer.from(good.signature);
  bad[at] ^= 1;
  await rejected(`one bit flipped in signature byte ${at}`, v, max(payIx(v, tamper({ signature: bad }), alice)), ERR.BadSignature);
}
{
  const bad = Buffer.from(good.pubSeed);
  bad[0] ^= 1;
  await rejected('public seed altered', v, max(payIx(v, tamper({ pubSeed: bad }), alice)), ERR.BadSignature);
}
{
  // Walking a chain forward is the one thing a forger can do for free.
  const bad = Buffer.from(good.signature);
  walkChain(good.pubSeed, 3, bad.subarray(3 * N, 4 * N), good.digits[3], good.digits[3] + 1).copy(bad, 3 * N);
  await rejected('message chain walked one step forward', v, max(payIx(v, tamper({ signature: bad }), alice)), ERR.BadSignature);
}
await rejected('all-zero signature', v, max(payIx(v, tamper({ signature: Buffer.alloc(good.signature.length) }), alice)), ERR.BadSignature);
{
  // Valid signatures, wrong context.
  const other = newVault();
  assert.equal((await open(other)).err, null);
  await rejected("another vault's key and signature", v, max(payIx(v, signed(other, 0, SOL_ASSET, mallory, amount), mallory)), ERR.BadSignature);
  await rejected('right key, signed for a different vault address', v, max(payIx(v, signed(v, 0, SOL_ASSET, alice, amount, { vault: other.address }), alice)), ERR.BadSignature);
  await rejected('right key, signed for a different sequence number', v, max(payIx(v, signed(v, 0, SOL_ASSET, alice, amount, { sequence: 1n }), alice)), ERR.BadSignature);
  await rejected('a later key used early', v, max(payIx(v, signed(v, 0, SOL_ASSET, alice, amount, { key: v.key(1), nextKeyHash: v.key(2).keyHash }), alice)), ERR.BadSignature);
  await rejected('a token payment signature used to move SOL', v, max(payIx(v, signed(v, 0, fresh(), alice, amount), alice)), ERR.BadSignature);
}
await rejected('recipient is the vault itself', v, max(payIx(v, signed(v, 0, SOL_ASSET, v.address, amount), v.address)), ERR.SelfTransfer);
await rejected('next key equal to the current key', v, max(payIx(v, signed(v, 0, SOL_ASSET, alice, amount, { nextKeyHash: v.key(0).keyHash }), alice)), ERR.KeyReuse);
{
  const short = payIx(v, good, alice);
  short.data = short.data.subarray(0, short.data.length - 1);
  await rejected('instruction data one byte short', v, max(short), 'InvalidInstructionData');
  const long = payIx(v, good, alice);
  long.data = Buffer.concat([long.data, Buffer.from([0])]);
  await rejected('instruction data one byte long', v, max(long), 'InvalidInstructionData');
  const tag = payIx(v, good, alice);
  tag.data = Buffer.from(tag.data);
  tag.data[0] = 9;
  await rejected('unknown instruction tag', v, max(tag), 'InvalidInstructionData');
}
await rejected('validly signed, but for more than the vault holds', v, max(payIx(v, signed(v, 0, SOL_ASSET, alice, 3n * SOL), alice)), 'InsufficientFunds');
await rejected('validly signed, but dipping one lamport into the rent reserve', v, max(payIx(v, signed(v, 0, SOL_ASSET, alice, 2n * SOL + 1n), alice)), 'InsufficientFunds');
{
  // An account the attacker creates and hands to the program is not a vault.
  const fake = Keypair.generate();
  await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      SystemProgram.createAccount({ fromPubkey: payer.publicKey, newAccountPubkey: fake.publicKey, lamports: Number(SOL), space: STATE_LEN, programId }),
    ),
    [payer, fake],
  );
  const ix = payIx(v, good, alice);
  ix.keys[0].pubkey = fake.publicKey;
  const res = await submit(ix, MAX_COMPUTE_UNITS);
  assert.equal(errorOf(res), 'UninitializedAccount');
  assert.equal(await balance(fake.publicKey), SOL);
  ok('an attacker-made account owned by the program is not treated as a vault');
}

// ---------------------------------------------------------- SOL: spends
console.log('\nSOL payments');
{
  // Relayed by a stranger's fee payer: exactly the signed outcome happens.
  const stranger = Keypair.generate();
  await airdrop(stranger.publicKey, 1);
  const strangerBefore = await balance(stranger.publicKey);
  const res = await submit(payIx(v, good, alice), computeLimit(good.hashes), stranger);
  assert.equal(res.err, null, JSON.stringify(res));
  assert.equal(await balance(alice), amount);
  assert.equal(await balance(v.address), reserve + 2n * SOL - amount);
  assert.equal(strangerBefore - (await balance(stranger.publicKey)), FEE);
  const s = await state(v.address);
  assert.deepEqual(s.keyHash, v.key(1).keyHash);
  assert.deepEqual(s.firstKeyHash, v.key(0).keyHash);
  assert.equal(s.sequence, 1n);
  assert.equal(s.outcome, OUTCOME_PAID);
  assert.deepEqual(s.lastMessage, good.digest);
  assert(res.bytes <= MAX_TX_BYTES);
  ok(`0.5 SOL paid, key rotated to #1, outcome recorded (${res.bytes} bytes, ${res.units} CU, ${good.hashes} hashes)`);

  // The replay names key #1 as "next", which is now the current key, so it
  // trips the reuse check even before the (now useless) signature is looked at.
  await rejected('replaying the same transaction', v, max(payIx(v, good, alice)), ERR.KeyReuse);
  await rejected('a new message signed with the retired key #0', v, max(payIx(v, signed(v, 1, SOL_ASSET, mallory, SOL, { key: v.key(0) }), mallory)), ERR.BadSignature);
  await rejected('cancelling a payment that already went through', v, max(cancelInstruction({ programId, vault: v.address, asset: SOL_ASSET, destination: alice, signed: good })), ERR.KeyReuse);
  assert.equal(await balance(alice), amount);
}
{
  // A deposit that arrives between signing and landing changes nothing.
  const bob = fresh();
  const s = signed(v, 1, SOL_ASSET, bob, SOL / 4n);
  await deposit(v.address, SOL);
  assert.equal((await submit(payIx(v, s, bob), computeLimit(s.hashes))).err, null);
  assert.equal(await balance(bob), SOL / 4n);
  assert.equal((await state(v.address)).sequence, 2n);
  ok('second payment uses key #1; a late deposit simply stays in the vault');
}
{
  // Send everything spendable: exactly the reserve stays, and the vault lives on.
  const carol = fresh();
  const spendable = (await balance(v.address)) - reserve;
  const s = signed(v, 2, SOL_ASSET, carol, spendable);
  assert.equal((await submit(payIx(v, s, carol), computeLimit(s.hashes))).err, null);
  assert.equal(await balance(carol), spendable);
  assert.equal(await balance(v.address), reserve);
  assert.equal((await state(v.address)).sequence, 3n);
  await rejected('spending from a vault that holds only its reserve', v, max(payIx(v, signed(v, 3, SOL_ASSET, carol, 1n), carol)), 'InsufficientFunds');
  ok('send-all leaves exactly the reserve; same address keeps working');

  await deposit(v.address, SOL);
  const s2 = signed(v, 3, SOL_ASSET, carol, SOL);
  assert.equal((await submit(payIx(v, s2, carol), computeLimit(s2.hashes))).err, null);
  assert.equal(await balance(carol), spendable + SOL);
  ok('the same address accepts and spends a fresh deposit');
}

// --------------------------------------------------------------- cancel
console.log('\ncancelling a signed payment');
{
  const c = newVault();
  assert.equal((await open(c)).err, null);
  await deposit(c.address, SOL);
  const dave = fresh();
  const pay = signed(c, 0, SOL_ASSET, dave, SOL / 2n);
  const cancelIx = (s, over = {}) => cancelInstruction({ programId, vault: c.address, asset: SOL_ASSET, destination: dave, signed: s, ...over });

  await rejected('cancel with the wrong secret', c, max(cancelIx({ ...pay, cancelSecret: randomBytes(32) })), ERR.BadSignature);
  await rejected("cancel using only what the payment made public (the commitment, not the secret)", c, max(cancelIx({ ...pay, cancelSecret: pay.cancelHash })), ERR.BadSignature);
  await rejected('cancel with a different amount than was signed', c, max(cancelIx({ ...pay, amount: 1n })), ERR.BadSignature);
  await rejected('cancel with a different destination than was signed', c, max(cancelIx(pay, { destination: mallory })), ERR.BadSignature);
  await rejected("cancel steering the vault to an attacker's next key", c, max(cancelIx({ ...pay, nextKeyHash: newVault().key(0).keyHash })), ERR.BadSignature);

  const res = await submit(cancelIx(pay), computeLimit(pay.hashes));
  assert.equal(res.err, null, JSON.stringify(res));
  const s = await state(c.address);
  assert.deepEqual(s.keyHash, c.key(1).keyHash);
  assert.equal(s.sequence, 1n);
  assert.equal(s.outcome, OUTCOME_CANCELLED);
  assert.deepEqual(s.lastMessage, pay.digest);
  assert.equal(await balance(dave), 0n);
  assert.equal(await balance(c.address), reserve + SOL);
  ok(`cancel retires the key without paying (${res.bytes} bytes, ${res.units} CU)`);

  await rejected('the cancelled payment can no longer be sent', c, max(payIx(c, pay, dave)), ERR.KeyReuse);
  const next = signed(c, 1, SOL_ASSET, dave, SOL / 2n);
  assert.equal((await submit(payIx(c, next, dave), computeLimit(next.hashes))).err, null);
  assert.equal(await balance(dave), SOL / 2n);
  ok('after a cancel the next key pays normally');
}

// --------------------------------------------------------------- tokens
for (const [label, tokenProgram, otherProgram] of [
  ['SPL Token', TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID],
  ['Token-2022', TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID],
]) {
  console.log(`\ntokens (${label})`);
  const opts = [undefined, { commitment: 'confirmed' }, tokenProgram];
  const ata = (mint, owner) => getAssociatedTokenAddressSync(mint, owner, true, tokenProgram);
  const tokens = async (account) => {
    try {
      return (await getAccount(conn, account, 'confirmed', tokenProgram)).amount;
    } catch {
      return 0n;
    }
  };

  const t = newVault();
  assert.equal((await open(t)).err, null);
  // payer is mint authority and freeze authority; 6 decimals.
  const mint = await createMint(conn, payer, payer.publicKey, payer.publicKey, 6, ...opts);
  const other = await createMint(conn, payer, payer.publicKey, null, 6, ...opts);
  const source = (await getOrCreateAssociatedTokenAccount(conn, payer, mint, t.address, true, 'confirmed', opts[1], tokenProgram)).address;
  const sourceOther = (await getOrCreateAssociatedTokenAccount(conn, payer, other, t.address, true, 'confirmed', opts[1], tokenProgram)).address;
  await mintTo(conn, payer, mint, source, payer, 1000_000000n, [], opts[1], tokenProgram);
  await mintTo(conn, payer, other, sourceOther, payer, 1000_000000n, [], opts[1], tokenProgram);
  assert.equal(source.toBase58(), ata(mint, t.address).toBase58());
  ok('the vault address receives tokens in an ordinary associated token account');

  const erin = fresh();
  const dest = ata(mint, erin);
  const thiefWallet = Keypair.generate();
  const thief = (await getOrCreateAssociatedTokenAccount(conn, payer, mint, thiefWallet.publicKey, true, 'confirmed', opts[1], tokenProgram)).address;
  const thiefOther = (await getOrCreateAssociatedTokenAccount(conn, payer, other, thiefWallet.publicKey, true, 'confirmed', opts[1], tokenProgram)).address;
  await mintTo(conn, payer, mint, thief, payer, 5_000000n, [], opts[1], tokenProgram);

  const createDest = createAssociatedTokenAccountIdempotentInstruction(payer.publicKey, dest, erin, mint, tokenProgram);
  const qty = 250_000000n;
  const pay = signed(t, 0, mint, dest, qty);
  const tokenIx = (s, over = {}) =>
    spendTokenInstruction({ programId, vault: t.address, source, destination: dest, mint, tokenProgram, signed: s, ...over });
  const held = async () => [await tokens(source), await tokens(sourceOther), await tokens(thief), await tokens(thiefOther)];
  const no = (name, ix, expect) => rejected(name, t, max(ix), expect, held);

  await no("destination swapped for an attacker's token account", tokenIx(pay, { destination: thief }), ERR.BadSignature);
  await no('amount raised', tokenIx({ ...pay, amount: qty + 1n }), ERR.BadSignature);
  await no('mint swapped for another token the vault holds', tokenIx(pay, { mint: other, source: sourceOther, destination: thiefOther }), ERR.BadSignature);
  await no('a SOL payment signature used to move tokens', tokenIx(signed(t, 0, SOL_ASSET, dest, qty)), ERR.BadSignature);
  await no('a made-up token program', tokenIx(pay, { tokenProgram: fresh() }), ERR.UnknownTokenProgram);
  await no('the other real token program', tokenIx(pay, { tokenProgram: otherProgram }), ERR.BadMint);
  await no('something that is not a mint in the mint slot', tokenIx(signed(t, 0, payer.publicKey, dest, qty), { mint: payer.publicKey }), ERR.BadMint);
  await rejected('a token payment signature sent as a SOL payment', t, max(payIx(t, pay, dest)), ERR.BadSignature, held);
  {
    // Correctly signed, but the token program itself refuses: the whole
    // transaction is undone, so the key is not used up.
    const before = [await state(t.address), await held()];
    const fromThief = await submit([createDest, tokenIx(pay, { source: thief })], MAX_COMPUTE_UNITS);
    assert(fromThief.err && fromThief.failedIn === tokenProgram.toBase58(), JSON.stringify(fromThief));
    const tooMuch = signed(t, 0, mint, dest, 5000_000000n);
    const over = await submit([createDest, tokenIx(tooMuch)], MAX_COMPUTE_UNITS);
    assert(over.err && over.failedIn === tokenProgram.toBase58(), JSON.stringify(over));
    assert.deepEqual([await state(t.address), await held()], before);
    ok("spending from someone else's token account, or more than the vault holds, fails and changes nothing");
  }

  {
    // The real thing, with a priority fee and creating the recipient's token account, all in one transaction.
    const units = computeLimit(pay.hashes, { token: true });
    const res = await submit([createDest, tokenIx(pay)], units, payer, { microLamportsPerCu: 1 });
    assert.equal(res.err, null, JSON.stringify(res));
    assert(res.units <= units, `estimate too low: ${res.units} > ${units}`);
    assert(res.bytes <= MAX_TX_BYTES, `${res.bytes} bytes`);
    assert.equal(await tokens(dest), qty);
    assert.equal(await tokens(source), 750_000000n);
    assert.equal(await tokens(sourceOther), 1000_000000n);
    const s = await state(t.address);
    assert.deepEqual(s.keyHash, t.key(1).keyHash);
    assert.equal(s.sequence, 1n);
    assert.equal(s.outcome, OUTCOME_PAID);
    assert.deepEqual(s.lastMessage, pay.digest);
    ok(`250 tokens paid to a brand-new recipient in one transaction (${res.bytes} bytes, ${res.units} CU)`);
    await no('replaying the token payment', tokenIx(pay), ERR.KeyReuse);
  }
  {
    // The rest, to an existing token account, then SOL from the same vault.
    const all = signed(t, 1, mint, dest, 750_000000n);
    const res = await submit(tokenIx(all), computeLimit(all.hashes, { token: true }));
    assert.equal(res.err, null, JSON.stringify(res));
    assert.equal(await tokens(dest), 1000_000000n);
    assert.equal(await tokens(source), 0n);
    await deposit(t.address, SOL);
    const sol = signed(t, 2, SOL_ASSET, erin, SOL);
    assert.equal((await submit(payIx(t, sol, erin), computeLimit(sol.hashes))).err, null);
    assert.equal(await balance(erin), SOL);
    ok('sends the whole token balance, then SOL, from the same vault with consecutive keys');
  }
  {
    // The case Cancel exists for: a signed payment that cannot succeed.
    await mintTo(conn, payer, mint, source, payer, 40_000000n, [], opts[1], tokenProgram);
    const stuck = signed(t, 3, mint, dest, 40_000000n);
    await freezeAccount(conn, payer, source, mint, payer, [], opts[1], tokenProgram);
    const before = await state(t.address);
    const frozen = await submit(tokenIx(stuck), MAX_COMPUTE_UNITS);
    assert(frozen.err && frozen.failedIn === tokenProgram.toBase58(), JSON.stringify(frozen));
    assert.deepEqual(await state(t.address), before);

    const cancel = cancelInstruction({ programId, vault: t.address, asset: mint, destination: dest, signed: stuck });
    assert.equal((await submit(cancel, computeLimit(stuck.hashes))).err, null);
    const s = await state(t.address);
    assert.equal(s.sequence, 4n);
    assert.equal(s.outcome, OUTCOME_CANCELLED);
    assert.deepEqual(s.lastMessage, stuck.digest);
    assert.equal(await tokens(source), 40_000000n);

    await thawAccount(conn, payer, source, mint, payer, [], opts[1], tokenProgram);
    await no('the cancelled token payment, once the account is thawed', tokenIx(stuck), ERR.KeyReuse);
    const retry = signed(t, 4, mint, dest, 40_000000n);
    assert.equal((await submit(tokenIx(retry), computeLimit(retry.hashes, { token: true }))).err, null);
    assert.equal(await tokens(dest), 1040_000000n);
    ok('a payment stuck on a frozen token account is cancelled, and the next key works');
  }
}

// ------------------------------------------------------------ cost survey
console.log('\ncompute cost over 40 SOL payments from one vault');
{
  const samples = [];
  const c = newVault();
  assert.equal((await open(c)).err, null);
  await deposit(c.address, SOL);
  for (let k = 0; k < 40; k++) {
    const to = fresh();
    const s = signed(c, k, SOL_ASSET, to, SOL / 100n);
    const units = computeLimit(s.hashes);
    const res = await submit(payIx(c, s, to), units);
    assert.equal(res.err, null, JSON.stringify(res));
    assert(res.units <= units, `estimate too low: ${res.units} > ${units}`);
    samples.push({ hashes: s.hashes, units: res.units, bytes: res.bytes });
  }
  assert.equal((await state(c.address)).sequence, 40n);
  // Least-squares fit: units = fixed + perHash * hashes
  const n = samples.length;
  const mx = samples.reduce((t, s) => t + s.hashes, 0) / n;
  const my = samples.reduce((t, s) => t + s.units, 0) / n;
  const perHash =
    samples.reduce((t, s) => t + (s.hashes - mx) * (s.units - my), 0) /
    samples.reduce((t, s) => t + (s.hashes - mx) ** 2, 0);
  const fixed = my - perHash * mx;
  const units = samples.map((s) => s.units);
  const hashes = samples.map((s) => s.hashes);
  const worst = CHAINS * CHAIN_STEPS;
  console.log(`  hashes  min ${Math.min(...hashes)}  mean ${Math.round(mx)}  max ${Math.max(...hashes)}`);
  console.log(`  CU      min ${Math.min(...units)}  mean ${Math.round(my)}  max ${Math.max(...units)}`);
  console.log(`  fit     ${perHash.toFixed(2)} CU per hash + ${Math.round(fixed)} fixed`);
  console.log(`  worst possible digest (${worst} hashes) would cost about ${Math.round(fixed + perHash * worst)} CU of ${MAX_COMPUTE_UNITS} allowed`);
  console.log(`  SOL payment transaction size ${samples[0].bytes} of ${MAX_TX_BYTES} bytes`);
  ok('40 consecutive payments, each within the client compute estimate');
}

console.log(`\n${passed} checks passed`);
