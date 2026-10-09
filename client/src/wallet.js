// The wallet: a master seed and the bookkeeping that makes sure each
// one-time key signs exactly one message.
//
// The vault's on-chain `sequence` says which key is current: key number
// `sequence` signs the next payment, and that payment installs key
// `sequence + 1`.
//
// THE RULE: before a signature with key k is created, the exact payment is
// saved as `pending`. From then on key k can only ever sign that payment
// again (or be retired by cancelling it), until the chain shows the vault
// has moved past k. A crash, a dropped transaction or an expired blockhash
// therefore never leads to a second, different signature.
//
// This file is portable: it runs in Node (see file-wallet.js) and in a
// browser (see web/). Where the state is kept and who pays the network fee
// are both passed in:
//
//   store     { save(state), load?() }       keeps the wallet state durable
//   feePayer  { publicKey, signTransaction }  an ordinary Solana signer

import { Buffer } from 'buffer';
import { PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import {
  ExtensionType,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  getAssociatedTokenAddressSync,
  getExtensionTypes,
  getPausableConfig,
  getTransferHook,
  unpackAccount,
  unpackMint,
} from '@solana/spl-token';
import bs58 from 'bs58';
import {
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
  describeMessage,
  openInstruction,
  signMessage,
  spendSolInstruction,
  spendTokenInstruction,
  vaultAddress,
} from './vault.js';

const TOKEN_PROGRAMS = [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID];
const isTokenProgram = (pk) => TOKEN_PROGRAMS.some((p) => p.equals(pk));

/** "1.5" with 9 decimals -> 1500000000n, exactly, with no floating point. */
export function parseUnits(text, decimals) {
  const pattern = decimals > 0 ? new RegExp(`^\\d+(\\.\\d{1,${decimals}})?$`) : /^\d+$/;
  if (!pattern.test(text)) throw new Error(`not a valid amount (up to ${decimals} decimal places): ${text}`);
  const [whole, frac = ''] = text.split('.');
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
}

/** 1500000000n with 9 decimals -> "1.5" */
export function formatUnits(amount, decimals) {
  const base = 10n ** BigInt(decimals);
  const frac = decimals > 0 ? (amount % base).toString().padStart(decimals, '0').replace(/0+$/, '') : '';
  return frac ? `${amount / base}.${frac}` : `${amount / base}`;
}

export const parseSol = (text) => parseUnits(text, 9);
export const formatSol = (lamports) => formatUnits(lamports, 9);

/** One readable line from an RPC, wallet-extension or program error. */
export function explainError(error) {
  const logs = error?.logs ?? error?.transactionLogs ?? [];
  const said = logs.find((line) => line.startsWith('Program log: Error: '));
  if (said) return said.slice('Program log: Error: '.length);
  const all = [error?.transactionError?.message, error?.message ?? String(error)].filter(Boolean).join(' ');
  if (/no record of a prior credit|insufficient lamports|insufficient funds for (fee|rent)/i.test(all)) {
    return 'The fee wallet does not have enough SOL. Send a little SOL to it and try again.';
  }
  if (/failed to fetch|networkerror|load failed|fetch failed|ECONNREFUSED/i.test(all)) {
    return 'Could not reach the Solana network. Check your connection and the RPC address.';
  }
  if (/user rejected/i.test(all)) return 'You declined the request in your wallet extension.';
  const text = (error?.transactionError?.message ?? error?.message ?? String(error)).split('\n')[0].trim();
  return text.length > 300 ? `${text.slice(0, 300)}…` : text;
}

const UPGRADEABLE_LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
const FROZEN_LOADERS = ['BPFLoader2111111111111111111111111111111111', 'BPFLoader1111111111111111111111111111111111'];

/**
 * Refuse a program that someone can still change.
 *
 * Whoever holds a program's upgrade key can replace its code and empty every
 * vault under it, and that key is an ordinary ed25519 key. So a vault should
 * only ever be created under a program whose upgrade authority is gone.
 */
export async function requireImmutableProgram(conn, programId) {
  programId = new PublicKey(programId);
  const info = await conn.getAccountInfo(programId);
  if (!info) throw new Error(`there is no program at ${programId.toBase58()} on this network`);
  if (!info.executable) throw new Error(`${programId.toBase58()} is not a program`);
  if (FROZEN_LOADERS.includes(info.owner.toBase58())) return;
  if (!info.owner.equals(UPGRADEABLE_LOADER) || info.data.length < 36 || Buffer.from(info.data).readUInt32LE(0) !== 2) {
    throw new Error('this program uses a loader this wallet cannot check, so it cannot confirm the program is unchangeable');
  }
  const programData = await conn.getAccountInfo(new PublicKey(info.data.subarray(4, 36)));
  if (!programData || programData.data.length < 13 || Buffer.from(programData.data).readUInt32LE(0) !== 3) {
    throw new Error('could not read this program\'s upgrade settings');
  }
  if (programData.data[12] !== 0) {
    const authority = new PublicKey(programData.data.subarray(13, 45)).toBase58();
    throw new Error(
      `this program can still be changed by whoever holds ${authority}, so a vault under it would not be safe. It has to be deployed as final first.`,
    );
  }
}

/** 32 fresh random bytes from the platform's secure generator. */
export function randomSeed() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Buffer.from(bytes);
}

/** Use a plain keypair as the fee payer. */
export function keypairSigner(keypair) {
  return {
    publicKey: keypair.publicKey,
    signTransaction: async (tx) => {
      tx.partialSign(keypair);
      return tx;
    },
  };
}

export class Wallet {
  /**
   * `state` is everything that is safe to store as-is. The master seed is
   * handed over separately so a store can keep it however it sees fit
   * (in the same file, encrypted, ...).
   */
  constructor(store, state, masterSeed) {
    if (state.version !== 2) throw new Error(`unsupported wallet version ${state.version}`);
    if (!Buffer.isBuffer(masterSeed) || masterSeed.length !== 32) throw new Error('master seed must be 32 bytes');
    this.store = store;
    this.state = state;
    this.masterSeed = masterSeed;
    this.programId = new PublicKey(state.programId);
    this.address = new PublicKey(state.address);
    this.keys = new Map();
  }

  /** The state of a brand-new wallet for `masterSeed`. Not saved yet. */
  static initialState({ programId, url, masterSeed }) {
    programId = new PublicKey(programId);
    return {
      version: 2,
      programId: programId.toBase58(),
      url,
      address: vaultAddress(programId, deriveVaultKey(masterSeed, 0).keyHash).toBase58(),
      // Lowest key number this wallet may still sign with. Only ever goes up.
      sequence: 0,
      pending: null,
      history: [],
    };
  }

  save() {
    this.store.save(this.state);
  }

  /**
   * Pick up anything another copy of this wallet (a second browser tab, a
   * second process) has saved since we last looked.
   */
  reload() {
    const fresh = this.store.load?.();
    if (fresh) this.state = fresh;
  }

  key(index) {
    let key = this.keys.get(index);
    if (!key) {
      key = deriveVaultKey(this.masterSeed, index);
      if (this.keys.size > 8) this.keys.clear();
      this.keys.set(index, key);
    }
    return key;
  }

  get pending() {
    return this.state.pending;
  }

  // ------------------------------------------------------------- reading

  /**
   * Read the vault from the chain and reconcile it with what this wallet
   * knows. Returns { opened, lamports, sequence, reserve, spendable }.
   *
   * Catches the three ways local and chain state can disagree:
   *  - the chain is ahead (another device spent, or this is a restore, or a
   *    pending payment landed): move forward and record what happened;
   *  - the chain is behind (a stale RPC node): refuse, because signing now
   *    would reuse a key;
   *  - the vault's current key is not ours: refuse.
   */
  async sync(conn) {
    this.reload();
    const info = await conn.getAccountInfo(this.address);
    const reserve = BigInt(await conn.getMinimumBalanceForRentExemption(STATE_LEN));
    const lamports = BigInt(info?.lamports ?? 0);

    if (!info || info.owner.equals(SystemProgram.programId)) {
      if (this.state.sequence > 0) {
        throw new Error('the RPC node shows no vault account, but this wallet has already spent from it; the node is out of date');
      }
      const spendable = lamports > reserve ? lamports - reserve : 0n;
      return { opened: false, lamports, sequence: 0, reserve, spendable };
    }

    const onChain = info.owner.equals(this.programId) ? decodeState(info.data) : null;
    if (!onChain) throw new Error(`${this.address.toBase58()} is not a vault of program ${this.programId.toBase58()}`);
    if (onChain.sequence > BigInt(0xfffffff0)) throw new Error('vault sequence is beyond what this wallet supports');
    const sequence = Number(onChain.sequence);

    if (sequence < this.state.sequence) {
      throw new Error(
        `the RPC node is out of date: it shows key #${sequence} as current, this wallet has already used #${this.state.sequence - 1}. Try again shortly.`,
      );
    }
    if (!this.key(sequence).keyHash.equals(onChain.keyHash)) {
      throw new Error(`the vault's current key (#${sequence}) does not come from this wallet's seed; refusing to continue`);
    }
    if (sequence > this.state.sequence) {
      // The vault moved on without this wallet recording it. If a payment
      // was pending, find out what became of it.
      if (this.state.pending) await this.#settle(conn, onChain, sequence);
      this.state.sequence = sequence;
      this.save();
    }
    return { opened: true, lamports, sequence, reserve, spendable: lamports - reserve };
  }

  /**
   * The pending key has been used up on-chain. The vault records the digest
   * of the last message and whether it paid or was cancelled, so compare
   * that with ours. If it is not ours, another copy of this wallet used the
   * key for something else and our payment was never made.
   */
  async #settle(conn, onChain, sequence) {
    const p = this.state.pending;
    let outcome = null;
    if (sequence === p.index + 1) {
      if (onChain.lastMessage.toString('hex') !== p.digest) outcome = 'superseded';
      else if (onChain.outcome === OUTCOME_PAID) outcome = 'sent';
      else if (onChain.outcome === OUTCOME_CANCELLED) outcome = 'cancelled';
    }
    // Which of our own transactions did it, if any. Also the fallback when
    // several keys have been used since and the record above is gone.
    let txid = null;
    try {
      const landed = await this.#landed(conn, p.txids);
      if (landed && !outcome) outcome = landed.kind === 'pay' ? 'sent' : 'cancelled';
      if (landed && (landed.kind === 'pay') === (outcome === 'sent')) txid = landed.id;
    } catch {
      // The transaction id is a convenience; the outcome above does not depend on it.
    }
    this.#record(p, outcome ?? 'unknown', txid);
  }

  async #landed(conn, txids) {
    for (let i = 0; i < txids.length; i += 256) {
      const batch = txids.slice(i, i + 256); // RPC limit per call
      const { value } = await conn.getSignatureStatuses(batch.map((t) => t.id), { searchTransactionHistory: true });
      const at = value.findIndex((status) => status && !status.err);
      if (at >= 0) return batch[at];
    }
    return null;
  }

  #record(p, outcome, txid) {
    this.state.history.push({
      index: p.index,
      asset: p.asset,
      decimals: p.decimals,
      recipient: p.recipient,
      amount: p.amount,
      outcome,
      txid,
      finishedAt: new Date().toISOString(),
    });
    this.state.pending = null;
  }

  /** Every token the vault holds: [{ mint, account, amount, decimals, frozen }]. */
  async holdings(conn) {
    const out = [];
    for (const programId of TOKEN_PROGRAMS) {
      const { value } = await conn.getParsedTokenAccountsByOwner(this.address, { programId });
      for (const { pubkey, account } of value) {
        const t = account.data.parsed.info;
        out.push({
          mint: t.mint,
          account: pubkey.toBase58(),
          amount: BigInt(t.tokenAmount.amount),
          decimals: t.tokenAmount.decimals,
          frozen: t.state === 'frozen',
        });
      }
    }
    return out;
  }

  /** What kind of token `mint` is, refusing the kinds this vault cannot send. */
  async #mint(conn, mint) {
    const info = await conn.getAccountInfo(mint);
    if (!info) throw new Error(`no token mint at ${mint.toBase58()}`);
    if (!isTokenProgram(info.owner)) throw new Error(`${mint.toBase58()} is not a token mint`);
    let parsed;
    try {
      parsed = unpackMint(mint, info, info.owner);
    } catch {
      throw new Error(`${mint.toBase58()} is not a token mint`);
    }
    if (info.owner.equals(TOKEN_2022_PROGRAM_ID)) {
      if (getExtensionTypes(parsed.tlvData).includes(ExtensionType.NonTransferable)) {
        throw new Error('this token is non-transferable');
      }
      const hook = getTransferHook(parsed);
      if (hook && !hook.programId.equals(PublicKey.default)) {
        throw new Error('this token uses a transfer hook, which this vault does not support');
      }
      if (getPausableConfig(parsed)?.paused) throw new Error('transfers of this token are currently paused');
    }
    return { tokenProgram: info.owner, decimals: parsed.decimals };
  }

  /** The vault's token account for `mint`. */
  tokenAccount(mint, tokenProgram) {
    return getAssociatedTokenAddressSync(mint, this.address, true, tokenProgram);
  }

  // ------------------------------------------------------------- set-up

  async #send(conn, feePayer, tx) {
    const blockhash = await conn.getLatestBlockhash();
    tx.feePayer = feePayer.publicKey;
    tx.recentBlockhash = blockhash.blockhash;
    const signedTx = await feePayer.signTransaction(tx);
    const txid = await conn.sendRawTransaction(signedTx.serialize());
    const result = await conn.confirmTransaction({ signature: txid, ...blockhash });
    if (result.value.err) throw new Error(`transaction failed: ${JSON.stringify(result.value.err)}`);
    return txid;
  }

  /** Create the on-chain vault account. Does not touch any vault key. */
  async open(conn, feePayer) {
    return this.#send(
      conn,
      feePayer,
      new Transaction().add(
        openInstruction({
          programId: this.programId,
          payer: feePayer.publicKey,
          vault: this.address,
          firstKeyHash: this.key(0).keyHash,
        }),
      ),
    );
  }

  /**
   * Make sure the vault has a token account for `mint`, so it can receive
   * that token. Returns { account, created }. Does not touch any vault key.
   */
  async openTokenAccount(conn, feePayer, mintText) {
    const mint = new PublicKey(mintText);
    const { tokenProgram } = await this.#mint(conn, mint);
    const account = this.tokenAccount(mint, tokenProgram);
    if (await conn.getAccountInfo(account)) return { account, created: false };
    await this.#send(
      conn,
      feePayer,
      new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(feePayer.publicKey, account, this.address, mint, tokenProgram),
      ),
    );
    return { account, created: true };
  }

  // ------------------------------------------------------------ planning
  //
  // A transaction that fails still publishes the signature, and the key can
  // then only repeat or cancel that payment. So every predictable failure is
  // caught here, before anything is signed. Planning only reads.

  async #start(conn) {
    const vault = await this.sync(conn);
    if (this.state.pending) {
      throw new Error('a payment is already pending; run "resume" to finish it or "cancel" to call it off');
    }
    if (!vault.opened) throw new Error('the vault account has not been opened yet');
    return vault;
  }

  /** Plan a SOL payment to an ordinary wallet address. */
  async planSol(conn, recipientText, amountText) {
    const vault = await this.#start(conn);
    const recipient = new PublicKey(recipientText);
    if (recipient.equals(this.address)) throw new Error('recipient is the vault itself');
    if (vault.spendable === 0n) throw new Error('the vault has no SOL to spend');

    const amount = amountText === 'all' ? vault.spendable : parseSol(amountText);
    if (amount === 0n) throw new Error('amount must be greater than zero');
    if (amount > vault.spendable) {
      throw new Error(`the vault can spend ${formatSol(vault.spendable)} SOL, cannot send ${formatSol(amount)}`);
    }
    // Programs, sysvars and other special accounts can refuse to be credited.
    const info = await conn.getAccountInfo(recipient);
    if (info && (info.executable || !info.owner.equals(SystemProgram.programId))) {
      throw new Error(`recipient is not an ordinary wallet address (it is owned by program ${info.owner.toBase58()})`);
    }
    // Solana refuses to create an account below the rent-exempt minimum.
    const rentMin = BigInt(await conn.getMinimumBalanceForRentExemption(0));
    if (amount < rentMin && BigInt(info?.lamports ?? 0) === 0n) {
      throw new Error(`recipient is a new account and needs at least ${formatSol(rentMin)} SOL to exist`);
    }
    return {
      index: vault.sequence,
      asset: 'SOL',
      decimals: 9,
      recipient,
      destination: recipient,
      amount,
      left: vault.spendable - amount,
    };
  }

  /**
   * Plan a token payment. `recipientText` is normally the recipient's wallet
   * address; their token account for this mint is also accepted.
   */
  async planToken(conn, mintText, recipientText, amountText) {
    await this.#start(conn);
    const mint = new PublicKey(mintText);
    const { tokenProgram, decimals } = await this.#mint(conn, mint);

    const source = this.tokenAccount(mint, tokenProgram);
    const sourceInfo = await conn.getAccountInfo(source);
    if (!sourceInfo) throw new Error('the vault holds none of this token');
    const held = unpackAccount(source, sourceInfo, tokenProgram);
    if (held.isFrozen) throw new Error("the vault's account for this token is frozen by the token's issuer");
    if (held.amount === 0n) throw new Error('the vault holds none of this token');

    const amount = amountText === 'all' ? held.amount : parseUnits(amountText, decimals);
    if (amount === 0n) throw new Error('amount must be greater than zero');
    if (amount > held.amount) {
      throw new Error(`the vault holds ${formatUnits(held.amount, decimals)}, cannot send ${formatUnits(amount, decimals)}`);
    }

    const recipient = new PublicKey(recipientText);
    if (recipient.equals(this.address) || recipient.equals(source)) throw new Error('recipient is the vault itself');
    const info = await conn.getAccountInfo(recipient);
    let destination;
    let createAccount = false;
    if (info && isTokenProgram(info.owner)) {
      // They gave a token account, not a wallet. Fine if it is for this token.
      let account;
      try {
        account = unpackAccount(recipient, info, info.owner);
      } catch {
        throw new Error('recipient is a token mint or other token-program account, not a wallet');
      }
      if (!info.owner.equals(tokenProgram) || !account.mint.equals(mint)) {
        throw new Error('recipient is a token account for a different token');
      }
      if (account.isFrozen) throw new Error("the recipient's token account is frozen");
      destination = recipient;
    } else {
      if (info?.executable) throw new Error('recipient is a program, not a wallet');
      destination = getAssociatedTokenAddressSync(mint, recipient, true, tokenProgram);
      const existing = await conn.getAccountInfo(destination);
      if (existing) {
        if (unpackAccount(destination, existing, tokenProgram).isFrozen) throw new Error("the recipient's token account is frozen");
      } else {
        createAccount = true; // the fee payer covers its rent, in the same transaction
      }
    }
    return {
      index: this.state.sequence,
      asset: mint.toBase58(),
      tokenProgram,
      decimals,
      recipient,
      destination,
      createAccount,
      amount,
      left: held.amount - amount,
    };
  }

  /**
   * Check that the fee payer can afford `plan` before the key is locked to
   * it. Running out of fee money is the most ordinary way for a payment to
   * fail, and after `commit` a failure costs a cancel.
   */
  async requireFeeFunds(conn, feePayerKey, plan, { microLamportsPerCu = 0 } = {}) {
    const priority = (BigInt(microLamportsPerCu) * 1_400_000n) / 1_000_000n;
    // A new token account costs its creator about 0.0021 SOL in rent.
    const rent = plan.createAccount ? 2_200_000n : 0n;
    const need = 10_000n + priority + rent;
    const have = BigInt(await conn.getBalance(feePayerKey));
    if (have < need) {
      throw new Error(`the fee wallet needs at least ${formatSol(need)} SOL for this payment and has ${formatSol(have)}`);
    }
  }

  // ----------------------------------------------------------- committing

  #message(p) {
    return {
      programId: this.programId,
      vault: this.address,
      sequence: BigInt(p.index),
      key: this.key(p.index),
      nextKeyHash: this.key(p.index + 1).keyHash,
      asset: p.asset === 'SOL' ? SOL_ASSET : new PublicKey(p.asset),
      destination: new PublicKey(p.destination),
      amount: BigInt(p.amount),
    };
  }

  /** Lock key `plan.index` to this one payment. Saved before anything is signed. */
  commit(plan) {
    this.reload();
    if (this.state.pending) throw new Error('a payment is already pending');
    if (plan.index !== this.state.sequence) throw new Error('the vault has changed since this payment was reviewed; review it again');
    const pending = {
      index: plan.index,
      asset: plan.asset,
      tokenProgram: plan.tokenProgram?.toBase58() ?? null,
      decimals: plan.decimals,
      recipient: plan.recipient.toBase58(),
      destination: plan.destination.toBase58(),
      createAccount: plan.createAccount ?? false,
      amount: plan.amount.toString(),
      createdAt: new Date().toISOString(),
      // Set once the signature has been handed to anything outside this
      // wallet: the network, or a fee wallet such as a browser extension.
      exposed: false,
      txids: [], // every transaction we have broadcast for this payment: { id, kind }
    };
    pending.digest = describeMessage(this.#message(pending)).digest.toString('hex');
    this.state.pending = pending;
    this.save();
  }

  /**
   * Sign and broadcast the pending payment, then wait for it to land. Safe
   * to call any number of times: it always produces the same signature.
   *
   * Returns { outcome, txid?, error? } where outcome is
   *   'sent'        the payment is on-chain
   *   'pending'     not landed yet; still locked; resume or cancel
   *   'cancelled'   it was cancelled instead
   *   'superseded'  another copy of this wallet used the key first, so this
   *                 payment was never made
   *   'unknown'     the key is used up but the record is gone; check the recipient
   */
  async sendPending(conn, feePayer, options = {}) {
    return this.#act(conn, feePayer, options, 'pay', (p, signed) => {
      if (p.asset === 'SOL') {
        return [spendSolInstruction({ programId: this.programId, vault: this.address, recipient: new PublicKey(p.destination), signed })];
      }
      const mint = new PublicKey(p.asset);
      const tokenProgram = new PublicKey(p.tokenProgram);
      const destination = new PublicKey(p.destination);
      const instructions = [];
      if (p.createAccount) {
        instructions.push(
          createAssociatedTokenAccountIdempotentInstruction(feePayer.publicKey, destination, new PublicKey(p.recipient), mint, tokenProgram),
        );
      }
      instructions.push(
        spendTokenInstruction({
          programId: this.programId,
          vault: this.address,
          source: this.tokenAccount(mint, tokenProgram),
          destination,
          mint,
          tokenProgram,
          signed,
        }),
      );
      return instructions;
    });
  }

  /**
   * Call off the pending payment. If its signature never left this wallet,
   * the lock is simply dropped and the key stays unused. Otherwise the
   * signature must be treated as public, so the key is retired on-chain
   * without paying. Same return shape as sendPending; a payment that lands
   * first wins.
   */
  async cancelPending(conn, feePayer, options = {}) {
    this.reload();
    if (!this.state.pending) throw new Error('nothing is pending');
    if (!this.state.pending.exposed) {
      await this.sync(conn);
      if (this.state.pending && !this.state.pending.exposed) {
        this.#record(this.state.pending, 'cancelled', null);
        this.save();
      }
      return this.#outcome();
    }
    return this.#act(conn, feePayer, options, 'cancel', (p, signed, message) => [
      cancelInstruction({
        programId: this.programId,
        vault: this.address,
        asset: message.asset,
        destination: message.destination,
        signed,
      }),
    ]);
  }

  async #act(conn, feePayer, { microLamportsPerCu }, kind, build) {
    this.reload();
    if (!this.state.pending) throw new Error('nothing is pending');
    await this.sync(conn); // settles `pending` if the vault has moved on
    if (!this.state.pending) return this.#outcome();
    const p = this.state.pending;

    const message = this.#message(p);
    const signed = signMessage(message);
    if (signed.digest.toString('hex') !== p.digest) {
      throw new Error('internal error: the pending payment no longer matches its recorded digest; nothing was sent');
    }
    const instructions = build(p, signed, message);
    const blockhash = await conn.getLatestBlockhash();
    const tx = buildTransaction({
      instructions,
      units: computeLimit(signed.hashes, { token: kind === 'pay' && p.asset !== 'SOL' }),
      feePayer: feePayer.publicKey,
      microLamportsPerCu,
      ...blockhash,
    });

    // Our instruction exactly as built, to compare with what comes back.
    const fingerprint = (ix) =>
      [ix.programId.toBase58(), Buffer.from(ix.data).toString('hex'), ...ix.keys.map((k) => `${k.pubkey.toBase58()}:${k.isSigner}:${k.isWritable}`)].join('|');
    const expected = fingerprint(instructions.at(-1));

    // From the next line on, the vault's signature is in someone else's hands.
    p.exposed = true;
    this.save();

    let error;
    let txid;
    try {
      const signedTx = await feePayer.signTransaction(tx);
      // A fee wallet may add to a transaction; it must not touch our instruction.
      if (!signedTx.instructions.some((ix) => fingerprint(ix) === expected)) {
        throw new Error('the fee wallet returned a different transaction; nothing was sent');
      }
      const raw = signedTx.serialize();
      if (raw.length > MAX_TX_BYTES) throw new Error(`transaction is ${raw.length} bytes, limit ${MAX_TX_BYTES}`);

      // Remember the transaction id before it leaves, so that whatever
      // happens next we can ask the chain whether this exact one landed.
      txid = bs58.encode(signedTx.signature);
      p.txids.push({ id: txid, kind });
      this.save();

      await conn.sendRawTransaction(raw);
      const result = await conn.confirmTransaction({ signature: txid, ...blockhash });
      if (result.value.err) error = new Error(`transaction failed: ${JSON.stringify(result.value.err)}`);
    } catch (e) {
      error = e;
    }
    // Success or not, only the chain can say what happened.
    try {
      await this.sync(conn);
    } catch (e) {
      error ??= e;
    }
    if (!this.state.pending) return this.#outcome();
    return { outcome: 'pending', error: error ?? new Error('confirmed, but the vault has not advanced yet') };
  }

  /** Result of the most recently settled payment. */
  #outcome() {
    const last = this.state.history.at(-1);
    return { outcome: last.outcome, txid: last.txid };
  }
}
