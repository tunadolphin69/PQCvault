#!/usr/bin/env node
// qpv: command line wallet for QP Vault.

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { createFileWallet, loadFileWallet } from './file-wallet.js';
import { explainError, formatSol, formatUnits, keypairSigner, requireImmutableProgram } from './wallet.js';

const HELP = `qpv - a Solana vault for SOL and tokens, opened only by hash-based one-time signatures

  qpv init --program <id> [--url <rpc>] [--seed <hex>]   create a wallet (or restore one from its seed)
  qpv address                                            the vault address; send SOL here any time
  qpv open                                               create the vault account on-chain
  qpv balance                                            SOL and tokens the vault holds
  qpv token-address <mint>                               get the vault ready to receive a token
  qpv send <recipient> <SOL | all>                       pay SOL to a wallet address
  qpv send-token <mint> <recipient> <amount | all>       pay a token to a wallet address
  qpv resume                                             retry a payment that did not confirm
  qpv cancel                                             call off a payment that did not confirm
  qpv status                                             vault, pending payment, history

options
  --wallet <file>      wallet file (default ~/.config/qp-vault/wallet.json, or $QPV_WALLET)
  --fee-payer <file>   ordinary Solana keypair that pays network fees (default ~/.config/solana/id.json)
  --priority-fee <n>   micro-lamports per compute unit, if the network is busy
  --yes                do not ask for confirmation
`;

const { values: opt, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    wallet: { type: 'string' },
    program: { type: 'string' },
    url: { type: 'string' },
    seed: { type: 'string' },
    'fee-payer': { type: 'string' },
    'priority-fee': { type: 'string' },
    yes: { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
});
const [command, ...args] = positionals;

const walletPath = opt.wallet ?? process.env.QPV_WALLET ?? join(homedir(), '.config', 'qp-vault', 'wallet.json');

const open = () => {
  if (!existsSync(walletPath)) throw new Error(`no wallet at ${walletPath}; run "qpv init" first`);
  const wallet = loadFileWallet(walletPath);
  return { wallet, conn: new Connection(opt.url ?? wallet.state.url, 'confirmed') };
};

const feePayer = () => {
  const path = opt['fee-payer'] ?? join(homedir(), '.config', 'solana', 'id.json');
  if (!existsSync(path)) throw new Error(`no fee payer keypair at ${path}; pass --fee-payer`);
  return keypairSigner(Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, 'utf8')))));
};

const sendOptions = () =>
  opt['priority-fee'] ? { microLamportsPerCu: Number(opt['priority-fee']) } : {};

async function confirm(question) {
  if (opt.yes) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(`${question} [y/N] `);
  rl.close();
  return /^y(es)?$/i.test(answer.trim());
}

async function ensureOpened(wallet, conn, payer) {
  if ((await wallet.sync(conn)).opened) return;
  console.log('opening the vault account on-chain...');
  console.log(`opened: ${await wallet.open(conn, payer)}`);
}

/** "1.5 SOL" or "250 of <mint>" */
const describe = (p) =>
  p.asset === 'SOL'
    ? `${formatSol(BigInt(p.amount))} SOL`
    : `${formatUnits(BigInt(p.amount), p.decimals)} of token ${p.asset}`;

function report(result) {
  const id = result.txid ? `: ${result.txid}` : '';
  switch (result.outcome) {
    case 'sent':
      console.log(`sent${id}`);
      return;
    case 'cancelled':
      console.log(`cancelled${id}. Nothing was paid.`);
      return;
    case 'superseded':
      process.exitCode = 1;
      console.error('NOT SENT. The vault was used from another copy of this wallet first, which used up the key.');
      console.error('Nothing was lost. Check "qpv status" and send again if you still want to.');
      return;
    case 'unknown':
      process.exitCode = 1;
      console.error('The key for this payment has been used, but the vault has moved on too far to tell how.');
      console.error("Check the recipient's balance before sending again.");
      return;
    default:
      process.exitCode = 1;
      console.error(`not confirmed: ${explainError(result.error)}`);
      console.error('The current key is locked to this exact payment.');
      console.error('Run "qpv resume" to try again, or "qpv cancel" to call it off.');
  }
}

async function pay(wallet, conn, payer, plan) {
  const what = describe({ ...plan, amount: plan.amount.toString() });
  console.log(`send   ${what}`);
  console.log(`to     ${plan.recipient.toBase58()}`);
  if (plan.createAccount) console.log('       (their token account will be created; the fee payer covers about 0.002 SOL rent)');
  console.log(`left   ${formatUnits(plan.left, plan.decimals)}${plan.asset === 'SOL' ? ' SOL spendable' : ''} in the vault`);
  console.log(`key    #${plan.index} (one-time)`);
  if (!(await confirm('Sign and send?'))) {
    console.log('not sent; nothing was signed');
    return;
  }
  await wallet.requireFeeFunds(conn, payer.publicKey, plan, sendOptions());
  wallet.commit(plan);
  report(await wallet.sendPending(conn, payer, sendOptions()));
}

const commands = {
  async init() {
    if (!opt.program) throw new Error('--program <program id> is required');
    if (existsSync(walletPath)) throw new Error(`${walletPath} already exists; refusing to overwrite it`);
    const url = opt.url ?? 'https://api.devnet.solana.com';
    let masterSeed;
    if (opt.seed) {
      if (!/^[0-9a-fA-F]{64}$/.test(opt.seed)) throw new Error('--seed must be 64 hex characters');
      masterSeed = Buffer.from(opt.seed, 'hex');
    }
    await requireImmutableProgram(new Connection(url, 'confirmed'), opt.program);
    const wallet = createFileWallet(walletPath, { programId: new PublicKey(opt.program), url, masterSeed });
    console.log(`wallet written to ${walletPath}`);
    if (!opt.seed) {
      console.log('\nBACK UP THIS SEED. It is the only way to recover your vault:\n');
      console.log(`  ${wallet.masterSeed.toString('hex')}\n`);
    }
    console.log(`vault address: ${wallet.address.toBase58()}`);
  },

  async address() {
    console.log(open().wallet.address.toBase58());
  },

  async open() {
    const { wallet, conn } = open();
    if ((await wallet.sync(conn)).opened) {
      console.log('the vault is already open');
      return;
    }
    console.log(`opened: ${await wallet.open(conn, feePayer())}`);
  },

  async balance() {
    const { wallet, conn } = open();
    const v = await wallet.sync(conn);
    console.log(`${formatSol(v.spendable)} SOL spendable`);
    if (v.opened) console.log(`${formatSol(v.reserve)} SOL held back as the account's permanent rent reserve`);
    else console.log(`(vault not opened yet; opening sets aside ${formatSol(v.reserve)} SOL as a rent reserve)`);
    for (const t of await wallet.holdings(conn)) {
      console.log(`${formatUnits(t.amount, t.decimals)} of token ${t.mint}${t.frozen ? '  (FROZEN by the issuer)' : ''}`);
    }
  },

  async 'token-address'() {
    const [mint] = args;
    if (!mint) throw new Error('usage: qpv token-address <mint>');
    const { wallet, conn } = open();
    const { account, created } = await wallet.openTokenAccount(conn, feePayer(), mint);
    console.log(created ? 'token account created' : 'token account already exists');
    console.log(`send this token to the vault address:   ${wallet.address.toBase58()}`);
    console.log(`or, if your wallet refuses that address, straight to its token account:   ${account.toBase58()}`);
  },

  async send() {
    const [recipient, amount] = args;
    if (!recipient || !amount) throw new Error('usage: qpv send <recipient> <SOL | all>');
    const { wallet, conn } = open();
    const payer = feePayer();
    await ensureOpened(wallet, conn, payer);
    await pay(wallet, conn, payer, await wallet.planSol(conn, recipient, amount));
  },

  async 'send-token'() {
    const [mint, recipient, amount] = args;
    if (!mint || !recipient || !amount) throw new Error('usage: qpv send-token <mint> <recipient> <amount | all>');
    const { wallet, conn } = open();
    const payer = feePayer();
    await ensureOpened(wallet, conn, payer);
    await pay(wallet, conn, payer, await wallet.planToken(conn, mint, recipient, amount));
  },

  async resume() {
    const { wallet, conn } = open();
    if (!wallet.pending) {
      console.log('nothing is pending');
      return;
    }
    report(await wallet.sendPending(conn, feePayer(), sendOptions()));
  },

  async cancel() {
    const { wallet, conn } = open();
    const p = wallet.pending;
    if (!p) {
      console.log('nothing is pending');
      return;
    }
    console.log(`cancel ${describe(p)} to ${p.recipient}`);
    if (p.exposed) {
      console.log('This payment was already broadcast, so it may still go through before the cancel does.');
    }
    if (!(await confirm('Cancel it?'))) return;
    report(await wallet.cancelPending(conn, feePayer(), sendOptions()));
  },

  async status() {
    const { wallet, conn } = open();
    const v = await wallet.sync(conn);
    console.log(`program    ${wallet.programId.toBase58()}`);
    console.log(`rpc        ${opt.url ?? wallet.state.url}`);
    console.log(`vault      ${wallet.address.toBase58()}${v.opened ? '' : '  (not opened yet)'}`);
    console.log(`spendable  ${formatSol(v.spendable)} SOL`);
    console.log(`next key   #${v.sequence}`);
    const p = wallet.pending;
    console.log(p ? `pending    ${describe(p)} to ${p.recipient} (since ${p.createdAt})` : 'pending    none');
    const label = { sent: 'sent      ', cancelled: 'cancelled ', superseded: 'NOT sent  ', unknown: 'unknown   ' };
    const why = { superseded: '(key was used by another copy of this wallet)', unknown: '(outcome could not be determined)' };
    for (const h of wallet.state.history) {
      console.log(`${label[h.outcome]} #${h.index}  ${describe(h)} to ${h.recipient}  ${h.txid ?? why[h.outcome] ?? ''}`);
    }
  },
};

if (opt.help || !command) {
  console.log(HELP);
} else if (!commands[command]) {
  console.error(`unknown command: ${command}\n\n${HELP}`);
  process.exitCode = 1;
} else {
  try {
    await commands[command]();
  } catch (error) {
    console.error(`error: ${explainError(error)}`);
    process.exitCode = 1;
  }
}
