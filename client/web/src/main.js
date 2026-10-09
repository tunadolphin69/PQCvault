// QP Vault, in a browser. One static page; nothing here talks to a server
// other than the Solana RPC endpoint the user chose.

import './polyfill.js';
import { Buffer } from 'buffer';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { Wallet, explainError, formatSol, formatUnits, randomSeed, requireImmutableProgram } from '../../src/wallet.js';
import { PROGRAM_ID, RPC_URL, explorerLink, networkOf } from './config.js';
import { builtinFeePayer, connectExtension, findExtension } from './fees.js';
import { createVault, hasVault, peek, removeVault, unlockVault } from './store.js';

// ------------------------------------------------------------ small tools

/** Build DOM without ever parsing a string as HTML. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs ?? {})) {
    if (value == null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'value') el.value = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : value);
  }
  return put(el, ...children);
}

/** Append children the way `h` does: skipping anything that is not there. */
function put(parent, ...children) {
  for (const child of children.flat(Infinity)) {
    if (child != null && child !== false) parent.append(child instanceof Node ? child : String(child));
  }
  return parent;
}

const short = (address) => `${address.slice(0, 4)}…${address.slice(-4)}`;

/** "1.5 SOL" or "250 of token Abcd…wxyz" */
const describe = (p) =>
  p.asset === 'SOL' ? `${formatSol(BigInt(p.amount))} SOL` : `${formatUnits(BigInt(p.amount), p.decimals)} of token ${short(p.asset)}`;

/** One vault operation at a time, across every tab that has this page open. */
const exclusive = (fn) => (navigator.locks ? navigator.locks.request('qpvault', fn) : fn());

// ------------------------------------------------------------------ state

const query = new URLSearchParams(location.search);

const app = {
  view: hasVault() ? 'locked' : 'welcome',
  busy: null, // text describing what is in progress
  notice: null, // { kind: 'ok' | 'error' | 'info', text, link? }
  // Chosen before a vault exists; fixed afterwards.
  setup: { programId: query.get('program') ?? PROGRAM_ID, url: query.get('rpc') ?? RPC_URL },
  wallet: null,
  conn: null,
  builtin: null, // built-in fee wallet
  extension: null, // connected wallet extension, if any
  feeMode: 'builtin',
  chain: null, // { vault, tokens, feeBalance } as last read
  form: { asset: 'SOL', recipient: '', amount: '' },
  review: null, // a plan waiting for "Sign and send"
  newSeed: null, // shown once, right after creating
  shownSeed: null,
  added: null, // { mint, account } after "Add token"
};

const feePayer = () => (app.feeMode === 'extension' && app.extension ? app.extension : app.builtin);

/** Run something slow: show progress, serialise with other tabs, surface errors. */
async function run(label, fn) {
  if (app.busy) return;
  app.busy = label;
  app.notice = null;
  render();
  try {
    await exclusive(fn);
  } catch (error) {
    app.notice = { kind: 'error', text: explainError(error) };
    // Whatever failed, show the vault as it now is, not as it was.
    if (app.view === 'main' && app.wallet) await refresh().catch(() => {});
  } finally {
    app.busy = null;
    render();
  }
}

async function refresh() {
  const { wallet, conn } = app;
  const vault = await wallet.sync(conn);
  const tokens = await wallet.holdings(conn);
  const feeBalance = BigInt(await conn.getBalance(feePayer().publicKey));
  app.chain = { vault, tokens, feeBalance };
  // Keep the send form pointing at something the vault still holds.
  if (app.form.asset !== 'SOL' && !tokens.some((t) => t.mint === app.form.asset)) app.form.asset = 'SOL';
}

function enter({ store, state, masterSeed, feeSecretKey }) {
  app.wallet = new Wallet(store, state, masterSeed);
  app.conn = new Connection(state.url, 'confirmed');
  app.builtin = builtinFeePayer(feeSecretKey);
  app.feeMode = 'builtin'; // an extension has to be connected again each visit
  app.view = 'main';
}

// ---------------------------------------------------------------- actions

async function checkSetup() {
  const { programId, url } = app.setup;
  if (!programId.trim()) throw new Error('Enter the program ID of the QP Vault deployment you want to use.');
  try {
    new PublicKey(programId.trim());
  } catch {
    throw new Error('That program ID is not a valid Solana address.');
  }
  if (!/^https?:\/\//.test(url.trim())) throw new Error('The RPC address must start with http:// or https://');
  // A vault is only as safe as its program is unchangeable. Check before creating one.
  await requireImmutableProgram(new Connection(url.trim(), 'confirmed'), programId.trim());
  return { programId: programId.trim(), url: url.trim() };
}

function checkPassword(password, again) {
  if (password.length < 8) throw new Error('Use a password of at least 8 characters.');
  if (password !== again) throw new Error('The two passwords do not match.');
}

const actions = {
  create: (password, again) =>
    run('Creating your vault…', async () => {
      const setup = await checkSetup();
      checkPassword(password, again);
      const masterSeed = randomSeed();
      const feeSecretKey = Keypair.generate().secretKey;
      const state = Wallet.initialState({ ...setup, masterSeed });
      const store = await createVault({ state, masterSeed, feeSecretKey, password });
      enter({ store, state, masterSeed, feeSecretKey });
      app.newSeed = masterSeed.toString('hex');
      app.view = 'backup';
    }),

  restore: (seedText, password, again) =>
    run('Restoring your vault…', async () => {
      const setup = await checkSetup();
      const seed = seedText.replace(/\s+/g, '');
      if (!/^[0-9a-fA-F]{64}$/.test(seed)) throw new Error('A seed is 64 characters, using only 0-9 and a-f.');
      checkPassword(password, again);
      const masterSeed = Buffer.from(seed, 'hex');
      const feeSecretKey = Keypair.generate().secretKey;
      const state = Wallet.initialState({ ...setup, masterSeed });
      const store = await createVault({ state, masterSeed, feeSecretKey, password });
      enter({ store, state, masterSeed, feeSecretKey });
      await refresh();
    }),

  unlock: (password) =>
    run('Unlocking…', async () => {
      enter(await unlockVault(password));
      app.view = 'main';
      await refresh();
    }),

  finishBackup: () =>
    run('Loading your vault…', async () => {
      app.newSeed = null;
      app.view = 'main';
      await refresh();
    }),

  refresh: () => run('Checking the network…', refresh),

  open: () =>
    run('Opening your vault on-chain…', async () => {
      await app.wallet.open(app.conn, feePayer());
      await refresh();
      app.notice = { kind: 'ok', text: 'Your vault is open.' };
    }),

  addToken: (mint) =>
    run('Preparing your vault for this token…', async () => {
      const { account } = await app.wallet.openTokenAccount(app.conn, feePayer(), mint.trim());
      app.added = { mint: mint.trim(), account: account.toBase58() };
      await refresh();
    }),

  review: () =>
    run('Checking this payment…', async () => {
      const { asset, recipient, amount } = app.form;
      if (!recipient.trim() || !amount.trim()) throw new Error('Enter who to pay and how much.');
      const plan =
        asset === 'SOL'
          ? await app.wallet.planSol(app.conn, recipient.trim(), amount.trim())
          : await app.wallet.planToken(app.conn, asset, recipient.trim(), amount.trim());
      await app.wallet.requireFeeFunds(app.conn, feePayer().publicKey, plan);
      app.review = plan;
    }),

  send: () =>
    run('Signing and sending…', async () => {
      const plan = app.review;
      app.review = null;
      // Checked again here: time has passed since the review.
      await app.wallet.requireFeeFunds(app.conn, feePayer().publicKey, plan);
      app.wallet.commit(plan);
      const paid = app.wallet.pending;
      report(await app.wallet.sendPending(app.conn, feePayer()), paid);
      app.form.recipient = '';
      app.form.amount = '';
      await refresh();
    }),

  resume: () =>
    run('Sending again…', async () => {
      const paid = app.wallet.pending;
      report(await app.wallet.sendPending(app.conn, feePayer()), paid);
      await refresh();
    }),

  cancel: () =>
    run('Cancelling…', async () => {
      const paid = app.wallet.pending;
      report(await app.wallet.cancelPending(app.conn, feePayer()), paid);
      await refresh();
    }),

  connectExtension: () =>
    run('Waiting for your wallet extension…', async () => {
      const found = findExtension();
      if (!found) throw new Error('No wallet extension was found in this browser.');
      app.extension = await connectExtension(found);
      app.feeMode = 'extension';
      await refresh();
    }),

  useBuiltin: () =>
    run('Checking the network…', async () => {
      app.feeMode = 'builtin';
      await refresh();
    }),

  showSeed: (password) =>
    run('Unlocking…', async () => {
      app.shownSeed = (await unlockVault(password)).masterSeed.toString('hex');
    }),

  lock: () => {
    Object.assign(app, { wallet: null, conn: null, builtin: null, extension: null, chain: null, review: null, shownSeed: null, notice: null, view: 'locked' });
    render();
  },

  remove: (typed) => {
    if (typed.trim().toLowerCase() !== 'remove') {
      app.notice = { kind: 'error', text: 'Type the word "remove" to confirm.' };
      render();
      return;
    }
    removeVault();
    location.replace(location.pathname + location.search);
  },
};

/** Turn the result of a send or cancel into one line for the person. */
function report(result, paid) {
  const what = describe(paid);
  const to = short(paid.recipient);
  const link = result.txid ? explorerLink(app.wallet.state.url, result.txid) : null;
  switch (result.outcome) {
    case 'sent':
      app.notice = { kind: 'ok', text: `Sent ${what} to ${to}.`, link };
      return;
    case 'cancelled':
      app.notice = { kind: 'ok', text: `Cancelled. ${what} to ${to} was not paid.`, link };
      return;
    case 'superseded':
      app.notice = { kind: 'error', text: `Not sent. Another copy of this vault used the key first, so ${what} to ${to} was never paid. Nothing was lost; send again if you still want to.` };
      return;
    case 'unknown':
      app.notice = { kind: 'error', text: `This vault has moved on too far to tell whether ${what} reached ${to}. Check their balance before sending again.` };
      return;
    default:
      app.notice = { kind: 'error', text: `Not confirmed: ${explainError(result.error)}` };
  }
}

// ------------------------------------------------------------------ views

const field = (label, input, hint) => h('label', { class: 'field' }, h('span', { class: 'field-label' }, label), input, hint && h('span', { class: 'hint' }, hint));

const button = (text, onclick, { kind = 'primary', disabled = false, id } = {}) =>
  h('button', { type: 'button', class: `button ${kind}`, onclick, disabled: disabled || Boolean(app.busy), id }, text);

function copyButton(text, label = 'Copy') {
  const el = button(label, async () => {
    await navigator.clipboard.writeText(text);
    el.textContent = 'Copied';
    setTimeout(() => (el.textContent = label), 1500);
  }, { kind: 'quiet' });
  return el;
}

const address = (text) => h('code', { class: 'address' }, text);

const groupedSeed = (seed) => h('code', { class: 'seed', id: 'seed' }, seed.match(/.{8}/g).join(' '));

function caution() {
  const url = app.wallet?.state.url ?? app.setup.url;
  const network = networkOf(url);
  return h(
    'p',
    { class: `caution ${network === 'mainnet' ? 'severe' : ''}`, role: 'note' },
    network === 'mainnet'
      ? 'This is mainnet, with real money, and this software is experimental and unaudited. A bug could lose everything you put in.'
      : 'Experimental and unaudited software. Use it to try things out, not to hold money you cannot afford to lose.',
  );
}

function masthead() {
  const url = app.wallet?.state.url ?? peek()?.url ?? app.setup.url;
  return h('header', { class: 'masthead' }, h('h1', null, 'QP Vault'), h('p', { class: 'network' }, networkOf(url)));
}

function statusLine() {
  const live = h('div', { class: 'status', role: 'status', 'aria-live': 'polite' });
  if (app.busy) live.append(h('p', { class: 'notice working' }, app.busy));
  else if (app.notice) {
    live.append(
      h(
        'p',
        { class: `notice ${app.notice.kind}`, id: 'notice' },
        app.notice.text,
        app.notice.link && [' ', h('a', { href: app.notice.link, target: '_blank', rel: 'noreferrer noopener' }, 'View the transaction')],
      ),
    );
  }
  return live;
}

function setupFields() {
  // Settings that came in through the link, not from this site or the person.
  const fromLink = (query.has('program') && query.get('program') !== PROGRAM_ID) || (query.has('rpc') && query.get('rpc') !== RPC_URL);
  return [
    fromLink &&
      h('p', { class: 'hint warn', id: 'link-warning' }, 'The link you opened chose the program and network below. A vault is only as trustworthy as its program, so continue only if you trust where the link came from.'),
    !PROGRAM_ID && !fromLink && h('p', { class: 'hint' }, 'This copy of the page has no program built in. Enter the ID of a QP Vault program you trust.'),
    setupDetails(fromLink),
  ];
}

function setupDetails(fromLink) {
  return h(
    'details',
    { class: 'advanced', open: !app.setup.programId || fromLink || undefined },
    h('summary', null, 'Network settings'),
    field(
      'Program ID',
      h('input', { type: 'text', id: 'program-id', 'data-bound': '1', spellcheck: 'false', autocomplete: 'off', value: app.setup.programId, oninput: (e) => (app.setup.programId = e.target.value) }),
      'The on-chain address of the QP Vault program. Your vault address depends on it.',
    ),
    field(
      'RPC address',
      h('input', { type: 'url', id: 'rpc-url', 'data-bound': '1', spellcheck: 'false', autocomplete: 'off', value: app.setup.url, oninput: (e) => (app.setup.url = e.target.value) }),
      'The Solana node this page reads from and sends through.',
    ),
  );
}

function passwordFields() {
  return [
    field('Password', h('input', { type: 'password', id: 'password', autocomplete: 'new-password' }), 'Encrypts your vault in this browser. At least 8 characters. It cannot be reset.'),
    field('Password again', h('input', { type: 'password', id: 'password-again', autocomplete: 'new-password' })),
  ];
}

const value = (id) => document.getElementById(id)?.value ?? '';

const views = {
  welcome: () =>
    h(
      'main',
      null,
      h('p', { class: 'lede' }, 'A vault for SOL and tokens that only a hash-based one-time signature can open. Your keys are made and kept in this browser.'),
      h('div', { class: 'choices' }, button('Create a new vault', () => ((app.view = 'create'), render()), { id: 'go-create' }), button('Restore from a seed', () => ((app.view = 'restore'), render()), { kind: 'secondary', id: 'go-restore' })),
    ),

  create: () =>
    h(
      'main',
      null,
      h('h2', null, 'Create a new vault'),
      h('form', { class: 'stack', onsubmit: (e) => (e.preventDefault(), actions.create(value('password'), value('password-again'))) }, passwordFields(), setupFields(), h('div', { class: 'row' }, h('button', { type: 'submit', class: 'button primary', id: 'create', disabled: Boolean(app.busy) }, 'Create vault'), button('Back', () => ((app.view = 'welcome'), render()), { kind: 'quiet' }))),
    ),

  restore: () =>
    h(
      'main',
      null,
      h('h2', null, 'Restore from a seed'),
      h(
        'form',
        { class: 'stack', onsubmit: (e) => (e.preventDefault(), actions.restore(value('restore-seed'), value('password'), value('password-again'))) },
        field('Seed', h('textarea', { id: 'restore-seed', rows: '3', spellcheck: 'false', autocomplete: 'off' }), 'The 64 characters you saved when the vault was created.'),
        passwordFields(),
        setupFields(),
        h('div', { class: 'row' }, h('button', { type: 'submit', class: 'button primary', id: 'restore', disabled: Boolean(app.busy) }, 'Restore vault'), button('Back', () => ((app.view = 'welcome'), render()), { kind: 'quiet' })),
      ),
    ),

  backup: () => {
    const ok = h('input', { type: 'checkbox', id: 'saved', onchange: () => (next.disabled = !ok.checked) });
    const next = button('Continue to my vault', actions.finishBackup, { disabled: true, id: 'backup-done' });
    return h(
      'main',
      null,
      h('h2', null, 'Save your seed'),
      h('p', null, 'This seed is your vault. Anyone who has it can spend from the vault, and without it nobody can, including you. It is shown once.'),
      groupedSeed(app.newSeed),
      h('div', { class: 'row' }, copyButton(app.newSeed, 'Copy seed')),
      h('p', null, 'Write it down or store it somewhere offline. Your password only protects the copy in this browser; it cannot recover a lost seed.'),
      h('label', { class: 'check' }, ok, 'I have saved this seed somewhere safe.'),
      h('div', { class: 'row' }, next),
    );
  },

  locked: () => {
    const info = peek();
    return h(
      'main',
      null,
      h('h2', null, 'Unlock your vault'),
      address(info.address),
      h('form', { class: 'stack', onsubmit: (e) => (e.preventDefault(), actions.unlock(value('unlock-password'))) }, field('Password', h('input', { type: 'password', id: 'unlock-password', autocomplete: 'current-password', autofocus: true })), h('div', { class: 'row' }, h('button', { type: 'submit', class: 'button primary', id: 'unlock', disabled: Boolean(app.busy) }, 'Unlock'))),
      removal('Forgot the password? Remove this vault from the browser, then restore it from your seed.'),
    );
  },

  main: () => h('main', null, pendingBlock(), vaultSection(), holdingsSection(), sendSection(), feeSection(), activitySection(), housekeeping()),
};

function removal(lead) {
  return h(
    'details',
    { class: 'advanced' },
    h('summary', null, 'Remove this vault from this browser'),
    h('p', { class: 'hint' }, lead),
    h('p', { class: 'hint warn' }, 'This deletes the encrypted seed stored here. Without your written-down seed, the funds in the vault are gone for good.'),
    field('Type "remove" to confirm', h('input', { type: 'text', id: 'remove-confirm', autocomplete: 'off' })),
    h('div', { class: 'row' }, button('Remove vault', () => actions.remove(value('remove-confirm')), { kind: 'danger', id: 'remove' })),
  );
}

/** The one-time keys: used, current, still to come. */
function keyStrip() {
  const next = Math.max(app.chain?.vault.sequence ?? 0, app.wallet.state.sequence);
  const locked = Boolean(app.wallet.pending);
  const strip = h('ol', { class: 'keys', 'aria-label': `${next} keys used. Key ${next} signs the next payment.` });
  for (let i = Math.max(0, next - 8); i < next; i++) strip.append(h('li', { class: 'key used', title: `Key ${i}: used` }));
  strip.append(h('li', { class: `key current ${locked ? 'locked' : ''}`, id: 'current-key' }, String(next)));
  for (let i = 0; i < 5; i++) strip.append(h('li', { class: 'key ahead' }));
  return h(
    'div',
    { class: 'keyline' },
    strip,
    h('p', { class: 'hint' }, locked ? `Key ${next} is locked to the payment above until it is sent or cancelled.` : `Key ${next} signs your next payment. Each key is used once, then retired.`),
  );
}

function vaultSection() {
  const text = app.wallet.address.toBase58();
  return h(
    'section',
    { 'aria-labelledby': 'vault-h' },
    h('h2', { id: 'vault-h' }, 'Your vault'),
    h('div', { class: 'address-row' }, h('code', { class: 'address', id: 'vault-address' }, text), copyButton(text)),
    h('p', { class: 'hint' }, 'This address never changes. Send SOL to it from any wallet or exchange.'),
    keyStrip(),
  );
}

function holdingsSection() {
  const chain = app.chain;
  const section = h('section', { 'aria-labelledby': 'hold-h' }, h('div', { class: 'heading-row' }, h('h2', { id: 'hold-h' }, 'Holdings'), button('Refresh', actions.refresh, { kind: 'quiet', id: 'refresh' })));
  if (!chain) {
    put(section, h('p', { class: 'hint' }, 'Not loaded yet.'));
    return section;
  }
  const { vault, tokens } = chain;
  put(section, 
    h('p', { class: 'balance' }, h('span', { class: 'figure', id: 'sol-balance' }, formatSol(vault.spendable)), ' SOL'),
    vault.opened
      ? h('p', { class: 'hint' }, `Plus ${formatSol(vault.reserve)} SOL that stays in the vault for good, as Solana's rent deposit.`)
      : h('p', { class: 'hint' }, `The vault has not been opened on-chain yet. Opening sets aside ${formatSol(vault.reserve)} SOL as Solana's rent deposit.`),
  );
  if (!vault.opened) put(section, h('div', { class: 'row' }, button('Open vault', actions.open, { id: 'open-vault' })));

  if (tokens.length > 0) {
    const list = h('ul', { class: 'tokens' });
    for (const t of tokens) {
      list.append(
        h(
          'li',
          { 'data-mint': t.mint },
          h('span', { class: 'figure' }, formatUnits(t.amount, t.decimals)),
          h('span', { class: 'token-name' }, 'token ', h('code', { title: t.mint }, short(t.mint)), t.frozen && h('strong', { class: 'flag' }, ' frozen by its issuer')),
          copyButton(t.account, 'Copy token account'),
        ),
      );
    }
    put(section, list);
  }

  put(section, 
    h(
      'details',
      { class: 'advanced', open: app.added ? true : undefined },
      h('summary', null, 'Receive a token'),
      h('p', { class: 'hint' }, 'A vault needs a token account for each kind of token before it can receive it. Creating one costs the fee wallet about 0.002 SOL.'),
      h('form', { class: 'inline', onsubmit: (e) => (e.preventDefault(), actions.addToken(value('add-mint'))) }, field('Token mint address', h('input', { type: 'text', id: 'add-mint', spellcheck: 'false', autocomplete: 'off' })), h('button', { type: 'submit', class: 'button secondary', id: 'add-token', disabled: Boolean(app.busy) }, 'Add token')),
      app.added && h('p', { class: 'hint', id: 'added-token' }, 'Ready. Send this token to your vault address. If the sending wallet refuses that address, send it to this token account instead: ', address(app.added.account)),
    ),
  );
  return section;
}

function sendSection() {
  const section = h('section', { 'aria-labelledby': 'send-h' }, h('h2', { id: 'send-h' }, 'Send'));
  const chain = app.chain;
  if (app.wallet.pending) return put(section, h('p', { class: 'hint' }, 'Finish or cancel the payment above before starting another.')), section;
  if (!chain) return section;
  if (!chain.vault.opened) return put(section, h('p', { class: 'hint' }, 'Open the vault first.')), section;

  if (app.review) {
    const plan = app.review;
    const what = describe({ ...plan, amount: plan.amount.toString() });
    put(section, 
      h(
        'div',
        { class: 'review', id: 'review' },
        h('dl', null, h('dt', null, 'Send'), h('dd', null, what), h('dt', null, 'To'), h('dd', null, address(plan.recipient.toBase58())), h('dt', null, 'Left in the vault'), h('dd', null, `${formatUnits(plan.left, plan.decimals)}${plan.asset === 'SOL' ? ' SOL' : ''}`), h('dt', null, 'Signed with'), h('dd', null, `key ${plan.index}, which is then retired`)),
        plan.createAccount && h('p', { class: 'hint' }, 'They have no account for this token yet. One is created in the same transaction; the fee wallet pays about 0.002 SOL for it.'),
        h('p', { class: 'hint' }, 'Check the address. Once sent, a payment cannot be reversed.'),
        h('div', { class: 'row' }, button('Sign and send', actions.send, { id: 'sign-send' }), button('Back', () => ((app.review = null), render()), { kind: 'quiet' })),
      ),
    );
    return section;
  }

  const assets = [h('option', { value: 'SOL', selected: app.form.asset === 'SOL' }, `SOL (${formatSol(chain.vault.spendable)} available)`)];
  for (const t of chain.tokens) {
    if (t.amount > 0n) assets.push(h('option', { value: t.mint, selected: app.form.asset === t.mint }, `Token ${short(t.mint)} (${formatUnits(t.amount, t.decimals)} available)`));
  }
  const amount = h('input', { type: 'text', id: 'amount', 'data-bound': '1', inputmode: 'decimal', autocomplete: 'off', value: app.form.amount, oninput: (e) => (app.form.amount = e.target.value) });
  put(section, 
    h(
      'form',
      { class: 'stack', onsubmit: (e) => (e.preventDefault(), actions.review()) },
      field('What', h('select', { id: 'asset', onchange: (e) => (app.form.asset = e.target.value) }, assets)),
      field('To', h('input', { type: 'text', id: 'recipient', 'data-bound': '1', spellcheck: 'false', autocomplete: 'off', value: app.form.recipient, oninput: (e) => (app.form.recipient = e.target.value) }), 'A Solana wallet address.'),
      field('Amount', h('div', { class: 'with-button' }, amount, button('All', () => ((app.form.amount = 'all'), (amount.value = 'all')), { kind: 'quiet', id: 'amount-all' }))),
      h('div', { class: 'row' }, h('button', { type: 'submit', class: 'button primary', id: 'review-payment', disabled: Boolean(app.busy) }, 'Review payment')),
    ),
  );
  return section;
}

function pendingBlock() {
  const p = app.wallet.pending;
  if (!p) return null;
  return h(
    'section',
    { class: 'pending', id: 'pending', 'aria-labelledby': 'pend-h' },
    h('h2', { id: 'pend-h' }, 'A payment has not gone through'),
    h('p', null, `${describe(p)} to `, address(p.recipient)),
    h('p', { class: 'hint' }, p.exposed ? 'It was already handed off, so it may still arrive. Try again to send exactly this payment, or cancel it. Nothing else can leave the vault until one of those works.' : 'It was never sent. Try again, or cancel it at no cost.'),
    h('div', { class: 'row' }, button('Try again', actions.resume, { id: 'resume' }), button('Cancel payment', actions.cancel, { kind: 'secondary', id: 'cancel' })),
  );
}

function feeSection() {
  const section = h('section', { 'aria-labelledby': 'fee-h' }, h('h2', { id: 'fee-h' }, 'Network fees'));
  const found = findExtension();
  const payer = feePayer();
  const balance = app.chain ? `${formatSol(app.chain.feeBalance)} SOL` : '';
  put(section, h('p', { class: 'hint' }, 'Every Solana transaction needs an ordinary wallet to pay a small fee, about 0.000005 SOL. It cannot touch what is in the vault.'));
  if (app.feeMode === 'extension' && app.extension) {
    put(section, 
      h('p', null, `Paid by ${app.extension.name}: `, address(payer.publicKey.toBase58()), ' ', h('span', { id: 'fee-balance' }, balance)),
      h('p', { class: 'hint' }, `${app.extension.name} will ask you to approve each payment. It sees the payment before you approve, so a payment you decline there still has to be cancelled here.`),
      h('div', { class: 'row' }, button('Use the built-in fee wallet instead', actions.useBuiltin, { kind: 'quiet', id: 'use-builtin' })),
    );
  } else {
    const text = app.builtin.publicKey.toBase58();
    const low = app.chain && app.chain.feeBalance < 3_000_000n;
    put(section, 
      h('p', null, 'Paid by a small fee wallet kept in this browser. It holds ', h('span', { id: 'fee-balance' }, balance), '.'),
      h('div', { class: 'address-row' }, h('code', { class: 'address', id: 'fee-address' }, text), copyButton(text)),
      low && h('p', { class: 'hint warn' }, 'It is running low. Send about 0.01 SOL to the address above to cover fees.'),
      found && h('div', { class: 'row' }, button(`Pay fees with ${found.name} instead`, actions.connectExtension, { kind: 'quiet', id: 'connect-extension' })),
    );
  }
  return section;
}

function activitySection() {
  const history = app.wallet.state.history;
  const section = h('section', { 'aria-labelledby': 'act-h' }, h('h2', { id: 'act-h' }, 'Activity'));
  if (history.length === 0) return put(section, h('p', { class: 'hint' }, 'Payments you make from this browser will be listed here.')), section;
  const words = { sent: 'Sent', cancelled: 'Cancelled', superseded: 'Not sent', unknown: 'Unknown' };
  const list = h('ol', { class: 'activity', reversed: true });
  for (const item of [...history].reverse()) {
    const link = item.txid ? explorerLink(app.wallet.state.url, item.txid) : null;
    list.append(
      h(
        'li',
        { class: item.outcome },
        h('span', { class: 'outcome' }, words[item.outcome] ?? item.outcome),
        h('span', null, describe(item), ' to ', h('code', { title: item.recipient }, short(item.recipient))),
        h('span', { class: 'hint' }, `key ${item.index}`, link && [' ', h('a', { href: link, target: '_blank', rel: 'noreferrer noopener' }, 'transaction')]),
      ),
    );
  }
  put(section, list);
  return section;
}

function housekeeping() {
  const { programId, url } = app.wallet.state;
  return h(
    'section',
    { class: 'housekeeping', 'aria-labelledby': 'keep-h' },
    h('h2', { id: 'keep-h' }, 'This browser'),
    h('div', { class: 'row' }, button('Lock', actions.lock, { kind: 'secondary', id: 'lock' })),
    h(
      'details',
      { class: 'advanced', open: app.shownSeed ? true : undefined },
      h('summary', null, 'Show my seed'),
      app.shownSeed
        ? [groupedSeed(app.shownSeed), h('div', { class: 'row' }, copyButton(app.shownSeed, 'Copy seed'), button('Hide', () => ((app.shownSeed = null), render()), { kind: 'quiet' }))]
        : h('form', { class: 'inline', onsubmit: (e) => (e.preventDefault(), actions.showSeed(value('seed-password'))) }, field('Password', h('input', { type: 'password', id: 'seed-password', autocomplete: 'current-password' })), h('button', { type: 'submit', class: 'button secondary', id: 'show-seed', disabled: Boolean(app.busy) }, 'Show seed')),
    ),
    removal('Do this before handing the device to someone else, or to start over.'),
    h('dl', { class: 'facts' }, h('dt', null, 'Program'), h('dd', null, address(programId)), h('dt', null, 'RPC'), h('dd', null, address(url))),
  );
}

function render() {
  const root = document.getElementById('app');
  // Redrawing must not wipe what someone has typed (a password, a seed) just
  // because an error message appeared. Fields tied to `app` restore themselves.
  const typed = new Map();
  for (const el of root.querySelectorAll('input[id], textarea[id]')) {
    if (!el.dataset.bound) typed.set(el.id, el.type === 'checkbox' ? el.checked : el.value);
  }
  // Nor should it snap shut a section someone opened.
  const label = (details) => details.querySelector('summary')?.textContent;
  const opened = new Set([...root.querySelectorAll('details[open]')].map(label));
  const focused = document.activeElement?.id;
  root.replaceChildren(masthead(), caution(), statusLine(), views[app.view]());
  for (const details of root.querySelectorAll('details')) {
    if (opened.has(label(details))) details.open = true;
  }
  for (const [id, was] of typed) {
    const el = document.getElementById(id);
    if (!el) continue;
    if (el.type === 'checkbox') {
      el.checked = was;
      el.dispatchEvent(new Event('change'));
    } else el.value = was;
  }
  if (focused) document.getElementById(focused)?.focus();
}

render();
// Another tab may have changed things; show the current picture when this one is looked at again.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && app.view === 'main' && !app.busy) actions.refresh();
});
