// Drives the built web wallet in a real (headless) browser against a real
// validator.
//
//   ./scripts/localnet.sh                       (terminal 1, from the repo root)
//   npm run web:build                           (from client/)
//   QPV_PROGRAM=<program id> npm run web:e2e    (from client/)
//
// Env: QPV_URL (default http://127.0.0.1:8899), QPV_PROGRAM, QPV_CHROME (path
// to a Chromium binary, if Playwright's own is not installed), QPV_SHOTS (a
// directory to write screenshots into).

import assert from 'node:assert/strict';
import { createReadStream, existsSync, mkdirSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Connection, Keypair, LAMPORTS_PER_SOL, Message, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction } from '@solana/web3.js';
import { TOKEN_2022_PROGRAM_ID, createMint, freezeAccount, getAccount, getAssociatedTokenAddressSync, mintTo, thawAccount } from '@solana/spl-token';
import { chromium } from 'playwright-core';
import { deriveVaultKey, vaultAddress } from '../src/vault.js';

const rpc = process.env.QPV_URL ?? 'http://127.0.0.1:8899';
if (!process.env.QPV_PROGRAM) throw new Error('set QPV_PROGRAM to the deployed program id');
const programId = new PublicKey(process.env.QPV_PROGRAM);
const conn = new Connection(rpc, 'confirmed');
const shots = process.env.QPV_SHOTS;
if (shots) mkdirSync(shots, { recursive: true });

const SOL = BigInt(LAMPORTS_PER_SOL);
const PASSWORD = 'correct horse battery';
const payer = Keypair.generate();
const friend = Keypair.generate().publicKey;
const balance = async (pk) => BigInt(await conn.getBalance(pk));
const token2022 = [undefined, { commitment: 'confirmed' }, TOKEN_2022_PROGRAM_ID];

let passed = 0;
const ok = (name) => {
  passed++;
  console.log(`  ok  ${name}`);
};

// ------------------------------------------------ serve the built site
const site = fileURLToPath(new URL('../../docs/', import.meta.url));
if (!existsSync(join(site, 'index.html'))) throw new Error('run "npm run web:build" first');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2' };
const server = createServer((req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname));
  const file = join(site, path === '/' ? 'index.html' : path);
  if (!file.startsWith(site) || !existsSync(file) || !statSync(file).isFile()) return res.writeHead(404).end();
  res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' });
  createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const start = `${origin}/?program=${programId.toBase58()}&rpc=${encodeURIComponent(rpc)}`;

// -------------------------------------------------------------- helpers
const browser = await chromium.launch({ executablePath: process.env.QPV_CHROME || undefined });
const problems = [];

async function newPage(context) {
  const page = await context.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    // Failed RPC calls the wallet handles are logged by the browser as "Failed to load resource"; those are expected in the negative tests.
    if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) problems.push(`console: ${m.text()}`);
  });
  page.setDefaultTimeout(60_000);
  return page;
}

const text = (page, sel) => page.locator(sel).innerText();
const shot = async (page, name) => shots && page.screenshot({ path: join(shots, `${name}.png`), fullPage: true });

/** Wait until nothing is in progress, then return the notice text ('' if none). */
async function settled(page) {
  await page.waitForFunction(() => !document.querySelector('.notice.working'));
  return (await page.locator('#notice').count()) ? text(page, '#notice') : '';
}

async function refresh(page) {
  await page.click('#refresh');
  return settled(page);
}

async function pay(page, { asset = 'SOL', to, amount }) {
  await page.selectOption('#asset', asset);
  await page.fill('#recipient', to);
  await page.fill('#amount', amount);
  await page.click('#review-payment');
  return settled(page);
}

async function send(page, payment) {
  const note = await pay(page, payment);
  assert.equal(note, '', `review failed: ${note}`);
  await page.waitForSelector('#review');
  await page.click('#sign-send');
  return settled(page);
}

async function deposit(to, lamports) {
  await sendAndConfirmTransaction(conn, new Transaction().add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: to, lamports })), [payer]);
}

const tokens = async (account) => {
  try {
    return (await getAccount(conn, account, 'confirmed', TOKEN_2022_PROGRAM_ID)).amount;
  } catch {
    return 0n;
  }
};

console.log(`web wallet at ${origin}, program ${programId.toBase58()} on ${rpc}`);
{
  const sig = await conn.requestAirdrop(payer.publicKey, 100 * LAMPORTS_PER_SOL);
  await conn.confirmTransaction({ signature: sig, ...(await conn.getLatestBlockhash()) });
}
const reserve = BigInt(await conn.getMinimumBalanceForRentExemption(107));

// ============================================================ first visit
console.log('\ncreating a vault');
const contextA = await browser.newContext({ viewport: { width: 760, height: 900 } });
const page = await newPage(contextA);
await page.goto(start);
await page.waitForSelector('#go-create');
await shot(page, '1-welcome');
await page.click('#go-create');
assert.equal(await page.inputValue('#program-id'), programId.toBase58());
assert.match(await text(page, '#link-warning'), /only if you trust where the link came from/);

// The page refuses to build a vault on a program that is missing or can still be changed.
await page.fill('#password', PASSWORD);
await page.fill('#password-again', PASSWORD);
await page.fill('#program-id', Keypair.generate().publicKey.toBase58());
await page.click('#create');
assert.match(await settled(page), /there is no program at/);
if (process.env.QPV_UPGRADEABLE_PROGRAM) {
  await page.fill('#program-id', process.env.QPV_UPGRADEABLE_PROGRAM);
  await page.click('#create');
  assert.match(await settled(page), /can still be changed by whoever holds/);
  ok('a program that is missing, or that its deployer can still change, is refused');
} else console.log('  --  skipped the upgradeable-program check (set QPV_UPGRADEABLE_PROGRAM)');
assert.equal(await page.evaluate(() => localStorage.getItem('qpvault:v1')), null);
await page.fill('#program-id', programId.toBase58());

await page.fill('#password', 'short');
await page.fill('#password-again', 'short');
await page.click('#create');
assert.match(await settled(page), /at least 8 characters/);
await page.fill('#password', PASSWORD);
await page.fill('#password-again', 'something else');
await page.click('#create');
assert.match(await settled(page), /do not match/);
ok('weak or mistyped passwords are refused');

await page.fill('#password', PASSWORD);
await page.fill('#password-again', PASSWORD);
await page.click('#create');
await page.waitForSelector('#seed');
const seed = (await text(page, '#seed')).replace(/\s+/g, '');
assert.match(seed, /^[0-9a-f]{64}$/);
await shot(page, '2-save-your-seed');
assert.equal(await page.isDisabled('#backup-done'), true);
await page.check('#saved');
await page.click('#backup-done');
await page.waitForSelector('#vault-address');
await settled(page);

const vault = new PublicKey(await text(page, '#vault-address'));
const expected = vaultAddress(programId, deriveVaultKey(Buffer.from(seed, 'hex'), 0).keyHash);
assert.equal(vault.toBase58(), expected.toBase58());
ok('the browser derives the same vault address as the command line tool');

const stored = await page.evaluate(() => localStorage.getItem('qpvault:v1'));
assert(stored.includes(vault.toBase58()));
assert(!stored.includes(seed), 'the seed is stored in the clear');
assert.match(stored, /"kdf":"PBKDF2-SHA256","iterations":600000/);
ok('the seed is stored encrypted, never in the clear');

// ====================================================== fund, open, send
console.log('\nSOL');
const feeA = new PublicKey(await text(page, '#fee-address'));
await deposit(vault, 2n * SOL);
assert.equal(await page.locator('#review-payment').count(), 0); // nothing to send from until the vault is open
await refresh(page);
assert.equal(await text(page, '#sol-balance'), '1.9983644');

await page.click('#open-vault');
assert.match(await settled(page), /fee wallet does not have enough SOL/);
ok('opening with an empty fee wallet fails with a readable message');
await deposit(feeA, SOL / 20n);
await refresh(page);
await page.click('#open-vault');
assert.match(await settled(page), /Your vault is open/);
assert.equal(await text(page, '#sol-balance'), '1.9983644');
assert.equal(await balance(vault), 2n * SOL);
await shot(page, '3-vault-open');

assert.match(await pay(page, { to: friend.toBase58(), amount: '5' }), /cannot send/);
assert.match(await pay(page, { to: 'not an address', amount: '1' }), /./);
assert.match(await pay(page, { to: programId.toBase58(), amount: '1' }), /not an ordinary wallet/);
assert.equal(await page.locator('#pending').count(), 0);
ok('bad payments are refused at review, before anything is signed');

assert.equal(await pay(page, { to: friend.toBase58(), amount: '0.25' }), '');
await page.waitForSelector('#review');
await shot(page, '4-review');
await page.click('#sign-send');
assert.match(await settled(page), /^Sent 0\.25 SOL to /);
assert.equal(await balance(friend), SOL / 4n);
assert.equal(await text(page, '#current-key'), '1');
assert.equal(await text(page, '#sol-balance'), '1.7483644');
ok('0.25 SOL sent; the key counter moves to 1');

// ================================================================ tokens
console.log('\ntokens (Token-2022)');
const mint = await createMint(conn, payer, payer.publicKey, payer.publicKey, 6, ...token2022);
const source = getAssociatedTokenAddressSync(mint, vault, true, TOKEN_2022_PROGRAM_ID);
const friendTokens = getAssociatedTokenAddressSync(mint, friend, true, TOKEN_2022_PROGRAM_ID);
await page.click('summary:has-text("Receive a token")');
await page.fill('#add-mint', mint.toBase58());
await page.click('#add-token');
await settled(page);
assert((await text(page, '#added-token')).includes(source.toBase58()));
await mintTo(conn, payer, mint, source, payer, 1000_000000n, [], token2022[1], TOKEN_2022_PROGRAM_ID);
await refresh(page);
assert.match(await text(page, `li[data-mint="${mint.toBase58()}"]`), /^1000\b/);
ok('the vault gets a token account and shows what arrives');

assert.equal(await pay(page, { asset: mint.toBase58(), to: friend.toBase58(), amount: '250.5' }), '');
assert.match(await text(page, '#review'), /no account for this token yet/);
await page.click('#sign-send');
assert.match(await settled(page), /^Sent 250\.5 of token /);
assert.equal(await tokens(friendTokens), 250_500000n);
ok('250.5 tokens sent to a recipient who had no token account');

// A payment that cannot succeed: the issuer freezes the vault's account after review.
assert.equal(await pay(page, { asset: mint.toBase58(), to: friend.toBase58(), amount: '40' }), '');
await freezeAccount(conn, payer, source, mint, payer, [], token2022[1], TOKEN_2022_PROGRAM_ID);
await page.click('#sign-send');
assert.match(await settled(page), /Not confirmed: Account is frozen/);
await page.waitForSelector('#pending');
assert.match(await text(page, '#pending'), /40 of token/);
assert.match(await text(page, '#send-h + p'), /Finish or cancel/);
await shot(page, '5-stuck-payment');
await page.click('#resume');
assert.match(await settled(page), /Not confirmed: Account is frozen/);
await page.click('#cancel');
assert.match(await settled(page), /^Cancelled\. 40 of token/);
assert.equal(await page.locator('#pending').count(), 0);
assert.equal(await text(page, '#current-key'), '3');
assert.equal(await tokens(friendTokens), 250_500000n);
assert.match(await text(page, `li[data-mint="${mint.toBase58()}"]`), /frozen by its issuer/);
ok('a payment stuck on a frozen account is retried, then cancelled, and the vault moves on');

await thawAccount(conn, payer, source, mint, payer, [], token2022[1], TOKEN_2022_PROGRAM_ID);
await refresh(page);
assert.match(await send(page, { asset: mint.toBase58(), to: friend.toBase58(), amount: 'all' }), /^Sent 749\.5 of token /);
assert.equal(await tokens(friendTokens), 1000_000000n);
ok('after the thaw, the rest of the tokens are sent with the next key');

// ====================================================== lock and unlock
console.log('\nlocking');
await page.reload();
await page.waitForSelector('#unlock-password');
assert.equal(await page.locator('#vault-address').count(), 0);
await page.fill('#unlock-password', 'wrong password');
await page.click('#unlock');
assert.match(await settled(page), /wrong password/);
await page.fill('#unlock-password', PASSWORD);
await page.click('#unlock');
await page.waitForSelector('#vault-address');
await settled(page);
assert.equal(await text(page, '#current-key'), '4');
assert.equal((await page.locator('.activity li').allInnerTexts()).map((t) => t.split(/\s/)[0]).join(','), 'Sent,Cancelled,Sent,Sent');
ok('reloading locks the vault; only the right password opens it; history survives');

await page.click('summary:has-text("Show my seed")');
await page.fill('#seed-password', PASSWORD);
await page.click('#show-seed');
await page.waitForSelector('#seed');
assert.equal((await text(page, '#seed')).replace(/\s+/g, ''), seed);
await page.click('button:has-text("Hide")');
ok('the seed can be shown again with the password');
await shot(page, '6-vault');

// ============================================== restore on another device
console.log('\nrestoring in a second browser');
const contextB = await browser.newContext({ viewport: { width: 390, height: 844 } });
const pageB = await newPage(contextB);
await pageB.goto(start);
await pageB.click('#go-restore');
await pageB.fill('#restore-seed', 'not a seed');
await pageB.fill('#password', PASSWORD);
await pageB.fill('#password-again', PASSWORD);
await pageB.click('#restore');
assert.match(await settled(pageB), /64 characters/);
await pageB.fill('#restore-seed', seed.match(/.{8}/g).join(' '));
await pageB.click('#restore');
await pageB.waitForSelector('#vault-address');
await settled(pageB);
assert.equal(await text(pageB, '#vault-address'), vault.toBase58());
assert.equal(await text(pageB, '#current-key'), '4');
assert.equal(await text(pageB, '#sol-balance'), '1.7483644');
ok('a restore lands on the same address and picks up at key 4 from the chain');

const feeB = new PublicKey(await text(pageB, '#fee-address'));
assert.notEqual(feeB.toBase58(), feeA.toBase58());
assert.match(await pay(pageB, { to: friend.toBase58(), amount: '0.1' }), /fee wallet needs at least/);
assert.equal(await pageB.locator('#pending').count(), 0);
ok('an unfunded fee wallet is caught at review, so no key gets locked');
await deposit(feeB, SOL / 20n);
await refresh(pageB);
assert.match(await send(pageB, { to: friend.toBase58(), amount: '0.1' }), /^Sent 0\.1 SOL/);
await shot(pageB, '7-phone-width');

// The first browser had a payment under review with the key the second one just used.
assert.equal(await pay(page, { to: friend.toBase58(), amount: '0.2' }), '');
await page.waitForSelector('#review');
assert.match(await send(pageB, { to: friend.toBase58(), amount: '0.05' }), /^Sent 0\.05 SOL/);
await page.click('#sign-send');
assert.match(await settled(page), /^Not sent\. Another copy of this vault used the key first, so 0\.2 SOL/);
assert.equal(await page.locator('#pending').count(), 0);
assert.equal(await text(page, '#current-key'), '6');
assert.match(await text(page, '.activity li >> nth=0'), /^Not sent/);
assert.equal(await balance(friend), SOL / 4n + SOL / 10n + SOL / 20n);
ok('two browsers on one seed: the stale one signs nothing, says so, and catches up');

// =========================================================== two tabs
console.log('\ntwo tabs in one browser');
const tab2 = await newPage(contextA);
await tab2.goto(start);
await tab2.fill('#unlock-password', PASSWORD);
await tab2.click('#unlock');
await tab2.waitForSelector('#vault-address');
await settled(tab2);
assert.equal(await pay(page, { to: friend.toBase58(), amount: '0.01' }), '');
await page.waitForSelector('#review');
assert.match(await send(tab2, { to: friend.toBase58(), amount: '0.02' }), /^Sent 0\.02 SOL/);
await page.click('#sign-send');
assert.match(await settled(page), /changed since this payment was reviewed/);
assert.equal(await page.locator('#pending').count(), 0);
assert.equal(await text(page, '#current-key'), '7');
ok('two tabs share one lock: the second cannot sign with a key the first used');
await tab2.close();

// ============================================= a wallet extension pays
console.log('\nfees paid by a wallet extension (a stand-in for Phantom)');
const extensionKey = Keypair.generate();
await deposit(extensionKey.publicKey, SOL / 10n);
let reject = false;
let asked = 0;
const contextC = await browser.newContext({ viewport: { width: 760, height: 900 } });
await contextC.exposeFunction('__extensionAddress', () => extensionKey.publicKey.toBase58());
await contextC.exposeFunction('__extensionSign', (message) => {
  asked++;
  if (reject) return { rejected: true };
  const tx = Transaction.populate(Message.from(Buffer.from(message)));
  tx.partialSign(extensionKey);
  return { signature: Array.from(tx.signature) };
});
await contextC.addInitScript(() => {
  window.phantom = {
    solana: {
      isPhantom: true,
      publicKey: null,
      async connect() {
        const address = await window.__extensionAddress();
        this.publicKey = { toString: () => address };
        return { publicKey: this.publicKey };
      },
      async signTransaction(tx) {
        const result = await window.__extensionSign(Array.from(tx.serializeMessage()));
        if (result.rejected) throw Object.assign(new Error('User rejected the request.'), { code: 4001 });
        tx.addSignature(tx.feePayer, globalThis.Buffer.from(result.signature));
        return tx;
      },
    },
  };
});
const pageC = await newPage(contextC);
await pageC.goto(start);
await pageC.click('#go-restore');
await pageC.fill('#restore-seed', seed);
await pageC.fill('#password', PASSWORD);
await pageC.fill('#password-again', PASSWORD);
await pageC.click('#restore');
await pageC.waitForSelector('#vault-address');
await settled(pageC);
await pageC.click('#connect-extension');
await settled(pageC);
assert.match(await text(pageC, '#fee-h ~ p >> nth=1'), new RegExp(`Paid by Phantom: ${extensionKey.publicKey.toBase58()}`));

const before = await balance(extensionKey.publicKey);
assert.match(await send(pageC, { to: friend.toBase58(), amount: '0.03' }), /^Sent 0\.03 SOL/);
assert.equal(before - (await balance(extensionKey.publicKey)), 5000n);
ok('the extension signs as fee payer and pays the 0.000005 SOL fee');

reject = true;
assert.match(await send(pageC, { to: friend.toBase58(), amount: '0.04' }), /declined the request/);
await pageC.waitForSelector('#pending');
assert.match(await text(pageC, '#pending'), /already handed off/);
await shot(pageC, '8-declined-in-extension');
reject = false;
const friendBefore = await balance(friend);
await pageC.click('#resume');
assert.match(await settled(pageC), /^Sent 0\.04 SOL/);
assert.equal((await balance(friend)) - friendBefore, SOL / 25n);
assert(asked >= 3);
ok('declining in the extension leaves the payment locked; "Try again" completes it');

// ============================================================== removal
console.log('\nremoving');
await pageC.click('#keep-h ~ details >> summary:has-text("Remove this vault")');
await pageC.fill('#remove-confirm', 'nope');
await pageC.click('#remove');
assert.match(await settled(pageC), /Type the word/);
await pageC.fill('#remove-confirm', 'remove');
await pageC.click('#remove');
await pageC.waitForSelector('#go-create');
assert.equal(await pageC.evaluate(() => localStorage.getItem('qpvault:v1')), null);
ok('removing the vault wipes it from the browser');

// ================================================================ wrap up
assert.equal((await balance(vault)) >= reserve, true);
assert.deepEqual(problems, [], 'the page logged errors');
ok('no script errors and no content-security-policy violations in any page');

await browser.close();
server.close();
console.log(`\n${passed} checks passed`);
