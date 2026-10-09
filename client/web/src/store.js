// Browser storage for one vault.
//
// The master seed and the built-in fee wallet's key are encrypted with the
// user's password (PBKDF2-SHA256, then AES-256-GCM, both from the browser's
// own WebCrypto). Everything else is bookkeeping that is safe to read: the
// address, which key is next, the pending payment, the history.

import { Buffer } from 'buffer';

const KEY = 'qpvault:v1';
const ITERATIONS = 600_000;

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (text) => new Uint8Array(Buffer.from(text, 'base64'));

async function deriveKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function seal(secrets, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, ITERATIONS);
  const data = new TextEncoder().encode(JSON.stringify(secrets));
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: b64(salt), iv: b64(iv), data: b64(new Uint8Array(sealed)) };
}

async function unseal(box, password) {
  const key = await deriveKey(password, unb64(box.salt), box.iterations);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.data));
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new Error('wrong password');
  }
}

const read = () => {
  const text = localStorage.getItem(KEY);
  return text ? JSON.parse(text) : null;
};

const write = (record) => {
  const text = JSON.stringify(record);
  localStorage.setItem(KEY, text);
  // A payment lock that did not reach storage is worse than an error.
  if (localStorage.getItem(KEY) !== text) throw new Error('the browser did not save the wallet; nothing was sent');
};

export const hasVault = () => read() !== null;

/** What can be shown before unlocking. */
export const peek = () => {
  const record = read();
  return record && { address: record.state.address, programId: record.state.programId, url: record.state.url };
};

/** The store handed to the wallet core: plain, synchronous saves of the state. */
class BrowserStore {
  save(state) {
    const record = read();
    if (!record) throw new Error('this vault was removed from the browser in another tab');
    write({ ...record, state });
  }

  load() {
    return read()?.state ?? null;
  }
}

/** Save a brand-new vault. Refuses to overwrite one that is already here. */
export async function createVault({ state, masterSeed, feeSecretKey, password }) {
  if (hasVault()) throw new Error('this browser already holds a vault');
  const box = await seal({ seed: masterSeed.toString('hex'), fee: b64(feeSecretKey) }, password);
  write({ state, box });
  return new BrowserStore();
}

/** Decrypt the secrets. Throws "wrong password". */
export async function unlockVault(password) {
  const record = read();
  if (!record) throw new Error('no vault in this browser');
  const secrets = await unseal(record.box, password);
  return {
    store: new BrowserStore(),
    state: record.state,
    masterSeed: Buffer.from(secrets.seed, 'hex'),
    feeSecretKey: unb64(secrets.fee),
  };
}

export const removeVault = () => localStorage.removeItem(KEY);
