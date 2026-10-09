// Node only: keep a wallet in one JSON file, owner-readable, seed included.
// This is what the command line tool uses.

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { Wallet, randomSeed } from './wallet.js';

class FileStore {
  constructor(path, masterSeed) {
    this.path = path;
    this.masterSeed = masterSeed;
  }

  #body(state) {
    return JSON.stringify({ ...state, masterSeed: this.masterSeed.toString('hex') }, null, 2) + '\n';
  }

  /** First write: fails if the file already exists. */
  create(state) {
    mkdirSync(dirname(this.path), { recursive: true });
    const fd = openSync(this.path, 'wx', 0o600);
    writeSync(fd, this.#body(state));
    fsyncSync(fd);
    closeSync(fd);
  }

  /** Later writes: either fully on disk or not changed at all. */
  save(state) {
    const tmp = `${this.path}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    writeSync(fd, this.#body(state));
    fsyncSync(fd);
    closeSync(fd);
    renameSync(tmp, this.path);
  }

  load() {
    // eslint-disable-next-line no-unused-vars
    const { masterSeed, ...state } = JSON.parse(readFileSync(this.path, 'utf8'));
    return state;
  }
}

/** Create a new wallet file. Refuses to overwrite an existing one. */
export function createFileWallet(path, { programId, url, masterSeed = randomSeed() }) {
  if (masterSeed.length !== 32) throw new Error('master seed must be 32 bytes');
  const state = Wallet.initialState({ programId, url, masterSeed });
  const store = new FileStore(path, masterSeed);
  store.create(state);
  return new Wallet(store, state, masterSeed);
}

/** Open an existing wallet file. */
export function loadFileWallet(path) {
  if (!existsSync(path)) throw new Error(`no wallet at ${path}`);
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  if (raw.version !== 2) throw new Error(`unsupported wallet version ${raw.version}`);
  const masterSeed = Buffer.from(raw.masterSeed, 'hex');
  const store = new FileStore(path, masterSeed);
  return new Wallet(store, store.load(), masterSeed);
}
