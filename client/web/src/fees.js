// Who pays the network fee. Either way it is an ordinary Solana signer with
// no power over the vault.

import { Keypair, PublicKey } from '@solana/web3.js';
import { keypairSigner } from '../../src/wallet.js';

/** A small wallet kept in this browser just for fees. */
export const builtinFeePayer = (secretKey) => keypairSigner(Keypair.fromSecretKey(secretKey));

/** A wallet extension such as Phantom, if one is installed. */
export function findExtension() {
  const provider = globalThis.phantom?.solana ?? globalThis.solflare ?? globalThis.solana;
  if (!provider?.signTransaction) return null;
  const name = provider.isPhantom ? 'Phantom' : provider.isSolflare ? 'Solflare' : 'your wallet extension';
  return { provider, name };
}

/** Ask the extension to connect, and wrap it as a fee payer. */
export async function connectExtension({ provider, name }) {
  const result = await provider.connect();
  const key = result?.publicKey ?? provider.publicKey;
  if (!key) throw new Error(`${name} did not share an address`);
  return {
    name,
    publicKey: new PublicKey(key.toString()),
    signTransaction: (tx) => provider.signTransaction(tx),
  };
}
