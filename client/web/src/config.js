// Where this copy of the web wallet points by default.
//
// PROGRAM_ID is the address the QP Vault program was deployed to. Leave it
// empty until there is a deployment; the page then asks for one. Anyone
// hosting this page for others should fill it in, so visitors are not asked
// to trust an address they were merely sent.
export const PROGRAM_ID = '';
export const RPC_URL = 'https://api.devnet.solana.com';

/** A short, human name for the network behind an RPC URL. */
export function networkOf(url) {
  if (/devnet/i.test(url)) return 'devnet';
  if (/testnet/i.test(url)) return 'testnet';
  if (/^https?:\/\/(127\.0\.0\.1|localhost)[:/]/i.test(url)) return 'local test network';
  if (/mainnet/i.test(url)) return 'mainnet';
  return 'custom network';
}

/** Link to a transaction on Solana Explorer, where there is one. */
export function explorerLink(url, txid) {
  const network = networkOf(url);
  if (network === 'devnet' || network === 'testnet') return `https://explorer.solana.com/tx/${txid}?cluster=${network}`;
  if (network === 'mainnet') return `https://explorer.solana.com/tx/${txid}`;
  return null;
}
