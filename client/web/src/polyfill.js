// Solana's libraries expect Node's Buffer to exist. Must be imported first.
import { Buffer } from 'buffer';

globalThis.Buffer ??= Buffer;
