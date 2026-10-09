//! Winternitz one-time signature verification (hash-based, w = 256).
//!
//! Security rests only on SHA-256 preimage resistance. There is no elliptic
//! curve anywhere in this file, which is the whole point: Shor's algorithm has
//! nothing to attack.
//!
//! Parameters
//!   n      = 24 bytes   every chain value is SHA-256 truncated to 192 bits
//!   w      = 256        one chain per byte of the message digest
//!   chains = 26         24 message bytes + 2 checksum bytes
//!   sig    = 624 bytes
//!
//! These are the sizes of NIST SP 800-208's LMOTS_SHA256_N24_W8. The hash
//! input layout here is this program's own, not LMS's. 192 bits is what lets
//! a token transfer, its account list and the signature share one
//! transaction.
//!
//! Every hash call is prefixed with the key's 16-byte public seed and a type
//! tag, and each chain step also carries its chain and step index, so a hash
//! computed for one position in one key is useless anywhere else.

use solana_pubkey::Pubkey;
use solana_sha256_hasher::hashv;

/// Bytes kept from each SHA-256 output.
pub const N: usize = 24;
/// Message digest bytes that are signed (one chain each).
pub const MSG_DIGITS: usize = 24;
/// Checksum length in bytes (one chain each).
pub const CSUM_DIGITS: usize = 2;
/// Total hash chains per key.
pub const CHAINS: usize = MSG_DIGITS + CSUM_DIGITS;
/// Steps from a chain's secret start to its public end.
pub const CHAIN_STEPS: u8 = 255;
/// Per-key public seed length.
pub const SEED_LEN: usize = 16;
/// Signature length in bytes.
pub const SIG_LEN: usize = CHAINS * N;

const TAG_CHAIN: u8 = 0;
const TAG_PUBKEY: u8 = 1;
const TAG_MESSAGE: u8 = 2;
const TAG_CANCEL: u8 = 3;

/// Everything one signature authorises.
pub struct Message<'a> {
    pub program_id: &'a Pubkey,
    pub vault: &'a Pubkey,
    /// Which spend of this vault this is.
    pub sequence: u64,
    /// The token mint, or 32 zero bytes for SOL.
    pub asset: &'a Pubkey,
    pub amount: u64,
    /// Recipient wallet for SOL; recipient token account for tokens.
    pub destination: &'a Pubkey,
    /// Hash of the key that takes over the vault afterwards.
    pub next_key_hash: &'a [u8; 32],
    /// Hash of the secret that lets the owner cancel this payment.
    pub cancel_hash: &'a [u8; 32],
}

/// The 32-byte digest of a message. The first 24 bytes are what gets signed;
/// the whole thing is what the vault records as "last message".
pub fn message_digest(pub_seed: &[u8; SEED_LEN], m: &Message) -> [u8; 32] {
    hashv(&[
        pub_seed,
        &[TAG_MESSAGE],
        m.program_id.as_ref(),
        m.vault.as_ref(),
        &m.sequence.to_le_bytes(),
        m.asset.as_ref(),
        &m.amount.to_le_bytes(),
        m.destination.as_ref(),
        m.next_key_hash,
        m.cancel_hash,
    ])
    .to_bytes()
}

/// The 26 chain positions a signature of `digest` must open.
pub fn digits_of(digest: &[u8; 32]) -> [u8; CHAINS] {
    let mut digits = [0u8; CHAINS];
    digits[..MSG_DIGITS].copy_from_slice(&digest[..MSG_DIGITS]);

    // Checksum. A forger can only walk chains forward (raise a digit). Raising
    // any message digit lowers this sum, which lowers at least one checksum
    // digit, and lowering a digit means inverting SHA-256.
    let mut sum: u16 = 0;
    for d in &digits[..MSG_DIGITS] {
        sum += (CHAIN_STEPS - *d) as u16; // max 24 * 255 = 6120, fits u16
    }
    digits[MSG_DIGITS] = (sum >> 8) as u8;
    digits[MSG_DIGITS + 1] = sum as u8;
    digits
}

/// Finish every chain from the signature value to its public end and return
/// the hash of the resulting public key.
///
/// This never fails: a wrong signature simply produces a different hash,
/// which then does not match the key hash stored in the vault.
pub fn recover_pubkey_hash(
    pub_seed: &[u8; SEED_LEN],
    digits: &[u8; CHAINS],
    signature: &[u8; SIG_LEN],
) -> [u8; 32] {
    const X: usize = SEED_LEN + 3; // offset of the chain value in `step`

    // step = pub_seed | TAG_CHAIN | chain index | step index | value
    let mut step = [0u8; X + N];
    step[..SEED_LEN].copy_from_slice(pub_seed);
    step[SEED_LEN] = TAG_CHAIN;

    // pk = pub_seed | TAG_PUBKEY | end of chain 0 | ... | end of chain 25
    let mut pk = [0u8; SEED_LEN + 1 + SIG_LEN];
    pk[..SEED_LEN].copy_from_slice(pub_seed);
    pk[SEED_LEN] = TAG_PUBKEY;

    for i in 0..CHAINS {
        step[SEED_LEN + 1] = i as u8;
        step[X..].copy_from_slice(&signature[i * N..(i + 1) * N]);
        for j in digits[i]..CHAIN_STEPS {
            step[SEED_LEN + 2] = j;
            let h = hashv(&[&step]);
            step[X..].copy_from_slice(&h.as_ref()[..N]);
        }
        let at = SEED_LEN + 1 + i * N;
        pk[at..at + N].copy_from_slice(&step[X..]);
    }

    hashv(&[&pk]).to_bytes()
}

/// Number of SHA-256 calls `recover_pubkey_hash` makes for these digits.
pub fn verify_cost(digits: &[u8; CHAINS]) -> u32 {
    digits.iter().map(|d| (CHAIN_STEPS - *d) as u32).sum()
}

/// Commitment to the secret that cancels spend number `sequence` of `vault`.
pub fn cancel_hash(vault: &Pubkey, sequence: u64, secret: &[u8; 32]) -> [u8; 32] {
    hashv(&[&[TAG_CANCEL], vault.as_ref(), &sequence.to_le_bytes(), secret]).to_bytes()
}
