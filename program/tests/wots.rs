//! Native tests for the signature check. `cargo test` from program/.
//!
//! The vector in vector/mod.rs was produced by the JavaScript client, so
//! passing here means the two implementations agree byte for byte.

mod vector;

use qp_vault::wots::{
    cancel_hash, digits_of, message_digest, recover_pubkey_hash, verify_cost, Message, CHAINS,
    CHAIN_STEPS, MSG_DIGITS, N,
};
use solana_pubkey::Pubkey;
use solana_sha256_hasher::hashv;
use vector::*;

/// The vector's message with any fields replaced.
#[derive(Clone, Copy)]
struct M {
    program: [u8; 32],
    vault: [u8; 32],
    sequence: u64,
    asset: [u8; 32],
    amount: u64,
    destination: [u8; 32],
    next: [u8; 32],
    cancel: [u8; 32],
}

const BASE: M = M {
    program: PROGRAM_ID,
    vault: VAULT,
    sequence: SEQUENCE,
    asset: ASSET,
    amount: AMOUNT,
    destination: DESTINATION,
    next: NEXT_KEY_HASH,
    cancel: CANCEL_HASH,
};

fn digest(m: M) -> [u8; 32] {
    message_digest(
        &PUB_SEED,
        &Message {
            program_id: &Pubkey::new_from_array(m.program),
            vault: &Pubkey::new_from_array(m.vault),
            sequence: m.sequence,
            asset: &Pubkey::new_from_array(m.asset),
            amount: m.amount,
            destination: &Pubkey::new_from_array(m.destination),
            next_key_hash: &m.next,
            cancel_hash: &m.cancel,
        },
    )
}

fn digits(m: M) -> [u8; CHAINS] {
    digits_of(&digest(m))
}

#[test]
fn matches_the_javascript_client() {
    assert_eq!(
        cancel_hash(&Pubkey::new_from_array(VAULT), SEQUENCE, &CANCEL_SECRET),
        CANCEL_HASH
    );
    assert_eq!(digest(BASE), DIGEST);
    let d = digits(BASE);
    assert_eq!(d, DIGITS);
    assert_eq!(verify_cost(&d), HASHES);
    assert_eq!(recover_pubkey_hash(&PUB_SEED, &d, &SIGNATURE), PUBKEY_HASH);
}

#[test]
fn every_message_field_is_signed() {
    let other = [9u8; 32];
    let variants = [
        M { program: other, ..BASE },
        M { vault: other, ..BASE },
        M { sequence: SEQUENCE + 1, ..BASE },
        M { asset: other, ..BASE },
        M { asset: [0u8; 32], ..BASE }, // the same payment, but in SOL
        M { amount: AMOUNT + 1, ..BASE },
        M { destination: other, ..BASE },
        M { next: other, ..BASE },
        M { cancel: other, ..BASE },
        // Same bytes in swapped positions must not collide either.
        M { vault: DESTINATION, destination: VAULT, ..BASE },
        M { asset: DESTINATION, destination: ASSET, ..BASE },
        M { sequence: AMOUNT, amount: SEQUENCE, ..BASE },
        M { next: CANCEL_HASH, cancel: NEXT_KEY_HASH, ..BASE },
    ];
    for m in variants {
        let d = digits(m);
        assert_ne!(d, DIGITS);
        assert_ne!(recover_pubkey_hash(&PUB_SEED, &d, &SIGNATURE), PUBKEY_HASH);
    }
}

#[test]
fn cancel_commitment_is_bound_to_vault_and_sequence() {
    let vault = Pubkey::new_from_array(VAULT);
    let mut secret = CANCEL_SECRET;
    secret[31] ^= 1;
    assert_ne!(cancel_hash(&vault, SEQUENCE, &secret), CANCEL_HASH);
    assert_ne!(cancel_hash(&vault, SEQUENCE + 1, &CANCEL_SECRET), CANCEL_HASH);
    assert_ne!(
        cancel_hash(&Pubkey::new_from_array([9u8; 32]), SEQUENCE, &CANCEL_SECRET),
        CANCEL_HASH
    );
    // The public commitment is not its own secret.
    assert_ne!(cancel_hash(&vault, SEQUENCE, &CANCEL_HASH), CANCEL_HASH);
}

#[test]
fn any_flipped_signature_bit_is_rejected() {
    let d = digits(BASE);
    for byte in 0..SIGNATURE.len() {
        let mut sig = SIGNATURE;
        sig[byte] ^= 1 << (byte % 8);
        assert_ne!(recover_pubkey_hash(&PUB_SEED, &d, &sig), PUBKEY_HASH, "byte {byte}");
    }
}

#[test]
fn wrong_public_seed_is_rejected() {
    let mut seed = PUB_SEED;
    seed[15] ^= 0x80;
    assert_ne!(recover_pubkey_hash(&seed, &digits(BASE), &SIGNATURE), PUBKEY_HASH);
}

/// One chain step, written out independently of the library code.
fn step(i: u8, j: u8, x: &[u8]) -> [u8; N] {
    let h = hashv(&[&PUB_SEED, &[0u8, i, j], x]);
    h.as_ref()[..N].try_into().unwrap()
}

/// The classic Winternitz forgery attempt: walk one message chain forward,
/// claiming a higher digit there. The checksum then needs a chain walked
/// *backward*, which the forger cannot do, so they are stuck with the old
/// checksum values and the key no longer matches.
#[test]
fn walking_a_chain_forward_does_not_forge() {
    let d = digits(BASE);
    for i in 0..MSG_DIGITS {
        if d[i] == CHAIN_STEPS {
            continue;
        }
        // Forger's signature: chain i advanced by one step.
        let mut sig = SIGNATURE;
        let next = step(i as u8, d[i], &SIGNATURE[i * N..(i + 1) * N]);
        sig[i * N..(i + 1) * N].copy_from_slice(&next);

        // The digits such a message would have: digit i up by one, so the
        // checksum is down by one.
        let mut forged = d;
        forged[i] += 1;
        let sum = u16::from_be_bytes([d[MSG_DIGITS], d[MSG_DIGITS + 1]]) - 1;
        forged[MSG_DIGITS..].copy_from_slice(&sum.to_be_bytes());

        // Sanity: the advanced chain itself is consistent...
        let mut honest = d;
        honest[i] += 1;
        assert_eq!(recover_pubkey_hash(&PUB_SEED, &honest, &sig), PUBKEY_HASH);
        // ...but with the checksum the message actually demands, it fails.
        assert_ne!(recover_pubkey_hash(&PUB_SEED, &forged, &sig), PUBKEY_HASH, "chain {i}");
    }
}

/// The property the checksum exists for: for any two different messages, the
/// second needs at least one chain opened *earlier* than the first did.
#[test]
fn a_second_message_always_needs_an_earlier_chain_value() {
    let signed = digits(BASE);
    for k in 0u64..20_000 {
        let destination = hashv(&[&k.to_le_bytes()]).to_bytes();
        let other = digits(M { amount: k, destination, ..BASE });
        assert!(
            (0..CHAINS).any(|i| other[i] < signed[i]),
            "message {k} could be forged from the signed one"
        );
    }
}

#[test]
fn checksum_is_the_remaining_distance() {
    let d = digits(BASE);
    let sum: u32 = d[..MSG_DIGITS].iter().map(|x| 255 - *x as u32).sum();
    assert_eq!(u16::from_be_bytes([d[MSG_DIGITS], d[MSG_DIGITS + 1]]) as u32, sum);
}
