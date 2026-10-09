//! QP Vault: a Solana vault for SOL and tokens that no elliptic-curve key can
//! open.
//!
//! A vault is one account at one permanent address. It stores the hash of a
//! Winternitz one-time public key. Funds leave only through a spend, which
//! checks a Winternitz signature inside this program. A stolen or
//! quantum-recovered ed25519 key is useless against it.
//!
//! A Winternitz key may sign only once, so every signed message also names
//! the hash of the owner's *next* key, and the vault switches to it in the
//! same transaction. The signature that was just published is dead the moment
//! it lands: it cannot be replayed, and the key it exposed controls nothing.
//!
//! The address is the program-derived address of
//!
//! ```text
//! ["qpvault", hash of the FIRST key]
//! ```
//!
//! so it has no private key, and it never changes as keys rotate. Tokens are
//! held in ordinary token accounts whose owner is that address.
//!
//! # Account state (107 bytes)
//!
//! ```text
//! [0]        version, 1
//! [1]        address bump
//! [2..34]    hash of the first key (the address seed)
//! [34..66]   hash of the current key
//! [66..74]   sequence: number of keys used up so far, u64 little-endian
//! [74]       what the last key did: 0 nothing yet, 1 paid, 2 cancelled
//! [75..107]  digest of the last signed message
//! ```
//!
//! The last two fields let a wallet learn from the chain alone whether its
//! own payment is the one that went through.
//!
//! # Instructions
//!
//! Every spend carries the same signed fields:
//!
//! ```text
//! amount (u64 LE) | public seed (16) | next key hash (32) | cancel hash (32) | signature (624)
//! ```
//!
//! `Open` (tag 0): create the state for a vault. Anyone may call it; the
//! address fixes the outcome, so there is nothing to get wrong or hijack.
//!
//! ```text
//! data      hash of the first key (32)
//! accounts  0. [signer, writable] payer (covers the rent reserve if needed)
//!           1. [writable]         vault
//!           2. []                 system program
//! ```
//!
//! `SpendSol` (tag 1): pay `amount` lamports to `recipient`.
//!
//! ```text
//! data      the signed fields
//! accounts  0. [writable] vault
//!           1. [writable] recipient
//! ```
//!
//! `SpendToken` (tag 2): pay `amount` base units of `mint` to a token account.
//!
//! ```text
//! data      the signed fields
//! accounts  0. [writable] vault
//!           1. [writable] source token account (owned by the vault)
//!           2. [writable] destination token account
//!           3. []         mint
//!           4. []         token program (SPL Token or Token-2022)
//! ```
//!
//! `Cancel` (tag 3): use up the current key *without* paying. Needs the
//! signature of the payment being cancelled plus the cancel secret that
//! payment committed to, so only the owner can do it. This is the way out if
//! a signed payment can never succeed (a frozen token account, say): without
//! it the key would be stuck on that message forever.
//!
//! ```text
//! data      asset (32) | destination (32) | amount (u64 LE) | public seed (16)
//!           | next key hash (32) | cancel secret (32) | signature (624)
//! accounts  0. [writable] vault
//! ```

pub mod wots;

use solana_account_info::{next_account_info, AccountInfo};
use solana_cpi::{invoke, invoke_signed};
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::{pubkey, Pubkey};
use solana_rent::{sysvar::GetSysvar, Rent};
use wots::{Message, SEED_LEN, SIG_LEN};

/// First seed of every vault address.
pub const VAULT_SEED: &[u8] = b"qpvault";

pub const IX_OPEN: u8 = 0;
pub const IX_SPEND_SOL: u8 = 1;
pub const IX_SPEND_TOKEN: u8 = 2;
pub const IX_CANCEL: u8 = 3;

pub const STATE_VERSION: u8 = 1;
pub const STATE_LEN: usize = 107;
const AT_BUMP: usize = 1;
const AT_FIRST_KEY: usize = 2;
const AT_KEY: usize = 34;
const AT_SEQUENCE: usize = 66;
const AT_OUTCOME: usize = 74;
const AT_LAST_MESSAGE: usize = 75;

pub const OUTCOME_PAID: u8 = 1;
pub const OUTCOME_CANCELLED: u8 = 2;

/// Length of the signed fields after the tag byte.
pub const SPEND_LEN: usize = 8 + SEED_LEN + 32 + 32 + SIG_LEN;
/// Length of `Cancel` data after the tag byte.
pub const CANCEL_LEN: usize = 32 + 32 + SPEND_LEN;

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
/// Stands in for a mint when the asset is SOL. No mint can live at this key.
pub const SOL: Pubkey = Pubkey::new_from_array([0u8; 32]);
pub const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Errors returned as `ProgramError::Custom`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// The signature is not a signature of this exact request by the vault's
    /// current key.
    BadSignature = 0,
    /// The recipient is the vault itself.
    SelfTransfer = 1,
    /// The next key is the same as the current key.
    KeyReuse = 2,
    /// The token program is neither SPL Token nor Token-2022.
    UnknownTokenProgram = 3,
    /// The mint account does not belong to the given token program.
    BadMint = 4,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&IX_OPEN, rest)) => open(program_id, accounts, rest),
        Some((&IX_SPEND_SOL, rest)) => spend_sol(program_id, accounts, rest),
        Some((&IX_SPEND_TOKEN, rest)) => spend_token(program_id, accounts, rest),
        Some((&IX_CANCEL, rest)) => cancel(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn open(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let key_hash: &[u8; 32] = data
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let vault = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if system_program.key != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    // The address commits to the first key, so the state written below is the
    // only state this address can ever start with.
    let (expected, bump) = Pubkey::find_program_address(&[VAULT_SEED, key_hash], program_id);
    if expected != *vault.key {
        return Err(ProgramError::InvalidSeeds);
    }
    // Before it is opened a vault address is a plain system account. It may
    // already hold SOL that someone sent early.
    if vault.owner != &SYSTEM_PROGRAM_ID || !vault.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let reserve = Rent::get()?.minimum_balance(STATE_LEN);
    let held = vault.lamports();
    if held < reserve {
        invoke(
            &system_instruction(
                2, // Transfer
                &(reserve - held).to_le_bytes(),
                vec![
                    AccountMeta::new(*payer.key, true),
                    AccountMeta::new(*vault.key, false),
                ],
            ),
            &[payer.clone(), vault.clone(), system_program.clone()],
        )?;
    }

    let bump_seed = [bump];
    let signer: &[&[u8]] = &[VAULT_SEED, key_hash, &bump_seed];
    // Allocate, then Assign: the vault signs for itself as a program address.
    invoke_signed(
        &system_instruction(
            8,
            &(STATE_LEN as u64).to_le_bytes(),
            vec![AccountMeta::new(*vault.key, true)],
        ),
        &[vault.clone(), system_program.clone()],
        &[signer],
    )?;
    invoke_signed(
        &system_instruction(
            1,
            program_id.as_ref(),
            vec![AccountMeta::new(*vault.key, true)],
        ),
        &[vault.clone(), system_program.clone()],
        &[signer],
    )?;

    let mut state = vault.try_borrow_mut_data()?;
    if state.len() != STATE_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    state.fill(0);
    state[0] = STATE_VERSION;
    state[AT_BUMP] = bump;
    state[AT_FIRST_KEY..AT_KEY].copy_from_slice(key_hash);
    state[AT_KEY..AT_SEQUENCE].copy_from_slice(key_hash);
    Ok(())
}

/// The fields every spend carries, as laid out in instruction data.
struct Signed<'a> {
    amount: u64,
    pub_seed: &'a [u8; SEED_LEN],
    next_key_hash: &'a [u8; 32],
    /// Cancel hash for a spend; cancel secret for a `Cancel`.
    cancel: &'a [u8; 32],
    signature: &'a [u8; SIG_LEN],
}

impl<'a> Signed<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() != SPEND_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (amount, rest) = data.split_at(8);
        let (pub_seed, rest) = rest.split_at(SEED_LEN);
        let (next_key_hash, rest) = rest.split_at(32);
        let (cancel, signature) = rest.split_at(32);
        Ok(Self {
            amount: u64::from_le_bytes(amount.try_into().unwrap()),
            pub_seed: pub_seed.try_into().unwrap(),
            next_key_hash: next_key_hash.try_into().unwrap(),
            cancel: cancel.try_into().unwrap(),
            signature: signature.try_into().unwrap(),
        })
    }
}

/// The single gate every outflow passes through.
///
/// Checks that `vault` is a real vault and that `signed` is its current key's
/// signature over exactly (asset, amount, destination, next key, cancel
/// hash); then retires that key, installs the next one and records what
/// happened. Returns the seeds material the vault needs to sign for itself.
fn authorize_and_rotate(
    program_id: &Pubkey,
    vault: &AccountInfo,
    asset: &Pubkey,
    destination: &Pubkey,
    signed: &Signed,
    cancel_hash: &[u8; 32],
    outcome: u8,
) -> Result<([u8; 32], u8), ProgramError> {
    // Only `open` ever writes a version byte into an account this program
    // owns, so passing these checks means: this is a real vault.
    if vault.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let mut state = vault.try_borrow_mut_data()?;
    if state.len() != STATE_LEN || state[0] != STATE_VERSION {
        return Err(ProgramError::UninitializedAccount);
    }
    let bump = state[AT_BUMP];
    let first_key_hash: [u8; 32] = state[AT_FIRST_KEY..AT_KEY].try_into().unwrap();
    let key_hash: [u8; 32] = state[AT_KEY..AT_SEQUENCE].try_into().unwrap();
    let sequence = u64::from_le_bytes(state[AT_SEQUENCE..AT_OUTCOME].try_into().unwrap());

    if *signed.next_key_hash == key_hash {
        return Err(VaultError::KeyReuse.into());
    }

    // The signed message is everything the instruction does. Whoever relays
    // the transaction cannot change any part of it.
    let digest = wots::message_digest(
        signed.pub_seed,
        &Message {
            program_id,
            vault: vault.key,
            sequence,
            asset,
            amount: signed.amount,
            destination,
            next_key_hash: signed.next_key_hash,
            cancel_hash,
        },
    );
    let digits = wots::digits_of(&digest);
    if wots::recover_pubkey_hash(signed.pub_seed, &digits, signed.signature) != key_hash {
        return Err(VaultError::BadSignature.into());
    }

    // Rotate. From here on that signature verifies against nothing.
    let next_sequence = sequence
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    state[AT_KEY..AT_SEQUENCE].copy_from_slice(signed.next_key_hash);
    state[AT_SEQUENCE..AT_OUTCOME].copy_from_slice(&next_sequence.to_le_bytes());
    state[AT_OUTCOME] = outcome;
    state[AT_LAST_MESSAGE..].copy_from_slice(&digest);
    Ok((first_key_hash, bump))
}

fn spend_sol(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let signed = Signed::parse(data)?;
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let recipient = next_account_info(iter)?;

    if recipient.key == vault.key {
        return Err(VaultError::SelfTransfer.into());
    }
    authorize_and_rotate(
        program_id,
        vault,
        &SOL,
        recipient.key,
        &signed,
        signed.cancel,
        OUTCOME_PAID,
    )?;

    // The rent reserve stays behind. If the account were ever emptied it
    // would be deleted, and its address would fall back to the first key.
    let reserve = Rent::get()?.minimum_balance(STATE_LEN);
    if signed.amount > vault.lamports().saturating_sub(reserve) {
        return Err(ProgramError::InsufficientFunds);
    }
    **vault.try_borrow_mut_lamports()? -= signed.amount;
    let credited = recipient
        .lamports()
        .checked_add(signed.amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **recipient.try_borrow_mut_lamports()? = credited;
    Ok(())
}

fn spend_token(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let signed = Signed::parse(data)?;
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let source = next_account_info(iter)?;
    let destination = next_account_info(iter)?;
    let mint = next_account_info(iter)?;
    let token_program = next_account_info(iter)?;

    // The vault is about to sign a call into this program, so it must be one
    // of the two real token programs and nothing else.
    if *token_program.key != TOKEN_PROGRAM_ID && *token_program.key != TOKEN_2022_PROGRAM_ID {
        return Err(VaultError::UnknownTokenProgram.into());
    }
    // Decimals sit at byte 44 of a mint in both token programs. Only trust
    // that layout in an account the token program actually owns.
    if mint.owner != token_program.key || mint.data_len() < 82 {
        return Err(VaultError::BadMint.into());
    }
    let decimals = mint.try_borrow_data()?[44];

    // Signed: this mint, this amount, this destination token account. The
    // source is not signed and need not be: the token program only lets the
    // vault move tokens out of accounts the vault owns, of this mint.
    let (first_key_hash, bump) = authorize_and_rotate(
        program_id,
        vault,
        mint.key,
        destination.key,
        &signed,
        signed.cancel,
        OUTCOME_PAID,
    )?;

    // TransferChecked: the token program verifies mint and decimals itself.
    let mut ix_data = Vec::with_capacity(10);
    ix_data.push(12);
    ix_data.extend_from_slice(&signed.amount.to_le_bytes());
    ix_data.push(decimals);
    let transfer = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*source.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*destination.key, false),
            AccountMeta::new_readonly(*vault.key, true),
        ],
        data: ix_data,
    };
    let bump_seed = [bump];
    invoke_signed(
        &transfer,
        &[
            source.clone(),
            mint.clone(),
            destination.clone(),
            vault.clone(),
            token_program.clone(),
        ],
        &[&[VAULT_SEED, &first_key_hash, &bump_seed]],
    )
}

fn cancel(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != CANCEL_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (asset, rest) = data.split_at(32);
    let (destination, rest) = rest.split_at(32);
    let asset = Pubkey::new_from_array(asset.try_into().unwrap());
    let destination = Pubkey::new_from_array(destination.try_into().unwrap());
    // Same layout as a spend, with the cancel secret where the hash would be.
    let signed = Signed::parse(rest)?;

    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;

    // Read the sequence to rebuild the commitment the payment was signed
    // with. If the secret is wrong the commitment is wrong, the digest is
    // wrong, and the signature check inside fails.
    if vault.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let sequence = {
        let state = vault.try_borrow_data()?;
        if state.len() != STATE_LEN || state[0] != STATE_VERSION {
            return Err(ProgramError::UninitializedAccount);
        }
        u64::from_le_bytes(state[AT_SEQUENCE..AT_OUTCOME].try_into().unwrap())
    };
    let cancel_hash = wots::cancel_hash(vault.key, sequence, signed.cancel);

    authorize_and_rotate(
        program_id,
        vault,
        &asset,
        &destination,
        &signed,
        &cancel_hash,
        OUTCOME_CANCELLED,
    )?;
    Ok(())
}

/// A system program instruction, encoded by hand (u32 variant index followed
/// by the payload) to keep serialization crates out of the on-chain binary.
/// Variants used: 1 Assign(owner), 2 Transfer(lamports), 8 Allocate(space).
fn system_instruction(variant: u32, payload: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&variant.to_le_bytes());
    data.extend_from_slice(payload);
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts,
        data,
    }
}
