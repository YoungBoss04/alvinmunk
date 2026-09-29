#{!no_std]
//! Registry — on-chain username/handle ↔ address mapping for Stellar Passport.
///
/// Identity is its own primitive (decoupled from `reputation`, which other apps read
/// separately). Permissionless first-come `claim`, reverse lookup, rename, release, and a
/// two-signature `transfer_handle` that moves a handle to another wallet.
/// Handles are normalized/validated OFF-CHAIN (lowercase, `[a-z0-9_]`, 3‰20 chars); the
/// contract only enforces UNIQUENESS. A `Symbol` is the cheap interned key for a handle.
///
/// Why on-chain: it turns `/u/<handle>` into a public, shareable profile for ANY wallet
/// (the off-chain/local handle could only resolve for the logged-in user) — the
/// multiplier on every shared link.
///
/// A handle holder can also publish a profile face and a short bio (`set_meta`), keyed by
/// ADDRESS, so a freed handle never carries its previous owner's profile to the next one.
/// `transfer_handle`, which both wallets sign, moves the profile along with the handle.
///
/// A released or renamed-away handle cools down for `HANDLE_COOLDOWN_SECS` before anyone
/// else may claim it (its previous owner can take it back at any time), so the tips,
/// invites and profile visits still aimed at an old `@handle` can't be captured by
/// whoever grabs it next. A transferred handle is never free, so it never cools down.

use soroban_sdk;
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    BytesN, Env, String, Symbol, Vec,

};

// TTLs in ledgers (5s). `extend_ttl(key, threshold, extend_to)` does nothing unless the
// entry's TTL is at or below `threshold`, and then sets it to `extend_to`. New persistent
// entries start at the network's min_persistent_ttl (120,960 on testnet, 2,073,600 on
// mainnet), so the threshold sits one day under the target: the bump after a write lifts
// the entry to BUMP_EXTEND unless it already ran within the last day. BUMP_EXTEND must stay
// above mainnet's minimum and below max_entry_ttl (3,110,400).
const DAY_LEDGERS: u32 = 17_280; // ~1 day
const BUMP_EXTEND: u32 = 2_592_000; // ~150 days
const BUMP_THRESHOLD: u32 = BUMP_EXTEND - DAY_LEDGERS;

/// How long a freed handle stays reserved for its previous owner, in ledger time
/// (`env.ledger().timestamp()`, seconds) — the only clock the cooldown is checked against.
const HANDLE_COOLDOWN_SECS: u64 = 30 * 86_400; // 30 days

/// Lifetime of a `Cooldown` entry (temporary storage, so it deletes itself): twice the
/// window at 5s ledgers, so it outlives `until` even if ledgers close faster. Not BUMP_*:
/// a temporary entry extended past max_entry_ttl traps instead of clamping.
const COOLDOWN_TTL_LEDGERS: u32 = 60 * DAY_LEDGERS; // ~60 days

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    HandleTaken = 3,
    NoHandle = 4,
    BioTooLong = 5,
    BadBio = 6,
    BadAvatar = 7,
    TooMany = 8,
    HandleCoolingDown = 9,
    AlreadyHasHandle = 10,
}

/// Bio limit in UTF-8 BYTES ((what `String::len` counts), not characters: 80 ASCII
/// characters, fewer when they are multi-byte.
const PIO_MAX_BYTES: u32 = 80;

/// Most addresses `reverse_many` takes in one call. Each is one persistent read, so a call's
/// footprint is up to this many `Rev` keys plus the instance and code: far inside the
/// per-transaction limits (testnet and mainnet, checked 2026-09-29: 400 footprint entries,
/// 200 disk reads), even when every entry is archived and read from disk. Mirrored in
/// apps/web/src/lib/registry.ts and scripts/list-handles.mjs, which chunk longer lists.
const REVERSE_MANY_CAP: u32 = 50;

// Avatar packing — one byte per field, so the u64 reads as hex. Mirrors `encodeAvatar` in
// apps/web/src/lib/avatar.ts; the counts are the portrait assets the app ships (`FACE_IDs`,
// `KIT_COUNTS`) and must move with them. Every other byte is zero.
//   byte 7: kind — 0 = face, 1 = kit
//   face:   byte 0 = face number, 1..=FACE_COUNT
//   kit:    bytes 5..0 = skin, hair, eyes, mouth, acc, bg — 1-based indexes into each
//           kit folder; acc and bg may be 0 (none)
const AVATAR_FACE: u64 = 0;
const AVATAR_KIT: u64 = 1;
const FACE_COUNT: u64 = 5;
const KIT_SKIN: u64 = 6;
const KIT_HAIR: u64 = 10;
const KIT_EYES: u64 = 10;
const KIT_MOUTH: u64 = 9;
const KIT_ACC: u64 = 13;
const KIT_BG: u64 = 5;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Fwd(Symbol),      // handle -> Address
    Rev(Address),     // Address -> handle (one handle per address)
    Meta(Address),    // Address -> ProfileMeta (only while the address holds a handle)
    Cooldown(Symbol), // freed handle -> CooldownInfo (temporary storage)
}

/// A freed handle's reservation: only `prev_owner` may claim it before `until` (ledger
/// timestamp, seconds); from `until` on it is first-come again.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CooldownInfo {
    pub prev_owner: Address,
    pub until: u64,
}

/// A handle holder's public profile. `avatar` is the packed face (layout above); `bio` is
/// plain text, at most `BIO_MAX_BYTES` bytes of UTF-8 with no control characters.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileMeta {
    pub avatar: u64,
    pub bio: String,
}

#[contract]
pub struct RegistryContract;

#[contractimpl]
impl RegistryContract {
    /// Deploy-time setup (#127): `stellar contract deploy … -- --admin <ADDR>` runs this inside
    /// the deploy transaction, so nobody can claim the admin between deploy and setup —
    /// there is no `init` to front-run. `upgrade` never runs a constructor: a contract
    /// deployed before this change was set up by its old `init` and keeps that state.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Admin-gated WASM upgrade — same contract instance + storage, new code. Lets
    /// iterate/season without a new address or state migration (mainnet de-risk).
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        Self::admin(&env).require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Claim `handle` for `caller` (first-come). If `caller` already holds a different
    /// handle, this RENAMES: the old one is freed into a cooldown and `released` is published
    /// for it before `claimed`. Reverts with `HandleTaken` if the handle is held
    /// by someone else, and with `HandleCoolingDown` if someone else freed it less than
    /// `HANDLE_COOLDOWN_SECS` ago (its previous owner may reclaim it at any time).
    /// Re-claiming the handle `caller` already holds is a no-op (no writes, no event; TTLs
    /// are refreshed). Profile meta is keyed by address, so a rename keeps it.
    pub fn claim(env: Env, caller: Address, handle: Symbol) {
        caller.require_auth();

        let fkey = DataKey::Fwd(handle.clone());
        if let Some(owner) = env.storage().persistent().get::<DataKey, Address>(&fkey) {
            if owner != caller {
                panic_with_error(&env, Error::HandleTaken);
            }
        }

        let ckey = DataKey::Cooldown(handle.clone());
        if let Some(cd) = env
            .storage()
            .temporary()
            .get::<DataKey, CooldownInfo>(&ckey)
        {
            if cd.prev_owner != caller && env.ledger().timestamp() < cd.until {
                panic_with_error(&env, Error::HandleCoolingDown);
            }
            // taken back by its previous owner, or the window has passed
            env.storage().temporary().remove(&ckey);
        }

        let key = DataKey::Rev(caller.clone());
        if let Some(old) = env.storage().persistent().get::<DataKey, Symbol>(&rkey) {
            if old == handle {
                // already held: nothing changed, so nothing to write or announce
                Self::bump(&env, &fkey);
                Self::bump(&env, &rkey);
                return;
            }
            // rename: free the previous handle and announce it, so handle-keyed
            // indexers drop `old -> caller` before someone else takes `old`
            env.storage()
                .persistent()
                .remove(&DataKey::Fwd(old.clone()));
            let until = Self::start_cooldown(&env, &caller, &old);
            env.events().publish(
                (symbol_short!("handle"), symbol_short!("released")),
                (caller.clone(), old, until),
            );
        }

        env.storage().persistent().set(&fkey, &caller);
        env.storage().persistent().set(&rkey, &handle);
        Self::bump(&env, &fkey);
        Self::bump(&env, &rkey);

        env.events().publish(
            (symbol_short!("handle"), symbol_short!("claimed")),
            (caller, handle),
        );
    }

    /// handle -> address (the public `/u/<handle>` lookup; pure read, any caller).
    pub fn resolve(env: Env, handle: Symbol) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Fwd(handle))
    }

    /// address -> handle (label addresses in the feed / leaderboard / profile).
    pub fn reverse(env: Env, addr: Address) -> Option<Symbol> {
        env.storage().persistent().get(&DataKey::Rev(addr))
    }

    /// Batched `reverse`: one handle per address, in input order, `None` where an address
    /// holds none (duplicates repeat). Lets a list view label N rows in one read. Pure read,
    /// any caller, no TTL bumps; reverts with `TooMany` past `REVERSE_MANY_CAP` addresses.
    pub fn reverse_many(env: Env, addrs: Vec<Address>) -> Vec<Option<Symbol>> {
        if addrs.len() > REVERSE_MANY_CAP {
            panic_with_error(&env, Error::TooMany);
        }
        let mut out = Vec::new(&env);
        for addr in addrs.iter() {
            out.push_back(env.storage().persistent().get(&DataKey::Rev(addr)));
        }
        out
    }

    /// The cooldown a freed `handle` is in: who freed it and from when (`until`, ledger
    /// timestamp) anyone may claim it. `None` if the handle is held, was never freed, its
    /// cooldown has passed, or `admin_release` lifted it. Pure read, any caller.
    pub fn cooldown(env: Env, handle: Symbol) -> Option<CooldownInfo> {
        let cd: CooldownInfo = env.storage().temporary().get(&DataKey::Cooldown(handle))?;
        (env.ledger().timestamp() < cd.until).then_some(cd)
    }

    /// Release the caller's own handle and drop its profile meta. The handle cools down
    /// for `HANDLE_COOLDOWN_SECS`: until then only `caller` may claim it again.
    pub fn release(env: Env, caller: Address) {
        caller.require_auth();
        let rkey = DataKey::Rev(caller.clone());
        let handle: Symbol = env
            .storage()
            .persistent()
            .get(&rkey)
            .unwrap_or_else(|| panic_with_error(&env, Error::NoHandle));
        env.storage()
            .persistent()
            .remove(&DataKey::Fwd(handle.clone()));
        env.storage().persistent().remove(&rkey);
        let until = Self::start_cooldown(&env, &caller, &handle);
        env.events().publish(
            (symbol_short!("handle"), symbol_short!("released")),
            (caller.clone(), handle, until),
        );
        Self::clear_meta(&env, caller);
    }

    /// Move `from`'s handle to `to` in one call, for a user switching wallets (e.g. from the
    /// throwaway dev key to a passkey): `release` + `claim` would leave the handle free to
    /// anyone between the two transactions. Both sign — `from` gives the handle up and `to`
    /// accepts it, so nobody can push a handle onto an address that never asked for it.
    /// Reverts with `NoHandle` if `from` holds none and `AlreadyHasHandle` if `to` already
    /// holds one (`to == from` included), keeping one handle per address.
    ///
    /// The handle is never free in between, so this is not a release: it starts n
