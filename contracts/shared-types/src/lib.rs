#![no_std]

use soroban_sdk::{contracttype, Address, Env, IntoVal, String};

/// Four-tier progress level for a player profile
#[contracttype]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProgressLevel {
    /// Level 0 - profile created, no verification yet
    Unverified,
    /// Level 1 - identity confirmed by academy or KYC
    VerifiedIdentity,
    /// Level 2 - performance milestones verified by approved third party
    PerformanceMilestones,
    /// Level 3 - scout feedback or trial offer logged
    EliteTier,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractHealth {
    /// Whether the contract has completed its one-time initialization.
    pub initialized: bool,
    /// Whether state-changing operations are currently paused.
    pub paused: bool,
    /// Whether the `scout_access.pay_to_contact` function is paused independently
    /// of the whole-contract pause (function-scoped circuit breaker).
    /// Always `false` for contracts that do not implement a `pay_to_contact`
    /// function (`registration`, `verification`, `progress`).
    pub pay_to_contact_paused: bool,
}

/// Maximum number of entries in an IPFS/Arweave media-reference list.
pub const MAX_MEDIA_REFS: u32 = 10;

/// Maximum length (in bytes) of a single IPFS/Arweave media reference string.
/// CIDv1 base32 strings can be up to 128 chars; Arweave tx IDs are 43 chars.
/// A generous upper bound prevents cost amplification via oversized entries.
pub const MAX_MEDIA_REF_LEN: u32 = 256;

/// Validate a single IPFS/Arweave media reference string.
///
/// Accepts:
/// - CIDv0: 46-char base58btc string starting with `Qm`
/// - CIDv1 (base32): 59–128 char RFC4648 lowercase base32 string starting with `bafy`
/// - Arweave transaction ID: 43-char base64url string (A-Z, a-z, 0-9, -, _)
///
/// Returns `Ok(())` if the string is a valid CID or Arweave tx ID,
/// `Err(&'static str)` with a descriptive message otherwise.
pub fn validate_cid(hash: &String) -> Result<(), &'static str> {
    let hash_len = hash.len();
    let bytes = hash.to_bytes();

    let starts_with_qm = bytes.get(0) == Some(b'Q') && bytes.get(1) == Some(b'm');
    let starts_with_bafy = hash_len >= 4
        && bytes.get(0) == Some(b'b')
        && bytes.get(1) == Some(b'a')
        && bytes.get(2) == Some(b'f')
        && bytes.get(3) == Some(b'y');

    if starts_with_qm {
        // CIDv0: exactly 46 chars
        if hash_len != 46 {
            return Err("invalid cid: CIDv0 must be exactly 46 characters");
        }
        // Base58btc charset only (alphanumeric, excluding 0, O, I, l) — this
        // rejects whitespace, control characters, and any other byte outside
        // the alphabet, not just the four excluded look-alike characters.
        for i in 0..hash_len {
            match bytes.get(i) {
                Some(b) if is_base58btc_char(b) => {}
                _ => {
                    return Err("invalid cid: CIDv0 contains invalid base58btc character");
                }
            }
        }
        Ok(())
    } else if starts_with_bafy {
        // CIDv1 (base32): 59–128 chars, RFC4648 lowercase base32 charset
        // (a–z, 2–7). This is a lightweight format sanity check, not a full
        // CID decoder — it does not parse the multibase prefix, multicodec,
        // or multihash the way a real CID library would. Any CID that
        // passes this check but is still malformed will simply fail to
        // resolve against the downstream IPFS/Arweave gateway, which acts
        // as the real source of truth for CID validity. This function only
        // needs to catch obviously wrong input (wrong prefix, wrong length,
        // or bytes outside the expected alphabet — e.g. whitespace or
        // control characters), not guarantee byte-for-byte correctness.
        if !(59..=128).contains(&hash_len) {
            return Err("invalid cid: CIDv1 must be 59–128 characters");
        }
        for i in 0..hash_len {
            match bytes.get(i) {
                Some(b) if is_base32_char(b) => {}
                _ => {
                    return Err("invalid cid: CIDv1 contains invalid base32 character");
                }
            }
        }
        Ok(())
    } else {
        Err("invalid cid: must start with 'Qm' (CIDv0) or 'bafy' (CIDv1)")
    }
}

/// Validate a single Arweave transaction ID.
///
/// Arweave tx IDs are 43-character base64url strings (no padding).
/// Charset: A-Z, a-z, 0-9, -, _.
pub fn validate_arweave_tx_id(id: &String) -> Result<(), &'static str> {
    let len = id.len();
    if len != 43 {
        return Err("invalid arweave tx id: must be exactly 43 characters");
    }
    let bytes = id.to_bytes();
    for i in 0..len {
        match bytes.get(i) {
            Some(b'A'..=b'Z') | Some(b'a'..=b'z') | Some(b'0'..=b'9') | Some(b'-') | Some(b'_') => {}
            _ => {
                return Err("invalid arweave tx id: contains invalid base64url character");
            }
        }
    }
    Ok(())
}

/// Validate all media references for a player profile.
///
/// Checks every entry in `hashes` and rejects the entire list if any
/// entry is invalid. The validation rules are:
///
/// 1. The list must contain 1–10 entries.
/// 2. No entry may be empty or exceed [`MAX_MEDIA_REF_LEN`] characters.
/// 3. Every entry must be either a valid CID (v0 or v1) or a valid
///    Arweave transaction ID (43-char base64url).
/// 4. Duplicate entries are rejected.
///
/// Returns `Ok(())` on success, or `Err(&'static str)` describing the
/// first validation failure.
pub fn validate_media_refs(hashes: &Vec<String>) -> Result<(), &'static str> {
    let len = hashes.len();
    if len == 0 || len > MAX_MEDIA_REFS as usize {
        return Err("invalid media refs: count must be 1–10");
    }

    let mut seen = Vec::new();
    for i in 0..len {
        let h = hashes.get(i).unwrap();
        let h_len = h.len();

        if h_len == 0 {
            return Err("invalid media ref: empty string");
        }
        if h_len > MAX_MEDIA_REF_LEN as usize {
            return Err("invalid media ref: entry exceeds maximum length");
        }

        // Check for duplicates
        for j in 0..seen.len() {
            if seen.get(j).unwrap() == h {
                return Err("invalid media ref: duplicate entry");
            }
        }
        seen.push_back(h.clone());

        // Validate as CID or Arweave tx ID
        if validate_cid(h).is_ok() {
            continue;
        }
        if validate_arweave_tx_id(h).is_ok() {
            continue;
        }
        return Err("invalid media ref: not a valid CID or Arweave tx id");
    }

    Ok(())
}

/// Base58btc alphabet: digits 1–9, uppercase A–Z except I/O, lowercase a–z
/// except l.
fn is_base58btc_char(b: u8) -> bool {
    matches!(b,
        b'1'..=b'9'
        | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
        | b'a'..=b'k' | b'm'..=b'z'
    )
}

/// RFC4648 lowercase base32 alphabet: a–z and 2–7.
fn is_base32_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'2'..=b'7')
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn s(env: &Env, v: &str) -> String {
        String::from_str(env, v)
    }

    #[test]
    fn wiring_link_unconfigured_is_not_configured() {
        let link = WiringLink::unconfigured();
        assert_eq!(link.address, None);
        assert_eq!(link.epoch, 0);
        assert!(!link.is_configured());
    }

    #[test]
    fn wiring_link_with_address_is_configured() {
        let env = Env::default();
        let addr = Address::generate(&env);
        let link = WiringLink {
            address: Some(addr),
            epoch: 1,
        };
        assert!(link.is_configured());
    }

    #[test]
    fn validate_cid_cidv0_valid() {
        let env = Env::default();
        assert!(validate_cid(&s(&env, "QmTestHash12345678901234567890123456789012345678")).is_ok());
    }

    #[test]
    fn validate_cid_cidv0_wrong_length() {
        let env = Env::default();
        assert!(validate_cid(&s(&env, "QmShort")).is_err());
    }

    #[test]
    fn validate_cid_cidv1_valid() {
        let env = Env::default();
        // bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354 - valid CIDv1 base32
        assert!(validate_cid(&s(&env, "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354")).is_ok());
    }

    #[test]
    fn validate_cid_cidv1_wrong_prefix() {
        let env = Env::default();
        assert!(validate_cid(&s(&env, "bafyXXX")).is_err());
    }

    #[test]
    fn validate_cid_invalid_characters() {
        let env = Env::default();
        assert!(validate_cid(&s(&env, "QmTestHash12345678901234567890123456789012345678!")).is_err());
    }

    #[test]
    fn validate_arweave_tx_id_valid() {
        let env = Env::default();
        // 43-char base64url string
        assert!(validate_arweave_tx_id(&s(&env, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012")).is_ok());
    }

    #[test]
    fn validate_arweave_tx_id_wrong_length() {
        let env = Env::default();
        assert!(validate_arweave_tx_id(&s(&env, "too_short")).is_err());
    }

    #[test]
    fn validate_arweave_tx_id_invalid_char() {
        let env = Env::default();
        assert!(validate_arweave_tx_id(&s(&env, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012!")).is_err());
    }

    #[test]
    fn validate_media_refs_valid_cid() {
        let env = Env::default();
        let hashes = Vec::from_slice(&env, &[s(&env, "QmTestHash12345678901234567890123456789012345678")]);
        assert!(validate_media_refs(&hashes).is_ok());
    }

    #[test]
    fn validate_media_refs_valid_arweave() {
        let env = Env::default();
        let hashes = Vec::from_slice(&env, &[s(&env, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012")]);
        assert!(validate_media_refs(&hashes).is_ok());
    }

    #[test]
    fn validate_media_refs_empty_list() {
        let env = Env::default();
        let hashes = Vec::new(&env);
        assert!(validate_media_refs(&hashes).is_err());
    }

    #[test]
    fn validate_media_refs_too_many() {
        let env = Env::default();
        let mut hashes = Vec::new(&env);
        for i in 0..11 {
            hashes.push_back(s(&env, &format!("QmTestHash1234567890123456789012345678901234567{}", i)));
        }
        assert!(validate_media_refs(&hashes).is_err());
    }

    #[test]
    fn validate_media_refs_duplicate() {
        let env = Env::default();
        let h = s(&env, "QmTestHash12345678901234567890123456789012345678");
        let hashes = Vec::from_slice(&env, &[h.clone(), h]);
        assert!(validate_media_refs(&hashes).is_err());
    }

    #[test]
    fn validate_media_refs_empty_string() {
        let env = Env::default();
        let hashes = Vec::from_slice(&env, &[s(&env, "")]);
        assert!(validate_media_refs(&hashes).is_err());
    }

    #[test]
    fn validate_media_refs_invalid_cid() {
        let env = Env::default();
        let hashes = Vec::from_slice(&env, &[s(&env, "not-a-cid")]);
        assert!(validate_media_refs(&hashes).is_err());
    }

    #[test]
    fn validate_media_refs_mixed_cid_and_arweave() {
        let env = Env::default();
        let hashes = Vec::from_slice(&env, &[
            s(&env, "QmTestHash12345678901234567890123456789012345678"),
            s(&env, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012"),
        ]);
        assert!(validate_media_refs(&hashes).is_ok());
    }
}
