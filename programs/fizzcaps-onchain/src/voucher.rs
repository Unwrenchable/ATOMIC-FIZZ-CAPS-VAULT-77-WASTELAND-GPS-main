//! Binary loot voucher v1 and Ed25519 precompile introspection.
//!
//! The signed message is rebuilt on-chain. The client never supplies trusted
//! bytes. The Ed25519 precompile verifies the signature; this module only
//! checks that the precompile verified the configured server key over that
//! exact message.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked,
};
use solana_sdk_ids::ed25519_program;
use solana_sha256_hasher::hash;

use crate::ErrorCode;

/// Domain separator. Not valid for the legacy off-chain pipe-format redeem path.
pub const VOUCHER_DOMAIN: &[u8; 24] = b"FIZZCAPS:LOOT_VOUCHER:v1";
pub const VOUCHER_MSG_LEN: usize = 169;
pub const MAX_HINT_LEN: usize = 64;
/// Security override: vouchers live at most 5 minutes (spec draft used 3600).
pub const MAX_VOUCHER_TTL_SECS: i64 = 300;
pub const MAX_CLOCK_SKEW_SECS: i64 = 30;

pub const VOUCHER_CLAIM_SEED: &[u8] = b"voucher-claim";
pub const LOOT_CLAIM_SEED: &[u8] = b"loot-claim";
pub const VOUCHER_GUARD_SEED: &[u8] = b"voucher-guard";

/// `1` mainnet-beta, `2` devnet, `3` localnet. Compile-time, never from the client.
pub const CLUSTER_TAG: u8 = if cfg!(feature = "mainnet") {
    1
} else if cfg!(feature = "devnet") {
    2
} else {
    3
};

const _: () = assert!(VOUCHER_DOMAIN.len() == 24);
const _: () = assert!(VOUCHER_MSG_LEN == 169);

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LootVoucherV1 {
    pub voucher_id: [u8; 16],
    pub loot_id: u64,
    pub lat_e6: i32,
    pub lng_e6: i32,
    /// UTF-8 hint, at most 64 bytes. The message commits to sha256(hint).
    pub location_hint: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl LootVoucherV1 {
    pub fn check_shape_and_time(&self, now: i64) -> Result<()> {
        require!(
            self.location_hint.len() <= MAX_HINT_LEN,
            ErrorCode::VoucherBadShape
        );
        require!(
            (-90_000_000..=90_000_000).contains(&self.lat_e6),
            ErrorCode::VoucherBadShape
        );
        require!(
            (-180_000_000..=180_000_000).contains(&self.lng_e6),
            ErrorCode::VoucherBadShape
        );
        let ttl = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or_else(|| error!(ErrorCode::VoucherBadShape))?;
        require!(ttl > 0, ErrorCode::VoucherBadShape);
        require!(ttl <= MAX_VOUCHER_TTL_SECS, ErrorCode::VoucherTtlTooLong);
        let latest_issue = now.saturating_add(MAX_CLOCK_SKEW_SECS);
        require!(
            self.issued_at <= latest_issue,
            ErrorCode::VoucherNotYetValid
        );
        require!(now <= self.expires_at, ErrorCode::VoucherExpired);
        Ok(())
    }

    /// Fixed 169-byte little-endian message. `program_id` is `crate::ID`.
    /// `player` is the transaction signer. Neither value is read from the client.
    pub fn message(&self, program_id: &Pubkey, player: &Pubkey) -> [u8; VOUCHER_MSG_LEN] {
        let mut m = [0u8; VOUCHER_MSG_LEN];
        let mut o = 0usize;
        let mut put = |b: &[u8]| {
            let end = o + b.len();
            m[o..end].copy_from_slice(b);
            o = end;
        };
        put(VOUCHER_DOMAIN);
        put(&[CLUSTER_TAG]);
        put(program_id.as_ref());
        put(player.as_ref());
        put(&self.voucher_id);
        put(&self.loot_id.to_le_bytes());
        put(&self.lat_e6.to_le_bytes());
        put(&self.lng_e6.to_le_bytes());
        put(&hash(self.location_hint.as_bytes()).to_bytes());
        put(&self.issued_at.to_le_bytes());
        put(&self.expires_at.to_le_bytes());
        debug_assert_eq!(o, VOUCHER_MSG_LEN);
        // Release builds strip debug_assert. Refuse to return a short write.
        assert_eq!(o, VOUCHER_MSG_LEN, "voucher message layout drifted");
        m
    }
}

/// Bounds-checked slice. `offset + len` uses checked arithmetic so a huge
/// offset cannot wrap.
pub fn checked_slice(d: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| error!(ErrorCode::Ed25519BadLayout))?;
    d.get(off..end)
        .ok_or_else(|| error!(ErrorCode::Ed25519BadLayout))
}

/// Parse one Ed25519 precompile instruction and return the pubkey, signature,
/// and message the precompile verified.
///
/// Header (little-endian), after `num_sigs: u8` and `padding: u8`:
///
/// | bytes | field |
/// |---|---|
/// | 2..4 | signature_offset |
/// | 4..6 | signature_instruction_index |
/// | 6..8 | public_key_offset |
/// | 8..10 | public_key_instruction_index |
/// | 10..12 | message_data_offset |
/// | 12..14 | message_data_size |
/// | 14..16 | message_instruction_index |
///
/// A previous parser read bytes 2..4 (the signature offset) as the pubkey
/// offset. The pubkey offset is bytes 6..8. Offsets are taken from the header
/// and are not hard-coded. All three instruction indexes must be `u16::MAX`
/// so the pubkey, signature, and message live in this instruction's data.
/// `message_data_size` must be exactly 169.
pub fn parse_ed25519_ix_data(d: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    require!(d.len() >= 16, ErrorCode::Ed25519BadLayout);
    require!(d[0] == 1, ErrorCode::Ed25519BadLayout);
    let rd = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
    let (sig_off, sig_ix) = (rd(2) as usize, rd(4));
    let (pk_off, pk_ix) = (rd(6) as usize, rd(8));
    let (msg_off, msg_len_u, msg_ix) = (rd(10) as usize, rd(12) as usize, rd(14));
    require!(
        sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX,
        ErrorCode::Ed25519BadLayout
    );
    require!(msg_len_u == VOUCHER_MSG_LEN, ErrorCode::Ed25519BadLayout);
    let pk = checked_slice(d, pk_off, 32)?;
    let sig = checked_slice(d, sig_off, 64)?;
    let msg = checked_slice(d, msg_off, msg_len_u)?;
    Ok((pk, sig, msg))
}

pub fn verify_voucher_ed25519(
    ix_sysvar: &AccountInfo,
    expected_signer: &Pubkey,
    expected_msg: &[u8],
) -> Result<()> {
    require!(
        expected_msg.len() == VOUCHER_MSG_LEN,
        ErrorCode::VoucherMessageMismatch
    );
    let cur = load_current_index_checked(ix_sysvar)? as usize;
    // Direct invocation only. Inside a CPI the top-level instruction belongs
    // to the caller, so this rejects claim_loot-via-CPI.
    let cur_ix = load_instruction_at_checked(cur, ix_sysvar)?;
    require_keys_eq!(cur_ix.program_id, crate::ID, ErrorCode::CpiNotAllowed);
    require!(cur > 0, ErrorCode::MissingEd25519Ix);
    let ed = load_instruction_at_checked(cur - 1, ix_sysvar)?;
    require_keys_eq!(ed.program_id, ed25519_program::ID, ErrorCode::MissingEd25519Ix);
    require!(ed.accounts.is_empty(), ErrorCode::Ed25519BadLayout);
    let (pk, _sig, msg) = parse_ed25519_ix_data(&ed.data)?;
    require!(pk == expected_signer.as_ref(), ErrorCode::WrongVoucherSigner);
    require!(msg == expected_msg, ErrorCode::VoucherMessageMismatch);
    Ok(())
}

/// Reject a server key that is empty or already used by another cluster slot.
/// Index 0 is unused. Slots 1, 2, and 3 are mainnet, devnet, and localnet.
pub fn assert_distinct_server_key(
    keys: &[Pubkey; 4],
    cluster_tag: u8,
    new_key: Pubkey,
) -> Result<()> {
    require!((1..=3).contains(&cluster_tag), ErrorCode::VoucherBadShape);
    require!(new_key != Pubkey::default(), ErrorCode::WrongVoucherSigner);
    for (i, existing) in keys.iter().enumerate() {
        if i == cluster_tag as usize || *existing == Pubkey::default() {
            continue;
        }
        require!(
            *existing != new_key,
            ErrorCode::ServerKeyReusedAcrossClusters
        );
    }
    Ok(())
}

#[account]
pub struct VoucherClaim {
    pub voucher_id: [u8; 16],
    pub player: Pubkey,
    pub loot_id: u64,
    pub claimed_at: i64,
    pub bump: u8,
}

impl VoucherClaim {
    pub const SPACE: usize = 8 + 16 + 32 + 8 + 8 + 1;
}

/// One claim per loot id, independent of the voucher id. Stops a second
/// voucher for the same cache from minting another NFT.
#[account]
pub struct LootClaim {
    pub loot_id: u64,
    pub player: Pubkey,
    pub voucher_id: [u8; 16],
    pub claimed_at: i64,
    pub bump: u8,
}

impl LootClaim {
    pub const SPACE: usize = 8 + 8 + 32 + 16 + 8 + 1;
}

/// Per-cluster Ed25519 server keys and the claim pause flag.
///
/// `server_keys[0]` is unused so `CLUSTER_TAG` indexes the slot directly:
/// 1 mainnet-beta, 2 devnet, 3 localnet. `claim_loot` reads only the slot for
/// the cluster this binary was built for. Callers cannot supply a key.
#[account]
pub struct VoucherGuard {
    pub server_keys: [Pubkey; 4],
    pub paused: bool,
    pub bump: u8,
}

impl VoucherGuard {
    pub const SPACE: usize = 8 + (32 * 4) + 1 + 1;

    pub fn active_server_key(&self) -> Pubkey {
        self.server_keys[CLUSTER_TAG as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(hint: &str, issued_at: i64, expires_at: i64) -> LootVoucherV1 {
        let mut voucher_id = [0u8; 16];
        for (i, b) in voucher_id.iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        LootVoucherV1 {
            voucher_id,
            loot_id: 42,
            lat_e6: 37_774_900,
            lng_e6: -122_419_400,
            location_hint: hint.to_string(),
            issued_at,
            expires_at,
        }
    }

    fn assert_code(err: anchor_lang::error::Error, expected: ErrorCode) {
        assert_eq!(err, expected.into());
    }

    #[test]
    fn message_len_is_169_and_hint_bounds() {
        let now = 1_700_000_000;
        let ok = sample(&"h".repeat(64), now, now + MAX_VOUCHER_TTL_SECS);
        let msg = ok.message(&crate::ID, &Pubkey::default());
        assert_eq!(msg.len(), 169);
        assert_eq!(VOUCHER_MSG_LEN, 169);
        assert_eq!(&msg[..24], b"FIZZCAPS:LOOT_VOUCHER:v1");
        assert_eq!(msg[24], CLUSTER_TAG);
        ok.check_shape_and_time(now).unwrap();

        let long = sample(&"h".repeat(65), now, now + 60);
        assert_code(
            long.check_shape_and_time(now).unwrap_err(),
            ErrorCode::VoucherBadShape,
        );
    }

    #[test]
    fn message_binds_player_and_changes_when_player_changes() {
        let now = 1_700_000_000;
        let v = sample("behind the vault door", now, now + 300);
        let player_a = Pubkey::new_from_array([7u8; 32]);
        let player_b = Pubkey::new_from_array([9u8; 32]);
        let a = v.message(&crate::ID, &player_a);
        let b = v.message(&crate::ID, &player_b);
        assert_ne!(a, b);
        assert_eq!(&a[57..89], player_a.as_ref());
        assert_eq!(&b[57..89], player_b.as_ref());
        assert_eq!(&a[25..57], crate::ID.as_ref());
    }

    #[cfg(feature = "localnet")]
    #[test]
    fn golden_message_matches_js_fixture() {
        let raw = include_str!("../../../anchor-tests/fixtures/voucher_v1_golden.hex");
        let expected = decode_hex(raw.trim());
        assert_eq!(expected.len(), 169);
        let v = sample("behind the vault door", 1_700_000_000, 1_700_000_300);
        let player = Pubkey::default();
        let msg = v.message(&crate::ID, &player);
        assert_eq!(msg.as_slice(), expected.as_slice());
    }

    #[test]
    fn parser_accepts_web3_js_layout_and_not_the_swapped_offset() {
        // Bytes produced by Ed25519Program.createInstructionWithPublicKey.
        // See anchor-tests/fixtures/ed25519_ix.hex (regenerated by
        // anchor-tests/scripts/gen-ed25519-fixture.js).
        let data = decode_hex(include_str!("../../../anchor-tests/fixtures/ed25519_ix.hex").trim());
        let pubkey = decode_hex(include_str!("../../../anchor-tests/fixtures/ed25519_pubkey.hex").trim());
        let signature = decode_hex(include_str!("../../../anchor-tests/fixtures/ed25519_sig.hex").trim());
        let message = decode_hex(include_str!("../../../anchor-tests/fixtures/ed25519_msg.hex").trim());
        assert_eq!(message.len(), 169);

        // Header field the old parser misread: bytes 2..4 are the signature
        // offset (48), not the pubkey offset. The pubkey offset is bytes 6..8.
        assert_eq!(u16::from_le_bytes([data[2], data[3]]), 48);
        assert_eq!(u16::from_le_bytes([data[6], data[7]]), 16);
        assert_eq!(u16::from_le_bytes([data[4], data[5]]), u16::MAX);

        let (pk, sig, msg) = parse_ed25519_ix_data(&data).unwrap();
        assert_eq!(pk, pubkey.as_slice());
        assert_eq!(sig, signature.as_slice());
        assert_eq!(msg, message.as_slice());
        // The swapped read would have returned signature bytes as the pubkey.
        assert_ne!(&data[48..80], pubkey.as_slice());
    }

    #[test]
    fn parser_rejects_bad_layouts() {
        let mut data = decode_hex(include_str!("../../../anchor-tests/fixtures/ed25519_ix.hex").trim());

        let mut zero_sigs = data.clone();
        zero_sigs[0] = 0;
        assert_code(
            parse_ed25519_ix_data(&zero_sigs).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );
        let mut two_sigs = data.clone();
        two_sigs[0] = 2;
        assert_code(
            parse_ed25519_ix_data(&two_sigs).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );

        // Each of the three instruction indexes must be 0xFFFF.
        for off in [4usize, 8, 14] {
            let mut bad = data.clone();
            bad[off] = 0;
            bad[off + 1] = 0;
            assert_code(
                parse_ed25519_ix_data(&bad).unwrap_err(),
                ErrorCode::Ed25519BadLayout,
            );
        }

        // message length must be exactly 169 even when the slice would fit.
        let mut short_msg = data.clone();
        short_msg[12] = 168;
        short_msg[13] = 0;
        assert_code(
            parse_ed25519_ix_data(&short_msg).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );
        // 170-byte message: extend the buffer so the slice is in-bounds.
        let mut long_msg = data.clone();
        long_msg.push(0);
        long_msg[12] = 170;
        long_msg[13] = 0;
        assert_code(
            parse_ed25519_ix_data(&long_msg).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );

        let mut past_end = data.clone();
        past_end[6] = 0xff;
        past_end[7] = 0xff; // pubkey offset = 65535
        assert_code(
            parse_ed25519_ix_data(&past_end).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );

        assert_code(
            parse_ed25519_ix_data(&data[..15]).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );

        assert_code(
            checked_slice(&[1, 2, 3], usize::MAX, 1).unwrap_err(),
            ErrorCode::Ed25519BadLayout,
        );

        // Keep `data` mutable use honest for the compiler.
        data[0] = 1;
    }

    #[test]
    fn time_rules() {
        let now = 1_700_000_000i64;
        let cases: &[(i64, i64, Option<ErrorCode>)] = &[
            (now - 100, now - 10, Some(ErrorCode::VoucherExpired)),
            (now + 31, now + 31 + 60, Some(ErrorCode::VoucherNotYetValid)),
            (now, now, Some(ErrorCode::VoucherBadShape)), // ttl 0
            (now, now + 301, Some(ErrorCode::VoucherTtlTooLong)),
            (now, now + 300, None),
            (now + 30, now + 30 + 300, None), // skew +30
            (now - 10, now + 290, None),
            (now, now + 1, None),
        ];
        for (issued, expires, expect) in cases {
            let v = sample("hint", *issued, *expires);
            match (v.check_shape_and_time(now), expect) {
                (Ok(()), None) => {}
                (Err(e), Some(code)) => assert_code(e, *code),
                (Ok(()), Some(code)) => panic!("expected {code:?}"),
                (Err(e), None) => panic!("unexpected {e:?}"),
            }
        }

        let bad_lat = LootVoucherV1 {
            lat_e6: 90_000_001,
            ..sample("hint", now, now + 10)
        };
        assert_code(
            bad_lat.check_shape_and_time(now).unwrap_err(),
            ErrorCode::VoucherBadShape,
        );
        let bad_lng = LootVoucherV1 {
            lng_e6: -180_000_001,
            ..sample("hint", now, now + 10)
        };
        assert_code(
            bad_lng.check_shape_and_time(now).unwrap_err(),
            ErrorCode::VoucherBadShape,
        );
    }

    #[test]
    fn server_keys_are_per_cluster() {
        let a = Pubkey::new_from_array([1u8; 32]);
        let b = Pubkey::new_from_array([2u8; 32]);
        let mut keys = [Pubkey::default(); 4];
        assert_distinct_server_key(&keys, 3, a).unwrap();
        keys[3] = a;
        assert_distinct_server_key(&keys, 2, b).unwrap();
        assert_code(
            assert_distinct_server_key(&keys, 2, a).unwrap_err(),
            ErrorCode::ServerKeyReusedAcrossClusters,
        );
        assert_code(
            assert_distinct_server_key(&keys, 0, b).unwrap_err(),
            ErrorCode::VoucherBadShape,
        );
        assert_code(
            assert_distinct_server_key(&keys, 1, Pubkey::default()).unwrap_err(),
            ErrorCode::WrongVoucherSigner,
        );
        // Replacing the same slot with the same key is allowed.
        assert_distinct_server_key(&keys, 3, a).unwrap();
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
