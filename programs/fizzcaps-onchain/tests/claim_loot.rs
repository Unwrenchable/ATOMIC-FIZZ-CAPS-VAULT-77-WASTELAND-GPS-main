//! Executed local-validator coverage for claim_loot.
//!
//! The program and Metaplex both run as SBF inside solana-program-test.
//! Build the program first, then copy the ELF next to the Metaplex fixture:
//!
//!   cargo-build-sbf --manifest-path programs/fizzcaps-onchain/Cargo.toml \
//!     --features localnet --tools-version v1.58 --sbf-out-dir target/deploy
//!   cp target/deploy/fizzcaps_onchain.so programs/fizzcaps-onchain/tests/fixtures/
//!   node scripts/fetch-metadata-program.js
//!   cargo test -p fizzcaps_onchain --features localnet --test claim_loot

use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use ed25519_dalek::Signer;
use fizzcaps_onchain::accounts::ClaimLoot as ClaimLootAccounts;
use fizzcaps_onchain::instruction::ClaimLoot as ClaimLootIx;
use fizzcaps_onchain::{
    FizzConfig, LootVoucherV1, VoucherGuard, ID, CLUSTER_TAG, VOUCHER_CLAIM_SEED,
    VOUCHER_GUARD_SEED,
};
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer as SdkSigner},
    system_program,
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccountState, AccountState, Mint};

const ISSUED: i64 = 1_700_000_000;
const FEE: u64 = 100 * 1_000_000_000;

fn pda(seeds: &[&[u8]]) -> (Pubkey, u8) {
    Pubkey::find_program_address(seeds, &ID)
}

fn owned(owner: Pubkey, data: Vec<u8>, lamports: u64) -> Account {
    Account {
        lamports,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn anchor_data<T: AccountSerialize>(value: &T) -> Vec<u8> {
    let mut data = Vec::new();
    value.try_serialize(&mut data).unwrap();
    data
}

fn pack_mint(mint: &Mint) -> Vec<u8> {
    let mut data = vec![0u8; Mint::LEN];
    mint.pack_into_slice(&mut data);
    data
}

fn pack_token(account: &TokenAccountState) -> Vec<u8> {
    let mut data = vec![0u8; TokenAccountState::LEN];
    account.pack_into_slice(&mut data);
    data
}

fn ed25519_ix(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Instruction {
    assert_eq!(message.len(), 169);
    let mut data = vec![0u8; 112 + message.len()];
    data[0] = 1;
    data[2..4].copy_from_slice(&48u16.to_le_bytes());
    data[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    data[6..8].copy_from_slice(&16u16.to_le_bytes());
    data[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    data[10..12].copy_from_slice(&112u16.to_le_bytes());
    data[12..14].copy_from_slice(&(message.len() as u16).to_le_bytes());
    data[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    data[16..48].copy_from_slice(pubkey);
    data[48..112].copy_from_slice(signature);
    data[112..].copy_from_slice(message);
    Instruction {
        program_id: solana_sdk_ids::ed25519_program::id(),
        accounts: vec![],
        data,
    }
}

fn sign_message(secret_key: &Keypair, message: &[u8]) -> [u8; 64] {
    let bytes = secret_key.to_bytes();
    let signing = ed25519_dalek::SigningKey::from_bytes(&bytes[..32].try_into().unwrap());
    let sig = signing.sign(message);
    assert_eq!(signing.verifying_key().as_bytes(), secret_key.pubkey().as_ref());
    sig.to_bytes()
}

struct World {
    player: Keypair,
    server: Keypair,
    config: Pubkey,
    guard: Pubkey,
    caps_mint: Pubkey,
    loot_auth: Pubkey,
    player_caps: Pubkey,
    loot_mint: Pubkey,
    player_loot: Pubkey,
    ctx: ProgramTestContext,
}

async fn start() -> World {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for name in ["fizzcaps_onchain.so", "mpl_token_metadata.so"] {
        let path = fixtures.join(name);
        assert!(path.exists(), "missing {} — see the module docs", path.display());
    }

    let player = Keypair::new();
    let server = Keypair::new();
    let (config, config_bump) = pda(&[b"fizz-config"]);
    let (guard, guard_bump) = pda(&[VOUCHER_GUARD_SEED]);
    let (caps_mint, _) = pda(&[b"caps-mint"]);
    let (loot_auth, _) = pda(&[b"loot-mint-auth"]);
    let player_caps = Pubkey::new_unique();

    let mut keys = [Pubkey::default(); 4];
    keys[CLUSTER_TAG as usize] = server.pubkey();
    let guard_account = VoucherGuard {
        server_keys: keys,
        paused: false,
        bump: guard_bump,
    };
    let config_account = FizzConfig {
        authority: player.pubkey(),
        treasury: player.pubkey(),
        caps_mint,
        total_tokens_launched: 0,
        total_volume_sol: 0,
        total_caps_burned: 0,
        admin_usdc_launches: 0,
        server_key: server.pubkey(),
        bump: config_bump,
    };

    let mut pt = ProgramTest::default();
    pt.prefer_bpf(true);
    pt.add_program("fizzcaps_onchain", ID, None);
    pt.add_program("mpl_token_metadata", mpl_token_metadata::ID, None);
    pt.add_account(
        player.pubkey(),
        owned(system_program::id(), vec![], 20_000_000_000),
    );
    pt.add_account(
        config,
        owned(ID, anchor_data(&config_account), 10_000_000),
    );
    pt.add_account(guard, owned(ID, anchor_data(&guard_account), 10_000_000));
    pt.add_account(
        caps_mint,
        owned(
            spl_token::id(),
            pack_mint(&Mint {
                mint_authority: COption::Some(player.pubkey()),
                supply: 1_000 * FEE,
                decimals: 9,
                is_initialized: true,
                freeze_authority: COption::None,
            }),
            10_000_000,
        ),
    );
    pt.add_account(
        player_caps,
        owned(
            spl_token::id(),
            pack_token(&TokenAccountState {
                mint: caps_mint,
                owner: player.pubkey(),
                amount: 500 * FEE,
                state: AccountState::Initialized,
                ..TokenAccountState::default()
            }),
            10_000_000,
        ),
    );
    let loot_mint = Pubkey::new_unique();
    let player_loot = Pubkey::new_unique();
    let loot_accounts = fresh_loot_accounts(loot_auth, loot_mint, player_loot, player.pubkey());
    for (key, account) in loot_accounts {
        pt.add_account(key, account);
    }

    let ctx = pt.start_with_context().await;
    let mut clock = ctx.banks_client.get_sysvar::<Clock>().await.unwrap();
    clock.unix_timestamp = ISSUED;
    ctx.set_sysvar(&clock);

    World {
        player,
        server,
        config,
        guard,
        caps_mint,
        loot_auth,
        player_caps,
        loot_mint,
        player_loot,
        ctx,
    }
}

fn fresh_loot_accounts(
    loot_auth: Pubkey,
    loot_mint: Pubkey,
    player_loot: Pubkey,
    player: Pubkey,
) -> Vec<(Pubkey, Account)> {
    vec![
        (
            loot_mint,
            owned(
                spl_token::id(),
                pack_mint(&Mint {
                    mint_authority: COption::Some(loot_auth),
                    supply: 0,
                    decimals: 0,
                    is_initialized: true,
                    freeze_authority: COption::Some(loot_auth),
                }),
                10_000_000,
            ),
        ),
        (
            player_loot,
            owned(
                spl_token::id(),
                pack_token(&TokenAccountState {
                    mint: loot_mint,
                    owner: player,
                    amount: 0,
                    state: AccountState::Initialized,
                    ..TokenAccountState::default()
                }),
                10_000_000,
            ),
        ),
    ]
}

fn voucher(loot_id: u64, voucher_id: [u8; 16]) -> LootVoucherV1 {
    LootVoucherV1 {
        voucher_id,
        loot_id,
        lat_e6: 36_115_900,
        lng_e6: -115_173_400,
        location_hint: "cache".to_string(),
        issued_at: ISSUED,
        expires_at: ISSUED + 300,
    }
}

fn claim_ix(
    world: &World,
    voucher: &LootVoucherV1,
    loot_mint: Pubkey,
    player_loot: Pubkey,
) -> Instruction {
    let (voucher_claim, _) = pda(&[VOUCHER_CLAIM_SEED, voucher.voucher_id.as_ref()]);
    let (loot_claim, _) = pda(&[b"loot-claim", &voucher.loot_id.to_le_bytes()]);
    let (metadata, _) = Pubkey::find_program_address(
        &[
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            loot_mint.as_ref(),
        ],
        &mpl_token_metadata::ID,
    );
    let (edition, _) = Pubkey::find_program_address(
        &[
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            loot_mint.as_ref(),
            b"edition",
        ],
        &mpl_token_metadata::ID,
    );
    let accounts = ClaimLootAccounts {
        player: world.player.pubkey(),
        config: world.config,
        voucher_guard: world.guard,
        caps_mint: world.caps_mint,
        player_caps_ata: world.player_caps,
        loot_mint,
        player_loot_ata: player_loot,
        loot_mint_authority: world.loot_auth,
        loot_metadata: metadata,
        loot_master_edition: edition,
        voucher_claim,
        loot_claim,
        token_program: spl_token::id(),
        metadata_program: mpl_token_metadata::ID,
        system_program: system_program::id(),
        instructions_sysvar: solana_sdk::sysvar::instructions::id(),
    };
    Instruction {
        program_id: ID,
        accounts: accounts.to_account_metas(None),
        data: ClaimLootIx {
            voucher: voucher.clone(),
        }
        .data(),
    }
}

async fn send(world: &mut World, ixs: &[Instruction]) -> std::result::Result<(), String> {
    let hash = world
        .ctx
        .banks_client
        .get_latest_blockhash()
        .await
        .map_err(|e| format!("{e:?}"))?;
    world.ctx.last_blockhash = hash;
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&world.player.pubkey()),
        &[&world.player],
        hash,
    );
    match world.ctx.banks_client.process_transaction_with_metadata(tx).await {
        Ok(meta) => match meta.result {
            Ok(()) => Ok(()),
            Err(err) => Err(format!(
                "{err:?}\n{}",
                meta.metadata
                    .map(|m| m.log_messages.join("\n"))
                    .unwrap_or_default()
            )),
        },
        Err(err) => Err(format!("{err:?}")),
    }
}

#[tokio::test]
async fn claim_loot_happy_path_replay_wrong_signer_and_missing_ed25519() {
    assert_eq!(CLUSTER_TAG, 3, "this test is the localnet build");
    let mut world = start().await;
    let voucher = voucher(42, [7u8; 16]);
    let message = voucher.message(&ID, &world.player.pubkey());
    let claim = claim_ix(&world, &voucher, world.loot_mint, world.player_loot);

    let missing = send(&mut world, &[claim.clone()]).await.unwrap_err();
    assert!(
        missing.contains("Missing Ed25519") || missing.contains("MissingEd25519Ix"),
        "missing ed25519: {missing}"
    );

    let attacker = Keypair::new();
    let bad_sig = sign_message(&attacker, &message);
    let bad_ed = ed25519_ix(&attacker.pubkey().to_bytes(), &bad_sig, &message);
    let wrong = send(&mut world, &[bad_ed, claim.clone()]).await.unwrap_err();
    assert!(
        wrong.contains("WrongVoucherSigner") || wrong.contains("configured server key"),
        "wrong signer: {wrong}"
    );

    let sig = sign_message(&world.server, &message);
    let ed = ed25519_ix(&world.server.pubkey().to_bytes(), &sig, &message);
    send(&mut world, &[ed.clone(), claim.clone()])
        .await
        .expect("happy path");

    let caps = world
        .ctx
        .banks_client
        .get_account(world.player_caps)
        .await
        .unwrap()
        .unwrap();
    let caps_account = TokenAccountState::unpack(&caps.data).unwrap();
    assert_eq!(caps_account.amount, 500 * FEE - FEE);
    let loot = world
        .ctx
        .banks_client
        .get_account(world.player_loot)
        .await
        .unwrap()
        .unwrap();
    let loot_account = TokenAccountState::unpack(&loot.data).unwrap();
    assert_eq!(loot_account.amount, 1);

    // A byte-identical resubmit is rejected by the bank before the program
    // runs. Advance one slot so the replay is a new transaction, then pin the
    // clock so the voucher is still inside its TTL and the PDA init is what fails.
    let slot = world.ctx.banks_client.get_sysvar::<Clock>().await.unwrap().slot;
    world.ctx.warp_to_slot(slot + 1).unwrap();
    let mut clock = world.ctx.banks_client.get_sysvar::<Clock>().await.unwrap();
    clock.unix_timestamp = ISSUED;
    world.ctx.set_sysvar(&clock);

    let replay = send(&mut world, &[ed, claim]).await.unwrap_err();
    assert!(
        replay.contains("already in use") || replay.contains("already exists"),
        "replay: {replay}"
    );
}
