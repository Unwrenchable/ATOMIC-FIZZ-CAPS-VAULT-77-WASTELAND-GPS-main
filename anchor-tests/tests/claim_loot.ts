/**
 * Integration coverage for claim_loot.
 *
 * N14 (CPI): claim_loot loads the top-level instruction and requires its
 * program id to equal crate::ID (ErrorCode::CpiNotAllowed). A second program
 * that CPIs into claim_loot is not built in this suite. Do not remove that
 * check. Confirm it on a devnet CPI harness before any deploy. This file does
 * not drop the requirement; the handler in voucher.rs still enforces it.
 *
 * Run from the repo root after `anchor build -- --features localnet`:
 *   bash anchor-tests/scripts/fetch-metadata.sh
 *   anchor test --skip-build --skip-lint
 */

import { createHash } from "crypto";
import * as anchor from "@coral-xyz/anchor";
import BN from "bn.js";
import { expect } from "chai";
import nacl from "tweetnacl";
import {
  createMint,
  getAccount,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

const { PublicKey, Keypair, SystemProgram, Ed25519Program, ComputeBudgetProgram, Transaction } =
  anchor.web3;

const METADATA_PROGRAM_ID = new PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
const BPF_LOADER = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const CLUSTER_TAG = 3; // localnet build
const FEE = 100n * 1_000_000_000n;

describe("claim_loot", function () {
  this.timeout(180000);

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.FizzcapsOnchain;
  const connection = provider.connection;
  const authority = provider.wallet;
  const server = Keypair.generate();
  const player = Keypair.generate();
  const other = Keypair.generate();

  let capsMint: anchor.web3.PublicKey;
  let config: anchor.web3.PublicKey;
  let guard: anchor.web3.PublicKey;
  let lootAuth: anchor.web3.PublicKey;
  let programData: anchor.web3.PublicKey;
  let nextLoot = 1000;

  function pda(seeds: Buffer[], programId = program.programId) {
    return PublicKey.findProgramAddressSync(seeds, programId)[0];
  }

  function u64le(n: number | bigint) {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(n));
    return b;
  }

  function buildMessage(opts: {
    player: anchor.web3.PublicKey;
    voucherId: Buffer;
    lootId: number;
    latE6: number;
    lngE6: number;
    hint: string;
    issuedAt: number;
    expiresAt: number;
    clusterTag?: number;
    programId?: anchor.web3.PublicKey;
  }) {
    const buf = Buffer.alloc(169);
    let o = 0;
    const put = (b: Buffer) => {
      b.copy(buf, o);
      o += b.length;
    };
    put(Buffer.from("FIZZCAPS:LOOT_VOUCHER:v1", "ascii"));
    put(Buffer.from([opts.clusterTag ?? CLUSTER_TAG]));
    put((opts.programId ?? program.programId).toBuffer());
    put(opts.player.toBuffer());
    put(opts.voucherId);
    put(u64le(opts.lootId));
    const lat = Buffer.alloc(4);
    lat.writeInt32LE(opts.latE6);
    put(lat);
    const lng = Buffer.alloc(4);
    lng.writeInt32LE(opts.lngE6);
    put(lng);
    put(createHash("sha256").update(Buffer.from(opts.hint, "utf8")).digest());
    const issued = Buffer.alloc(8);
    issued.writeBigInt64LE(BigInt(opts.issuedAt));
    put(issued);
    const exp = Buffer.alloc(8);
    exp.writeBigInt64LE(BigInt(opts.expiresAt));
    put(exp);
    if (o !== 169) throw new Error("layout drift " + o);
    return buf;
  }

  function voucherArgs(v: {
    voucherId: Buffer;
    lootId: number;
    latE6: number;
    lngE6: number;
    hint: string;
    issuedAt: number;
    expiresAt: number;
  }) {
    return {
      voucherId: Array.from(v.voucherId),
      lootId: new BN(v.lootId),
      latE6: v.latE6,
      lngE6: v.lngE6,
      locationHint: v.hint,
      issuedAt: new BN(v.issuedAt),
      expiresAt: new BN(v.expiresAt),
    };
  }

  async function airdrop(pk: anchor.web3.PublicKey) {
    const sig = await connection.requestAirdrop(pk, 2 * anchor.web3.LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig, "confirmed");
  }

  async function freshLootMint() {
    return createMint(connection, player, lootAuth, lootAuth, 0);
  }

  async function claimAccounts(opts: {
    claimant: anchor.web3.Keypair;
    lootMint: anchor.web3.PublicKey;
    voucherId: Buffer;
    lootId: number;
    capsMintOverride?: anchor.web3.PublicKey;
    metadataOverride?: anchor.web3.PublicKey;
    sysvarOverride?: anchor.web3.PublicKey;
  }) {
    const caps = opts.capsMintOverride ?? capsMint;
    const capsAta = await getOrCreateAssociatedTokenAccount(
      connection,
      opts.claimant,
      caps,
      opts.claimant.publicKey
    );
    const lootAta = await getOrCreateAssociatedTokenAccount(
      connection,
      opts.claimant,
      opts.lootMint,
      opts.claimant.publicKey
    );
    const metadata =
      opts.metadataOverride ??
      pda(
        [Buffer.from("metadata"), METADATA_PROGRAM_ID.toBuffer(), opts.lootMint.toBuffer()],
        METADATA_PROGRAM_ID
      );
    const masterEdition = pda(
      [
        Buffer.from("metadata"),
        METADATA_PROGRAM_ID.toBuffer(),
        opts.lootMint.toBuffer(),
        Buffer.from("edition"),
      ],
      METADATA_PROGRAM_ID
    );
    return {
      player: opts.claimant.publicKey,
      config,
      voucherGuard: guard,
      capsMint: caps,
      playerCapsAta: capsAta.address,
      lootMint: opts.lootMint,
      playerLootAta: lootAta.address,
      lootMintAuthority: lootAuth,
      lootMetadata: metadata,
      lootMasterEdition: masterEdition,
      voucherClaim: pda([Buffer.from("voucher-claim"), opts.voucherId]),
      lootClaim: pda([Buffer.from("loot-claim"), u64le(opts.lootId)]),
      tokenProgram: TOKEN_PROGRAM_ID,
      metadataProgram: METADATA_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
      instructionsSysvar:
        opts.sysvarOverride ?? anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
    };
  }

  async function sendClaim(opts: {
    claimant?: anchor.web3.Keypair;
    signer?: Keypair;
    messagePlayer?: anchor.web3.PublicKey;
    lootId?: number;
    latE6?: number;
    lngE6?: number;
    hint?: string;
    issuedAt?: number;
    expiresAt?: number;
    voucherId?: Buffer;
    clusterTag?: number;
    programId?: anchor.web3.PublicKey;
    edPublicKey?: Uint8Array;
    tamper?: (args: ReturnType<typeof voucherArgs>, signed: any) => void;
    between?: anchor.web3.TransactionInstruction[];
    omitEd?: boolean;
    accountsExtra?: Partial<{
      capsMintOverride: anchor.web3.PublicKey;
      metadataOverride: anchor.web3.PublicKey;
      sysvarOverride: anchor.web3.PublicKey;
      lootMint: anchor.web3.PublicKey;
    }>;
    instructionsDataPatch?: (data: Buffer) => Buffer;
    leadingCompute?: boolean;
  }) {
    const claimant = opts.claimant ?? player;
    const now = Math.floor(Date.now() / 1000);
    const fields = {
      voucherId: opts.voucherId ?? Buffer.from(Keypair.generate().publicKey.toBytes().subarray(0, 16)),
      lootId: opts.lootId ?? nextLoot++,
      latE6: opts.latE6 ?? 36115900,
      lngE6: opts.lngE6 ?? -115173400,
      hint: opts.hint ?? "cache",
      issuedAt: opts.issuedAt ?? now,
      expiresAt: opts.expiresAt ?? now + 300,
    };
    const lootMint = opts.accountsExtra?.lootMint ?? (await freshLootMint());
    const msg = buildMessage({
      player: opts.messagePlayer ?? claimant.publicKey,
      voucherId: fields.voucherId,
      lootId: fields.lootId,
      latE6: fields.latE6,
      lngE6: fields.lngE6,
      hint: fields.hint,
      issuedAt: fields.issuedAt,
      expiresAt: fields.expiresAt,
      clusterTag: opts.clusterTag,
      programId: opts.programId,
    });
    const sig = nacl.sign.detached(Uint8Array.from(msg), (opts.signer ?? server).secretKey);
    let edIx = Ed25519Program.createInstructionWithPublicKey({
      publicKey: opts.edPublicKey ?? (opts.signer ?? server).publicKey.toBytes(),
      message: msg,
      signature: sig,
    });
    if (opts.instructionsDataPatch) {
      edIx = new anchor.web3.TransactionInstruction({
        keys: edIx.keys,
        programId: edIx.programId,
        data: opts.instructionsDataPatch(Buffer.from(edIx.data)),
      });
    }
    const args = voucherArgs(fields);
    if (opts.tamper) opts.tamper(args, fields);
    const accounts = await claimAccounts({
      claimant,
      lootMint,
      voucherId: fields.voucherId,
      lootId: fields.lootId,
      capsMintOverride: opts.accountsExtra?.capsMintOverride,
      metadataOverride: opts.accountsExtra?.metadataOverride,
      sysvarOverride: opts.accountsExtra?.sysvarOverride,
    });
    const claimIx = await program.methods.claimLoot(args).accounts(accounts).instruction();
    const tx = new Transaction();
    if (opts.leadingCompute !== false) {
      tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }));
    }
    if (!opts.omitEd) tx.add(edIx);
    for (const ix of opts.between ?? []) tx.add(ix);
    tx.add(claimIx);
    await provider.sendAndConfirm(tx, [claimant]);
    return { fields, accounts, lootMint };
  }

  async function expectFail(fn: () => Promise<unknown>, needle: string) {
    try {
      await fn();
      expect.fail("transaction should have failed");
    } catch (err) {
      const text = String(err) + " " + ((err as { logs?: string[] }).logs || []).join(" ");
      expect(text).to.include(needle);
    }
  }

  before(async () => {
    await airdrop(player.publicKey);
    await airdrop(other.publicKey);
    capsMint = pda([Buffer.from("caps-mint")]);
    [programData] = PublicKey.findProgramAddressSync([program.programId.toBuffer()], BPF_LOADER);

    const stranger = Keypair.generate();
    await airdrop(stranger.publicKey);
    await expectFail(
      () =>
        program.methods
          .initializeCaps()
          .accounts({
            authority: stranger.publicKey,
            program: program.programId,
            programData,
            capsMint,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .signers([stranger])
          .rpc(),
      "NotUpgradeAuthority"
    );

    await program.methods
      .initializeCaps()
      .accounts({
        authority: authority.publicKey,
        program: program.programId,
        programData,
        capsMint,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    const capsInfo = await connection.getParsedAccountInfo(capsMint);
    const decimals = (capsInfo.value?.data as { parsed?: { info?: { decimals?: number } } }).parsed?.info?.decimals;
    expect(decimals).to.equal(9);
    const playerCaps = await getOrCreateAssociatedTokenAccount(
      connection,
      player,
      capsMint,
      player.publicKey
    );
    await mintTo(connection, authority.payer, capsMint, playerCaps.address, authority.payer, 1_000n * 1_000_000_000n);
    const otherCaps = await getOrCreateAssociatedTokenAccount(
      connection,
      other,
      capsMint,
      other.publicKey
    );
    await mintTo(connection, authority.payer, capsMint, otherCaps.address, authority.payer, 500n * 1_000_000_000n);

    config = pda([Buffer.from("fizz-config")]);
    guard = pda([Buffer.from("voucher-guard")]);
    lootAuth = pda([Buffer.from("loot-mint-auth")]);

    await expectFail(
      () =>
        program.methods
          .fizzInit(server.publicKey)
          .accounts({
            authority: stranger.publicKey,
            program: program.programId,
            programData,
            config,
            voucherGuard: guard,
            treasury: authority.publicKey,
            capsMint,
            systemProgram: SystemProgram.programId,
          })
          .signers([stranger])
          .rpc(),
      "NotUpgradeAuthority"
    );

    await program.methods
      .fizzInit(server.publicKey)
      .accounts({
        authority: authority.publicKey,
        program: program.programId,
        programData,
        config,
        voucherGuard: guard,
        treasury: authority.publicKey,
        capsMint,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  });

  it("T1 happy path burns 100 CAPS and records both PDAs", async () => {
    const before = await getAccount(
      connection,
      (await getOrCreateAssociatedTokenAccount(connection, player, capsMint, player.publicKey)).address
    );
    const result = await sendClaim({});
    const after = await getAccount(connection, result.accounts.playerCapsAta);
    expect(before.amount - after.amount).to.equal(FEE);
    const loot = await getAccount(connection, result.accounts.playerLootAta);
    expect(loot.amount).to.equal(1n);
    const meta = await connection.getAccountInfo(result.accounts.lootMetadata);
    expect(meta).to.not.equal(null);
    const claim = await program.account.voucherClaim.fetch(result.accounts.voucherClaim);
    expect(claim.player.toBase58()).to.equal(player.publicKey.toBase58());
    expect(claim.lootId.toNumber()).to.equal(result.fields.lootId);
    const lootClaim = await program.account.lootClaim.fetch(result.accounts.lootClaim);
    expect(lootClaim.lootId.toNumber()).to.equal(result.fields.lootId);
  });

  it("T2 rotates the localnet server key", async () => {
    const next = Keypair.generate();
    await program.methods
      .fizzSetServerKey(CLUSTER_TAG, next.publicKey)
      .accounts({
        config,
        voucherGuard: guard,
        authority: authority.publicKey,
      })
      .rpc();
    await expectFail(() => sendClaim({ signer: server, edPublicKey: server.publicKey.toBytes() }), "WrongVoucherSigner");
    await sendClaim({ signer: next, edPublicKey: next.publicKey.toBytes() });
    await program.methods
      .fizzSetServerKey(CLUSTER_TAG, server.publicKey)
      .accounts({ config, voucherGuard: guard, authority: authority.publicKey })
      .rpc();
  });

  it("N1 rejects a replayed voucher id and a replayed loot id", async () => {
    const voucherId = Buffer.alloc(16, 7);
    const lootId = nextLoot++;
    await sendClaim({ voucherId, lootId });
    await expectFail(() => sendClaim({ voucherId, lootId: nextLoot++ }), "already in use");
    await expectFail(() => sendClaim({ lootId }), "already in use");
  });

  it("N2 rejects an attacker key placed in the Ed25519 instruction", async () => {
    const attacker = Keypair.generate();
    await expectFail(
      () => sendClaim({ signer: attacker, edPublicKey: attacker.publicKey.toBytes() }),
      "WrongVoucherSigner"
    );
  });

  it("N3 rejects a tampered field after signing", async () => {
    await expectFail(
      () =>
        sendClaim({
          // loot_id is a PDA seed, so changing it fails account resolution
          // before the message check. lat_e6 is signed and is not a seed.
          tamper: (args) => {
            args.latE6 = args.latE6 + 1;
          },
        }),
      "VoucherMessageMismatch"
    );
  });

  it("N4 rejects a voucher signed for a different player", async () => {
    await expectFail(
      () => sendClaim({ claimant: other, messagePlayer: player.publicKey }),
      "VoucherMessageMismatch"
    );
  });

  it("N5 rejects the wrong cluster tag and program id", async () => {
    await expectFail(() => sendClaim({ clusterTag: 1 }), "VoucherMessageMismatch");
    await expectFail(
      () => sendClaim({ programId: Keypair.generate().publicKey }),
      "VoucherMessageMismatch"
    );
  });

  it("N6 N7 N8 reject expired, future, and overlong vouchers", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expectFail(
      () => sendClaim({ issuedAt: now - 100, expiresAt: now - 10 }),
      "VoucherExpired"
    );
    await expectFail(
      () => sendClaim({ issuedAt: now + 3600, expiresAt: now + 3600 + 60 }),
      "VoucherNotYetValid"
    );
    await expectFail(
      () => sendClaim({ issuedAt: now, expiresAt: now + 301 }),
      "VoucherTtlTooLong"
    );
  });

  it("N9 rejects a missing Ed25519 instruction", async () => {
    await expectFail(() => sendClaim({ omitEd: true }), "MissingEd25519Ix");
  });

  it("N10 rejects a non-adjacent Ed25519 instruction", async () => {
    await expectFail(
      () =>
        sendClaim({
          between: [ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 })],
        }),
      "MissingEd25519Ix"
    );
  });

  it("N11 rejects an Ed25519 ix whose message index is not u16::MAX", async () => {
    await expectFail(
      () =>
        sendClaim({
          leadingCompute: false,
          instructionsDataPatch: (data) => {
            const copy = Buffer.from(data);
            // Ed25519 ix is at index 0. Index 0 is not the u16::MAX sentinel,
            // but it names this same instruction, so the precompile still verifies.
            copy.writeUInt16LE(0, 14);
            return copy;
          },
        }),
      "Ed25519BadLayout"
    );
  });

  it("N15 rejects a caps mint that is not config.caps_mint", async () => {
    const fake = await createMint(connection, player, player.publicKey, null, 9);
    await expectFail(
      () => sendClaim({ accountsExtra: { capsMintOverride: fake } }),
      "ConstraintSeeds"
    );
  });

  it("N17 rejects a loot mint that already has supply", async () => {
    const dirty = await createMint(connection, player, lootAuth, null, 0);
    const ata = await getOrCreateAssociatedTokenAccount(connection, player, dirty, player.publicKey);
    // Mint authority is the PDA, so player cannot mint. Create a mint whose
    // authority is the player, which also fails BadLootMint.
    const wrongAuth = await createMint(connection, player, player.publicKey, null, 0);
    await mintTo(connection, player, wrongAuth, ata.address, player, 1n).catch(() => undefined);
    await expectFail(
      () => sendClaim({ accountsExtra: { lootMint: wrongAuth } }),
      "BadLootMint"
    );
  });

  it("N18 rejects a metadata account that is not the mint PDA", async () => {
    await expectFail(
      () => sendClaim({ accountsExtra: { metadataOverride: Keypair.generate().publicKey } }),
      "ConstraintSeeds"
    );
  });

  it("N19 rejects server-key rotation by a non-authority", async () => {
    await expectFail(
      () =>
        program.methods
          .fizzSetServerKey(CLUSTER_TAG, Keypair.generate().publicKey)
          .accounts({
            config,
            voucherGuard: guard,
            authority: player.publicKey,
          })
          .signers([player])
          .rpc(),
      "ConstraintHasOne"
    );
  });

  it("pause blocks claim_loot until cleared", async () => {
    await program.methods
      .fizzSetPaused(true)
      .accounts({ config, voucherGuard: guard, authority: authority.publicKey })
      .rpc();
    await expectFail(() => sendClaim({}), "ProgramPaused");
    await program.methods
      .fizzSetPaused(false)
      .accounts({ config, voucherGuard: guard, authority: authority.publicKey })
      .rpc();
  });
});
