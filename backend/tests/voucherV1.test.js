"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("node:child_process");

const PROGRAM_ID = "DXxzKfZh6aJCff7sEusMU1E9w4ZDwgJkYGgKStRRGRyP";
const ROOT = path.resolve(__dirname, "..", "..");

process.env.SOLANA_CLUSTER = process.env.SOLANA_CLUSTER || "localnet";
process.env.FIZZCAPS_PROGRAM_ID = process.env.FIZZCAPS_PROGRAM_ID || PROGRAM_ID;

const {
  buildVoucherMessageV1,
  toE6,
  newVoucherId,
  clampTtlSeconds,
  assertOnchainVoucherConfig,
  resolveClusterSecret,
  MAX_VOUCHER_TTL_SECONDS,
  VOUCHER_MSG_LEN,
  PROGRAM_ID: EXPORT_ID,
  PROGRAM_IDS,
} = require("../lib/voucherV1");

const GOLDEN = {
  cluster: "localnet",
  programId: PROGRAM_ID,
  player: "11111111111111111111111111111111",
  voucherId: "0102030405060708090a0b0c0d0e0f10",
  lootId: "42",
  latE6: 37774900,
  lngE6: -122419400,
  locationHint: "behind the vault door",
  issuedAt: 1700000000,
  expiresAt: 1700000300,
};

test("golden message matches the Rust fixture and is 169 bytes", () => {
  const message = buildVoucherMessageV1(GOLDEN);
  assert.equal(message.length, 169);
  assert.equal(VOUCHER_MSG_LEN, 169);
  assert.equal(message.subarray(0, 24).toString("ascii"), "FIZZCAPS:LOOT_VOUCHER:v1");
  assert.equal(message[24], 3);
  const hintHash = crypto.createHash("sha256").update(GOLDEN.locationHint).digest();
  assert.deepEqual(message.subarray(121, 153), hintHash);
  const fixture = fs.readFileSync(
    path.join(ROOT, "anchor-tests", "fixtures", "voucher_v1_golden.hex"),
    "utf8"
  ).trim();
  assert.equal(message.toString("hex"), fixture);
  assert.equal(EXPORT_ID, PROGRAM_ID);
  assert.equal(new Set(Object.values(PROGRAM_IDS)).size, 3);
});

test("tweetnacl round trip over the binary message", () => {
  const nacl = require("tweetnacl");
  const kp = nacl.sign.keyPair();
  const message = buildVoucherMessageV1(GOLDEN);
  const sig = nacl.sign.detached(message, kp.secretKey);
  assert.equal(sig.length, 64);
  assert.equal(nacl.sign.detached.verify(message, sig, kp.publicKey), true);
  const tampered = Buffer.from(message);
  tampered[105] ^= 0xff;
  assert.equal(nacl.sign.detached.verify(tampered, sig, kp.publicKey), false);
});

test("message binds the session player, not a body player", () => {
  const session = buildVoucherMessageV1(GOLDEN);
  const other = buildVoucherMessageV1({
    ...GOLDEN,
    player: "So11111111111111111111111111111111111111112",
  });
  assert.notDeepEqual(session, other);
});

test("voucher id is 16 CSPRNG bytes and TTL caps at 300", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "lib", "voucherV1.js"), "utf8");
  assert.match(src, /randomBytes\(16\)/);
  assert.equal(src.includes("Math.random"), false);
  const a = newVoucherId();
  const b = newVoucherId();
  assert.equal(a.length, 16);
  assert.equal(b.length, 16);
  assert.notDeepEqual(a, b);
  assert.equal(MAX_VOUCHER_TTL_SECONDS, 300);
  assert.equal(clampTtlSeconds(undefined), 300);
  assert.equal(clampTtlSeconds(900), 300);
  assert.equal(clampTtlSeconds(30), 30);
  assert.equal(clampTtlSeconds(0), 300);
});

test("toE6 rounds half away from zero", () => {
  assert.equal(toE6(37.7749), 37774900);
  assert.equal(toE6(-122.4194), -122419400);
  assert.equal(toE6(-1.5 / 1e6), -2);
});

test("cluster secrets must differ and config refuses a bad program id", () => {
  assert.throws(
    () =>
      assertOnchainVoucherConfig({
        SOLANA_CLUSTER: "localnet",
        FIZZCAPS_PROGRAM_ID: PROGRAM_ID,
        SERVER_SECRET_KEY_LOCALNET: "same",
        SERVER_SECRET_KEY_DEVNET: "same",
      }),
    (err) => err.code === "ONCHAIN_VOUCHER_CONFIG"
  );
  assert.throws(
    () =>
      assertOnchainVoucherConfig({
        SOLANA_CLUSTER: "devnet",
        FIZZCAPS_PROGRAM_ID: "GvTeKyGiFqtpJn2cJQxFb2iPVCYotvnMjMZKGAnPgZkc",
      }),
    (err) => err.code === "ONCHAIN_VOUCHER_CONFIG"
  );
  const secret = resolveClusterSecret({
    SOLANA_CLUSTER: "localnet",
    FIZZCAPS_PROGRAM_ID: PROGRAM_ID,
    SERVER_SECRET_KEY: "fallback-secret",
  });
  assert.equal(secret, "fallback-secret");
  const specific = resolveClusterSecret({
    SOLANA_CLUSTER: "devnet",
    FIZZCAPS_PROGRAM_ID: PROGRAM_IDS.devnet,
    SERVER_SECRET_KEY: "generic",
    SERVER_SECRET_KEY_DEVNET: "devnet-only",
  });
  assert.equal(specific, "devnet-only");
  assert.throws(
    () =>
      assertOnchainVoucherConfig({
        SOLANA_CLUSTER: "devnet",
        FIZZCAPS_PROGRAM_ID: PROGRAM_IDS.localnet,
      }),
    (err) => err.code === "ONCHAIN_VOUCHER_CONFIG"
  );
});

test("Ed25519 fixture matches web3.js createInstructionWithPublicKey", () => {
  const { Ed25519Program } = require("@solana/web3.js");
  const publicKey = Buffer.from(
    fs.readFileSync(path.join(ROOT, "anchor-tests", "fixtures", "ed25519_pubkey.hex"), "utf8").trim(),
    "hex"
  );
  const signature = Buffer.from(
    fs.readFileSync(path.join(ROOT, "anchor-tests", "fixtures", "ed25519_sig.hex"), "utf8").trim(),
    "hex"
  );
  const message = Buffer.from(
    fs.readFileSync(path.join(ROOT, "anchor-tests", "fixtures", "ed25519_msg.hex"), "utf8").trim(),
    "hex"
  );
  assert.equal(message.length, 169);
  const ix = Ed25519Program.createInstructionWithPublicKey({ publicKey, signature, message });
  const stored = fs.readFileSync(path.join(ROOT, "anchor-tests", "fixtures", "ed25519_ix.hex"), "utf8").trim();
  assert.equal(Buffer.from(ix.data).toString("hex"), stored);
  const data = Buffer.from(ix.data);
  // Bytes 2..4 are the signature offset. The pubkey offset is bytes 6..8.
  assert.equal(data.readUInt16LE(2), 48);
  assert.equal(data.readUInt16LE(6), 16);
  assert.equal(data.readUInt16LE(12), 169);
  assert.equal(data.readUInt16LE(4), 0xffff);
});

test("KMS command is RAW Ed25519 and non-Ed25519 is rejected", () => {
  const {
    assertEd25519Algorithm,
    buildSignCommandInput,
    ed25519PublicKeyFromSpkiDer,
    DEFAULT_SIGNING_ALG,
  } = require("../lib/kmsSigner");
  assert.equal(DEFAULT_SIGNING_ALG, "ED25519_SHA_512");
  const input = buildSignCommandInput(Buffer.from("hello"), "alias/fizz", "ED25519_SHA_512");
  assert.equal(input.MessageType, "RAW");
  assert.equal(input.SigningAlgorithm, "ED25519_SHA_512");
  assert.equal(input.KeyId, "alias/fizz");
  assert.throws(() => assertEd25519Algorithm("ECDSA_SHA_256", true), (err) => err.code === "ONCHAIN_VOUCHER_CONFIG");
  assert.doesNotThrow(() => assertEd25519Algorithm("ECDSA_SHA_256", false));
  const der = Buffer.concat([Buffer.alloc(12, 0x30), Buffer.alloc(32, 0x44)]);
  assert.deepEqual(ed25519PublicKeyFromSpkiDer(der), Buffer.alloc(32, 0x44));
});

test("missing SOLANA_CLUSTER or FIZZCAPS_PROGRAM_ID refuses to start", () => {
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    NODE_ENV: "test",
    SOLANA_CLUSTER: "",
    FIZZCAPS_PROGRAM_ID: "",
  };
  const missingCluster = spawnSync(
    process.execPath,
    ["-e", "require('./api/loot-voucher.js')"],
    { cwd: path.join(ROOT, "backend"), env, encoding: "utf8" }
  );
  assert.notEqual(missingCluster.status, 0);
  assert.match(missingCluster.stderr || missingCluster.stdout || "", /SOLANA_CLUSTER|FIZZCAPS_PROGRAM_ID/);

  const missingProgram = spawnSync(
    process.execPath,
    ["-e", "require('./api/loot-voucher.js')"],
    {
      cwd: path.join(ROOT, "backend"),
      env: { ...env, SOLANA_CLUSTER: "localnet", FIZZCAPS_PROGRAM_ID: "" },
      encoding: "utf8",
    }
  );
  assert.notEqual(missingProgram.status, 0);

  const server = spawnSync(process.execPath, ["server.js"], {
    cwd: path.join(ROOT, "backend"),
    env,
    encoding: "utf8",
    timeout: 20000,
  });
  assert.notEqual(server.status, 0, server.stdout + server.stderr);
  assert.match(server.stderr || server.stdout || "", /refusing to start/);
});

test("claim-voucher uses SIWS, server location data, and ignores body wallet", () => {
  const nacl = require("tweetnacl");
  const { encode } = require("../lib/safe-base58");
  const serverKp = nacl.sign.keyPair();
  const playerKp = nacl.sign.keyPair();
  const secret = encode(Buffer.from(serverKp.secretKey));
  const playerSecret = encode(Buffer.from(playerKp.secretKey));
  const script = `
    const http = require("http");
    const assert = require("assert");
    const nacl = require("tweetnacl");
    const { PublicKey } = require("@solana/web3.js");
    const { decode } = require("./lib/safe-base58");
    const { storeSession } = require("./lib/auth");
    const { buildVoucherMessageV1, toE6 } = require("./lib/voucherV1");
    const { buildClaimRequestMessage, CLAIM_DOMAIN, lootIdForLocation } = require("./lib/claimRequest");
    const app = require("./server");
    const playerSecret = decode(process.env.PLAYER_SECRET);
    const playerKp = nacl.sign.keyPair.fromSecretKey(Uint8Array.from(playerSecret));
    const sessionWallet = new PublicKey(playerKp.publicKey).toBase58();
    const bodyPlayer = new PublicKey(Buffer.alloc(32, 9)).toBase58();
    const locationId = "the_dimming_expanse_north_america_0";
    const siteLat = 16.365019;
    const siteLng = -90.892145;
    (async () => {
      const sessionId = "test-session";
      await storeSession(sessionId, { wallet: sessionWallet });
      const server = http.createServer(app);
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const port = server.address().port;
      const send = (path, headers, body) => new Promise((resolve, reject) => {
        const req = http.request({
          hostname: "127.0.0.1", port, path, method: "POST", headers
        }, (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
        });
        req.on("error", reject);
        if (body) req.write(body);
        req.end();
      });
      const auth = {
        "content-type": "application/json",
        authorization: "Bearer " + sessionId
      };
      const anon = await send("/api/claim-voucher", { "content-type": "application/json" }, "{}");
      assert.equal(anon.status, 401);
      const nonceRes = await send("/api/claim-voucher/nonce", auth, "{}");
      assert.equal(nonceRes.status, 200, nonceRes.body);
      const nonceJson = JSON.parse(nonceRes.body);
      assert.equal(nonceJson.ttlSeconds, 120);
      assert.equal(nonceJson.domain, CLAIM_DOMAIN);
      const lootId = lootIdForLocation({ id: locationId });
      const issuedAt = Math.floor(Date.now() / 1000);
      const claimMsg = buildClaimRequestMessage({
        domain: CLAIM_DOMAIN,
        wallet: sessionWallet,
        lootId,
        nonce: nonceJson.nonce,
        issuedAt
      });
      const claimSig = Buffer.from(nacl.sign.detached(claimMsg, playerKp.secretKey)).toString("base64");
      const payload = JSON.stringify({
        locationId,
        latitude: 16.3651,
        longitude: siteLng,
        locationHint: "client hint must be ignored",
        player: bodyPlayer,
        wallet: bodyPlayer,
        nonce: nonceJson.nonce,
        issuedAt,
        signature: claimSig
      });
      const headers = Object.assign({}, auth, { "content-length": Buffer.byteLength(payload) });
      const authed = await send("/api/claim-voucher", headers, payload);
      assert.equal(authed.status, 200, authed.body);
      const json = JSON.parse(authed.body);
      assert.equal(json.voucher.v, 2);
      assert.equal(json.voucher.lootId, lootId);
      assert.equal(json.voucher.locationHint, "The Dimming Expanse");
      assert.equal(json.voucher.latE6, toE6(siteLat));
      assert.notEqual(json.voucher.latE6, toE6(16.3651));
      assert.equal(json.voucher.lngE6, toE6(siteLng));
      assert.equal(json.voucher.voucherId.length, 32);
      assert.ok(json.voucher.expiresAt - json.voucher.issuedAt <= 300);
      const sig = Buffer.from(json.signature, "base64");
      const pub = new PublicKey(json.serverPubkey).toBytes();
      const message = buildVoucherMessageV1({
        cluster: json.cluster,
        programId: json.programId,
        player: sessionWallet,
        voucherId: json.voucher.voucherId,
        lootId: json.voucher.lootId,
        latE6: json.voucher.latE6,
        lngE6: json.voucher.lngE6,
        locationHint: json.voucher.locationHint,
        issuedAt: json.voucher.issuedAt,
        expiresAt: json.voucher.expiresAt
      });
      assert.equal(message.length, 169);
      assert.equal(nacl.sign.detached.verify(message, sig, pub), true);
      const wrongPlayer = buildVoucherMessageV1({
        cluster: json.cluster,
        programId: json.programId,
        player: bodyPlayer,
        voucherId: json.voucher.voucherId,
        lootId: json.voucher.lootId,
        latE6: json.voucher.latE6,
        lngE6: json.voucher.lngE6,
        locationHint: json.voucher.locationHint,
        issuedAt: json.voucher.issuedAt,
        expiresAt: json.voucher.expiresAt
      });
      assert.equal(nacl.sign.detached.verify(wrongPlayer, sig, pub), false);
      const replay = await send("/api/loot-voucher", headers, payload);
      assert.equal(replay.status, 401, replay.body);
      const far = JSON.stringify({
        locationId,
        latitude: 0,
        longitude: 0,
        nonce: "ab".repeat(16),
        issuedAt,
        signature: claimSig,
        wallet: bodyPlayer
      });
      const farRes = await send("/api/loot-voucher", Object.assign({}, auth, { "content-length": Buffer.byteLength(far) }), far);
      assert.equal(farRes.status, 403, farRes.body);
      assert.ok(farRes.body.includes("not_near_poi"));
      const nonce2 = await send("/api/claim-voucher/nonce", auth, "{}");
      assert.equal(nonce2.status, 200, nonce2.body);
      const n2 = JSON.parse(nonce2.body).nonce;
      const issued2 = Math.floor(Date.now() / 1000);
      const msg2 = buildClaimRequestMessage({
        domain: CLAIM_DOMAIN, wallet: sessionWallet, lootId, nonce: n2, issuedAt: issued2
      });
      const sig2 = Buffer.from(nacl.sign.detached(msg2, playerKp.secretKey)).toString("base64");
      const again = JSON.stringify({
        locationId, latitude: siteLat, longitude: siteLng,
        nonce: n2, issuedAt: issued2, signature: sig2, wallet: bodyPlayer
      });
      const cooled = await send("/api/claim-voucher", Object.assign({}, auth, { "content-length": Buffer.byteLength(again) }), again);
      assert.equal(cooled.status, 429, cooled.body);
      assert.ok(cooled.body.includes("cooldown"));
      server.close(() => process.exit(0));
    })().catch((err) => { console.error(err); process.exit(1); });
  `;
  const child = spawnSync(process.execPath, ["-e", script], {
    cwd: path.join(ROOT, "backend"),
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      NODE_ENV: "test",
      SOLANA_CLUSTER: "localnet",
      FIZZCAPS_PROGRAM_ID: PROGRAM_ID,
      SERVER_SECRET_KEY_LOCALNET: secret,
      PLAYER_SECRET: playerSecret,
      VOUCHER_TTL_SECONDS: "900",
      CLAIM_IP_MAX: "20",
    },
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(child.status, 0, (child.stdout || "") + (child.stderr || ""));
});

test("claim-voucher per-IP limit returns 429", () => {
  const nacl = require("tweetnacl");
  const { encode } = require("../lib/safe-base58");
  const secret = encode(Buffer.from(nacl.sign.keyPair().secretKey));
  const script = `
    const http = require("http");
    const assert = require("assert");
    const nacl = require("tweetnacl");
    const { PublicKey } = require("@solana/web3.js");
    const { storeSession } = require("./lib/auth");
    const app = require("./server");
    (async () => {
      const wallet = new PublicKey(nacl.sign.keyPair().publicKey).toBase58();
      await storeSession("ip-session", { wallet });
      const server = http.createServer(app);
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const port = server.address().port;
      const send = () => new Promise((resolve, reject) => {
        const req = http.request({
          hostname: "127.0.0.1", port, path: "/api/claim-voucher/nonce", method: "POST",
          headers: { "content-type": "application/json", authorization: "Bearer ip-session" }
        }, (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode));
        });
        req.on("error", reject);
        req.end("{}");
      });
      const statuses = [];
      for (let i = 0; i < 3; i++) statuses.push(await send());
      assert.deepEqual(statuses, [200, 200, 429]);
      server.close(() => process.exit(0));
    })().catch((err) => { console.error(err); process.exit(1); });
  `;
  const child = spawnSync(process.execPath, ["-e", script], {
    cwd: path.join(ROOT, "backend"),
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      NODE_ENV: "test",
      SOLANA_CLUSTER: "localnet",
      FIZZCAPS_PROGRAM_ID: PROGRAM_ID,
      SERVER_SECRET_KEY_LOCALNET: secret,
      CLAIM_IP_MAX: "2",
    },
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(child.status, 0, (child.stdout || "") + (child.stderr || ""));
});
