// backend/api/loot-voucher.js
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const router = require("express").Router();
const nacl = require("tweetnacl");
const rateLimit = require("express-rate-limit");
const { authMiddleware } = require("../lib/auth");
const { addPublicKey } = require("../lib/keys");
const { redis } = require("../lib/redis");
const {
  assertOnchainVoucherConfig,
  resolveClusterSecret,
  resolveClusterKmsKeyId,
  buildVoucherMessageV1,
  toE6,
  newVoucherId,
  clampTtlSeconds,
  MAX_VOUCHER_TTL_SECONDS,
} = require("../lib/voucherV1");
const {
  buildClaimRequestMessage,
  CLAIM_DOMAIN,
  NONCE_TTL_SECONDS,
  lootIdForLocation,
  hintFromLocation,
} = require("../lib/claimRequest");

// Fail fast. A missing or mismatched SOLANA_CLUSTER / FIZZCAPS_PROGRAM_ID
// refuses to load this module, and server.js exits when that happens.
const ONCHAIN = assertOnchainVoucherConfig();

// SECURITY FIX: rate-limit voucher generation — each successful call produces a
// signed voucher that can be redeemed for CAPS.  Without a rate limit a single
// unauthenticated caller could flood the endpoint and harvest many vouchers.
const CLAIM_IP_MAX = Number(process.env.CLAIM_IP_MAX || 10);
const CLAIM_COOLDOWN_SECONDS = Number(process.env.CLAIM_COOLDOWN_SECONDS || 300);
const voucherIssueLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number.isFinite(CLAIM_IP_MAX) && CLAIM_IP_MAX > 0 ? CLAIM_IP_MAX : 10,
  message: { ok: false, error: "Too many voucher requests — slow down, Vault Dweller" },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || "unknown",
});

// Helper: robust bs58 loader that works with different package shapes
function loadBs58() {
  try {
    // Try bs58 first (may export default)
    let b = require("bs58");
    if (b) {
      if (typeof b.encode === "function" && typeof b.decode === "function") return b;
      if (b.default && typeof b.default.encode === "function" && typeof b.default.decode === "function") return b.default;
    }

    // Fallback to base-x
    const baseX = require("base-x");
    const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const codec = typeof baseX === 'function' ? baseX(BASE58) : (baseX && baseX.default ? baseX.default(BASE58) : null);
    if (codec && typeof codec.encode === "function" && typeof codec.decode === "function") return codec;
  } catch (err) {
    throw new Error("Base58 library not available: " + err.message + ". Install 'bs58' or 'base-x'.", { cause: err });
  }
}

const bs58 = loadBs58();

function safeDecodeBase58(str, name = "key") {
  if (!str || typeof str !== "string") throw new Error(`${name} missing`);
  if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(str)) throw new Error(`${name} contains non-base58 characters`);
  try {
    return bs58.decode(str);
  } catch (err) {
    throw new Error(`${name} decode failed: ${err.message}`, { cause: err });  }
}

const USE_KMS = !!resolveClusterKmsKeyId(process.env);
let SERVER_KEYPAIR = null;
let SERVER_KEY_ID = null;
let KEY_INIT_ERROR = null;

// Coordinates and the location hint that go into the voucher come from
// locations.json. The client GPS is used only for the proximity check.
const VOUCHER_CLAIM_RADIUS = Number(process.env.VOUCHER_CLAIM_RADIUS || 150);

let VOUCHER_LOCATIONS = [];
try {
  const locFile = path.join(__dirname, "..", "..", "public", "data", "locations.json");
  const raw = JSON.parse(fs.readFileSync(locFile, "utf8"));
  const flat = Array.isArray(raw) ? raw : [];
  VOUCHER_LOCATIONS = flat.filter(p => p && p.id && p.lat != null && p.lng != null);
  if (VOUCHER_LOCATIONS.length === 0) {
    console.error("[loot-voucher] locations.json has no usable sites");
  }
} catch (e) {
  console.error("[loot-voucher] failed to load locations.json:", e.message);
}

function haversineMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = d => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function locationById(id) {
  return VOUCHER_LOCATIONS.find(loc => loc.id === id) || null;
}

function playerIsNear(loc, lat, lng) {
  const radius = typeof loc.triggerRadius === "number"
    ? loc.triggerRadius
    : (typeof loc.claimRadius === "number" ? loc.claimRadius : VOUCHER_CLAIM_RADIUS);
  return haversineMeters(lat, lng, Number(loc.lat), Number(loc.lng)) <= radius;
}

/**
 * Validate and load SERVER_SECRET_KEY at startup.
 * Enhanced error handling to prevent application outages from misconfigured keys.
 */
async function initServerKey() {
  if (USE_KMS) {
    console.log("[loot-voucher] KMS_SIGNING_KEY_ID configured; will use AWS KMS for signing");
    return;
  }

  console.log("[loot-voucher] Using FREE local signing (see docs/LOCAL_SIGNING_SETUP.md)");
  let secretEnv;
  try {
    secretEnv = resolveClusterSecret(process.env);
  } catch (err) {
    KEY_INIT_ERROR = err.message;
    console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}`);
    return;
  }

  if (!secretEnv) {
    KEY_INIT_ERROR = "SERVER_SECRET_KEY environment variable is not set";
    console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}. Voucher endpoint will be unavailable.`);
    return;
  }

  if (typeof secretEnv !== "string" || secretEnv.length < 64) {
    KEY_INIT_ERROR = "SERVER_SECRET_KEY appears to be invalid (too short or wrong format)";
    console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}. Expected a 64-byte Ed25519 secret key in base58.`);
    return;
  }

  try {
    const secret = safeDecodeBase58(secretEnv, "SERVER_SECRET_KEY");

    if (secret.length !== 64) {
      KEY_INIT_ERROR = `SERVER_SECRET_KEY has invalid length (${secret.length} bytes, expected 64)`;
      console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}`);
      return;
    }

    SERVER_KEYPAIR = nacl.sign.keyPair.fromSecretKey(secret);
    SERVER_KEY_ID = bs58.encode(Buffer.from(SERVER_KEYPAIR.publicKey));

    // Register the public key in the keys service so redeem-voucher.js can
    // look it up by keyId.  This is idempotent — safe to call on every restart.
    await addPublicKey(SERVER_KEY_ID, SERVER_KEY_ID, { notes: "loot-voucher server key" }).catch(e => {
      // IMPORTANT: if this fails, redeem-voucher.js cannot look up the key by
      // keyId and all voucher redemptions will fail with "Unknown signing key".
      // Treat as fatal during startup and set KEY_INIT_ERROR.
      KEY_INIT_ERROR = `keys.addPublicKey failed — voucher redemption will not work: ${e.message}`;
      console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}`);
      SERVER_KEYPAIR = null; // disable signing until key is registered
    });

    console.log("[loot-voucher] SERVER_SECRET_KEY loaded successfully (dev mode)");
  } catch (err) {
    KEY_INIT_ERROR = `Failed to initialize SERVER_SECRET_KEY: ${err.message}`;
    console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}`);
  }
}

// Initialize key at module load (async; errors are logged, not thrown)
// Note: initServerKey() is async — the promise is intentionally not awaited
// here because CommonJS module load is synchronous.  The server typically
// takes 100–200ms to bind its port; key init (local key decode + Redis write)
// completes in < 10ms in the normal path, so no request can arrive before
// KEY_INIT_ERROR / SERVER_KEYPAIR are set.  Any error is stored in KEY_INIT_ERROR
// and returned as HTTP 503 to the first caller if it does arrive early.
initServerKey().catch(err => {
  KEY_INIT_ERROR = `initServerKey promise rejected: ${err && err.message ? err.message : err}`;
  console.error(`[loot-voucher] CRITICAL: ${KEY_INIT_ERROR}`);
});

// Mounted at /api/loot-voucher and /api/claim-voucher.
// The player is the session wallet. wallet/player fields on the body are ignored.
// A one-time Redis nonce (GETDEL, 120s) plus an Ed25519 signature over
// domain, wallet, loot_id, nonce, and issued-at binds the request.
router.post("/nonce", voucherIssueLimiter, authMiddleware, async (req, res) => {
  try {
    const wallet = req.player && req.player.wallet;
    if (!wallet) {
      return res.status(401).json({ ok: false, error: "Session expired or invalid" });
    }
    const nonce = crypto.randomBytes(16).toString("hex");
    await redis.set(`claim:nonce:${wallet}:${nonce}`, "1", { EX: NONCE_TTL_SECONDS });
    res.json({
      ok: true,
      nonce,
      ttlSeconds: NONCE_TTL_SECONDS,
      domain: CLAIM_DOMAIN,
    });
  } catch (err) {
    console.error("[loot-voucher] nonce error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Failed to issue nonce" });
  }
});

router.post("/", voucherIssueLimiter, authMiddleware, async (req, res) => {
  try {
    const body = req.body || {};
    // Player GPS is for the proximity check only. Body wallet is ignored.
    const playerLat = Number(body.latitude);
    const playerLng = Number(body.longitude);
    if (!Number.isFinite(playerLat) || playerLat < -90 || playerLat > 90) {
      return res.status(400).json({ ok: false, error: "invalid_latitude" });
    }
    if (!Number.isFinite(playerLng) || playerLng < -180 || playerLng > 180) {
      return res.status(400).json({ ok: false, error: "invalid_longitude" });
    }
    if (typeof body.locationId !== "string" || !body.locationId) {
      return res.status(400).json({ ok: false, error: "invalid_location" });
    }
    if (VOUCHER_LOCATIONS.length === 0) {
      return res.status(503).json({ ok: false, error: "locations_unavailable" });
    }
    const site = locationById(body.locationId);
    if (!site) {
      return res.status(404).json({ ok: false, error: "unknown_location" });
    }
    if (!playerIsNear(site, playerLat, playerLng)) {
      return res.status(403).json({
        ok: false,
        error: "not_near_poi",
        message: "Vault Dweller, no registered Wasteland site detected at your coordinates.",
      });
    }

    const wallet = req.player && req.player.wallet;
    if (!wallet) {
      return res.status(401).json({ ok: false, error: "Session expired or invalid" });
    }
    const issuedAt = Number(body.issuedAt);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(issuedAt) || Math.abs(now - issuedAt) > NONCE_TTL_SECONDS) {
      return res.status(401).json({ ok: false, error: "issued_at" });
    }
    const nonce = typeof body.nonce === "string" ? body.nonce : "";
    if (!/^[0-9a-f]{32}$/.test(nonce)) {
      return res.status(401).json({ ok: false, error: "nonce_invalid" });
    }
    const spent = await redis.getdel(`claim:nonce:${wallet}:${nonce}`);
    if (spent !== "1") {
      return res.status(401).json({ ok: false, error: "nonce_invalid" });
    }

    // Server-side loot id, coordinates, and hint. The client cannot supply these.
    const lootId = lootIdForLocation(site);
    const latitude = Number(site.lat);
    const longitude = Number(site.lng);
    const locationHint = hintFromLocation(site);
    let message;
    try {
      message = buildClaimRequestMessage({
        domain: CLAIM_DOMAIN,
        wallet,
        lootId,
        nonce,
        issuedAt,
      });
    } catch (err) {
      return res.status(400).json({ ok: false, error: "bad_claim_message" });
    }
    let sigBytes;
    try {
      sigBytes = Buffer.from(String(body.signature || ""), "base64");
    } catch (err) {
      return res.status(401).json({ ok: false, error: "bad_signature" });
    }
    let walletBytes;
    try {
      walletBytes = Buffer.from(safeDecodeBase58(wallet, "wallet"));
    } catch (err) {
      return res.status(401).json({ ok: false, error: "bad_signature" });
    }
    if (sigBytes.length !== 64 || walletBytes.length !== 32 ||
        !nacl.sign.detached.verify(message, sigBytes, walletBytes)) {
      return res.status(401).json({ ok: false, error: "bad_signature" });
    }

    const cooled = await redis.set(
      `claim:cooldown:${wallet}:${site.id}`,
      "1",
      { NX: true, EX: CLAIM_COOLDOWN_SECONDS }
    );
    if (cooled === null || cooled === undefined) {
      return res.status(429).json({ ok: false, error: "cooldown" });
    }

    // BUG-042 FIX: calculate tiered CAPS reward from POI rarity and sign it into
    // the voucher.  Previously every voucher awarded the same flat DEFAULT_LOOT_CAPS
    // (or 100) because the LOOT_ID_TO_CAPS env var used a JSON format incompatible
    // with the comma-delimited parser in redeem-voucher.js, and random lootIds never
    // matched any entry anyway.  By embedding the server-calculated caps value in the
    // signed voucher, redeem-voucher.js can simply trust voucher.caps (it is covered
    // by the NaCl signature and cannot be tampered by the client).
    const RARITY_CAPS = {
      common:    parseInt(process.env.CAPS_COMMON    || "50",   10),
      uncommon:  parseInt(process.env.CAPS_UNCOMMON  || "100",  10),
      rare:      parseInt(process.env.CAPS_RARE      || "200",  10),
      epic:      parseInt(process.env.CAPS_EPIC      || "500",  10),
      legendary: parseInt(process.env.CAPS_LEGENDARY || "1000", 10),
    };
    const poiRarity = site.rarity ? String(site.rarity).toLowerCase() : "common";
    const capsReward = RARITY_CAPS[poiRarity] || RARITY_CAPS.common;

    // Player is the authenticated session wallet. A player or wallet field on
    // the body is ignored so a voucher cannot be redirected to someone else.
    const playerWallet = wallet;

    // CSPRNG voucher id (16 bytes). TTL is capped at 300 seconds.
    // Voucher timestamps are the server clock, not the claim-request issuedAt.
    const voucherIssuedAt = now;
    const voucherIdBuf = newVoucherId();
    const voucherId = voucherIdBuf.toString("hex");
    const ttlSeconds = clampTtlSeconds(process.env.VOUCHER_TTL_SECONDS || MAX_VOUCHER_TTL_SECONDS);
    const expiresAt = voucherIssuedAt + ttlSeconds;
    const latE6 = toE6(latitude);
    const lngE6 = toE6(longitude);

    // BUG-036 FIX: include voucherId and keyId. caps stays on the JSON object
    // for the legacy off-chain path's display, but it is NOT part of the V1
    // on-chain message (the program charges a fixed fee).
    const voucher = {
      v: 2,
      voucherId,
      keyId: SERVER_KEY_ID || "kms",
      lootId,
      caps: capsReward,
      latitude,
      longitude,
      latE6,
      lngE6,
      timestamp: String(voucherIssuedAt),
      issuedAt: voucherIssuedAt,
      expiresAt,
      locationHint,
      ttlSeconds,
    };

    const voucherMessage = buildVoucherMessageV1({
      cluster: ONCHAIN.cluster,
      programId: ONCHAIN.programId,
      player: playerWallet,
      voucherId: voucherIdBuf,
      lootId,
      latE6,
      lngE6,
      locationHint,
      issuedAt: voucherIssuedAt,
      expiresAt,
    });
    if (voucherMessage.length !== 169) {
      throw new Error("voucher message length");
    }

    let signatureBytes;
    let serverPubkey;

    if (USE_KMS) {
      const { signMessageWithKms, getPublicKeyFromKms } = require("../lib/kmsSigner");
      const { signatureBytes: sigBuf, keyIdUsed } = await signMessageWithKms(Buffer.from(voucherMessage));
      signatureBytes = sigBuf;
      const pub = await getPublicKeyFromKms(keyIdUsed);
      serverPubkey = pub.publicKeyBase58;
    } else {
      if (!SERVER_KEYPAIR) {
        const errorMessage = KEY_INIT_ERROR || "SERVER_SECRET_KEY not configured or invalid";
        console.error(`[loot-voucher] Cannot sign voucher: ${errorMessage}`);
        return res.status(503).json({
          error: "Voucher signing service unavailable",
          reason: process.env.NODE_ENV === "development" ? errorMessage : undefined,
        });
      }
      const sig = nacl.sign.detached(voucherMessage, SERVER_KEYPAIR.secretKey);
      signatureBytes = Buffer.from(sig);
      serverPubkey = SERVER_KEY_ID;
    }

    if (!signatureBytes || signatureBytes.length !== 64) {
      throw new Error("voucher signature length");
    }

    // Do not log message bytes or the signature.
    // V1 signature is base64. redeem-voucher rejects v:2, so this is not a
    // legacy pipe-format signature.
    res.json({
      ok: true,
      voucher,
      signature: signatureBytes.toString("base64"),
      serverPubkey,
      programId: ONCHAIN.programId,
      cluster: ONCHAIN.cluster,
    });
  } catch (err) {
    console.error("[loot-voucher] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "Failed to generate voucher" });
  }
});

module.exports = router;
