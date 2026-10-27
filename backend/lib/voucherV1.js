"use strict";

const crypto = require("crypto");
const { PublicKey } = require("@solana/web3.js");

// On-chain loot voucher message. NOT the legacy pipe format in gps.js.
const DOMAIN = Buffer.from("FIZZCAPS:LOOT_VOUCHER:v1", "ascii");
const CLUSTER_TAG = { "mainnet-beta": 1, devnet: 2, localnet: 3 };
const MAX_VOUCHER_TTL_SECONDS = 300;
const VOUCHER_MSG_LEN = 169;
// One id per cluster. None of these is a canonical-repo id
// (localnet HnWTnCKu…, devnet GvTeKyGi…, mainnet DXxzKfZh…).
// Canonical program: ATOMIC-FIZZ-CAPS-VAULT-77-WASTELAND-GPS. Do not deploy this copy.
const PROGRAM_IDS = {
  localnet: "H2nT8nZcJ1WvLjvZR3EZEYEjxQWiB3LEqeYBY52nkNyZ",
  devnet: "GEoBZ4ReipZW6sZv76TYXqgsziv1NVDtVLnn3E4TpUrk",
  "mainnet-beta": "CgjmUQQPHeYJHP1wJAqXpnFcSgK58sgxRn7FvKKczsBF",
};
const PROGRAM_ID = PROGRAM_IDS.localnet;

const CLUSTER_SECRET_ENV = {
  "mainnet-beta": "SERVER_SECRET_KEY_MAINNET",
  devnet: "SERVER_SECRET_KEY_DEVNET",
  localnet: "SERVER_SECRET_KEY_LOCALNET",
};

const CLUSTER_KMS_ENV = {
  "mainnet-beta": "KMS_SIGNING_KEY_ID_MAINNET",
  devnet: "KMS_SIGNING_KEY_ID_DEVNET",
  localnet: "KMS_SIGNING_KEY_ID_LOCALNET",
};

function configError(message) {
  const err = new Error(message);
  err.code = "ONCHAIN_VOUCHER_CONFIG";
  return err;
}

function assertOnchainVoucherConfig(env = process.env) {
  const cluster = env.SOLANA_CLUSTER;
  const programId = env.FIZZCAPS_PROGRAM_ID;
  if (!cluster || !CLUSTER_TAG[cluster]) {
    throw configError("SOLANA_CLUSTER must be mainnet-beta, devnet, or localnet");
  }
  if (!programId) {
    throw configError("FIZZCAPS_PROGRAM_ID is required");
  }
  const expectedId = PROGRAM_IDS[cluster];
  if (programId !== expectedId) {
    throw configError(`FIZZCAPS_PROGRAM_ID mismatch: expected ${expectedId} for ${cluster}`);
  }
  assertDistinct("SERVER_SECRET_KEY_*", [
    env.SERVER_SECRET_KEY_MAINNET,
    env.SERVER_SECRET_KEY_DEVNET,
    env.SERVER_SECRET_KEY_LOCALNET,
  ]);
  assertDistinct("KMS_SIGNING_KEY_ID_*", [
    env.KMS_SIGNING_KEY_ID_MAINNET,
    env.KMS_SIGNING_KEY_ID_DEVNET,
    env.KMS_SIGNING_KEY_ID_LOCALNET,
  ]);
  return { cluster, programId, clusterTag: CLUSTER_TAG[cluster] };
}

function assertDistinct(label, values) {
  const present = values.filter((v) => v);
  if (new Set(present).size !== present.length) {
    throw configError(`${label} must be distinct per cluster`);
  }
}

/**
 * Pick the signing secret for the configured cluster.
 * Cluster-specific env wins. SERVER_SECRET_KEY is the fallback for that one
 * cluster only. Two clusters must not share a secret.
 */
function resolveClusterSecret(env = process.env) {
  const { cluster } = assertOnchainVoucherConfig(env);
  const specific = [
    env.SERVER_SECRET_KEY_MAINNET,
    env.SERVER_SECRET_KEY_DEVNET,
    env.SERVER_SECRET_KEY_LOCALNET,
  ];
  assertDistinct("SERVER_SECRET_KEY_*", specific);
  const selected = env[CLUSTER_SECRET_ENV[cluster]] || env.SERVER_SECRET_KEY;
  if (!selected) {
    throw configError(`missing server secret for ${cluster} (${CLUSTER_SECRET_ENV[cluster]} or SERVER_SECRET_KEY)`);
  }
  return selected;
}

function resolveClusterKmsKeyId(env = process.env) {
  const { cluster } = assertOnchainVoucherConfig(env);
  const specific = [
    env.KMS_SIGNING_KEY_ID_MAINNET,
    env.KMS_SIGNING_KEY_ID_DEVNET,
    env.KMS_SIGNING_KEY_ID_LOCALNET,
  ];
  assertDistinct("KMS_SIGNING_KEY_ID_*", specific);
  return env[CLUSTER_KMS_ENV[cluster]] || env.KMS_SIGNING_KEY_ID || null;
}

function w64(v, signed) {
  const b = Buffer.alloc(8);
  const n = BigInt(v);
  if (signed) b.writeBigInt64LE(n);
  else b.writeBigUInt64LE(n);
  return b;
}

function w32(v) {
  const b = Buffer.alloc(4);
  b.writeInt32LE(v);
  return b;
}

function buildVoucherMessageV1({
  cluster,
  programId,
  player,
  voucherId,
  lootId,
  latE6,
  lngE6,
  locationHint,
  issuedAt,
  expiresAt,
}) {
  const tag = CLUSTER_TAG[cluster];
  if (!tag) throw new Error("unknown cluster");
  if (typeof locationHint !== "string") throw new Error("locationHint");
  const hintBytes = Buffer.from(locationHint, "utf8");
  if (hintBytes.length > 64) throw new Error("locationHint");
  const buf = Buffer.alloc(VOUCHER_MSG_LEN);
  let o = 0;
  const put = (b) => {
    const src = Buffer.isBuffer(b) ? b : Buffer.from(b);
    if (o + src.length > buf.length) throw new Error("layout drift");
    src.copy(buf, o);
    o += src.length;
  };
  put(DOMAIN);
  put(Buffer.from([tag]));
  put(new PublicKey(programId).toBuffer());
  put(new PublicKey(player).toBuffer());
  const vid = Buffer.isBuffer(voucherId) ? voucherId : Buffer.from(voucherId, "hex");
  if (vid.length !== 16) throw new Error("voucherId");
  put(vid);
  put(w64(lootId, false));
  put(w32(latE6));
  put(w32(lngE6));
  put(crypto.createHash("sha256").update(hintBytes).digest());
  put(w64(issuedAt, true));
  put(w64(expiresAt, true));
  if (o !== VOUCHER_MSG_LEN || buf.length !== VOUCHER_MSG_LEN) throw new Error("layout drift");
  return buf;
}

/** Half away from zero. Inputs are already range-checked by the route. */
function toE6(deg) {
  const x = Number(deg) * 1e6;
  if (!Number.isFinite(x)) throw new Error("lat/lng");
  const rounded = Math.sign(x) * Math.round(Math.abs(x));
  if (!Number.isSafeInteger(rounded)) throw new Error("lat/lng");
  return rounded;
}

/** 128-bit voucher id from crypto.randomBytes. */
function newVoucherId() {
  const id = crypto.randomBytes(16);
  if (!Buffer.isBuffer(id) || id.length !== 16) throw new Error("voucherId");
  return id;
}

function clampTtlSeconds(raw, max = MAX_VOUCHER_TTL_SECONDS) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return max;
  return Math.min(Math.floor(n), max);
}

module.exports = {
  DOMAIN,
  CLUSTER_TAG,
  CLUSTER_SECRET_ENV,
  CLUSTER_KMS_ENV,
  MAX_VOUCHER_TTL_SECONDS,
  VOUCHER_MSG_LEN,
  PROGRAM_ID,
  PROGRAM_IDS,
  assertOnchainVoucherConfig,
  resolveClusterSecret,
  resolveClusterKmsKeyId,
  buildVoucherMessageV1,
  toE6,
  newVoucherId,
  clampTtlSeconds,
};
