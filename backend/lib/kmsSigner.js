// backend/lib/kmsSigner.js
const { encode: bs58encode } = require("./safe-base58");

function loadKms() {
  return require("@aws-sdk/client-kms");
}

const REGION = process.env.AWS_REGION || "us-west-2";
// On-chain vouchers need raw Ed25519. ECDSA_SHA_256 cannot satisfy the precompile.
const DEFAULT_SIGNING_ALG = process.env.KMS_SIGNING_ALGORITHM || "ED25519_SHA_512";
const ONCHAIN_VOUCHERS = process.env.ONCHAIN_VOUCHERS !== "false";

function kmsKeyId(env = process.env) {
  try {
    const { resolveClusterKmsKeyId } = require("./voucherV1");
    return resolveClusterKmsKeyId(env);
  } catch (err) {
    if (err && err.code === "ONCHAIN_VOUCHER_CONFIG" && !env.SOLANA_CLUSTER) {
      return env.KMS_SIGNING_KEY_ID || null;
    }
    throw err;
  }
}

const KMS_KEY_ID = kmsKeyId();

function assertEd25519Algorithm(alg = DEFAULT_SIGNING_ALG, onchain = ONCHAIN_VOUCHERS) {
  if (onchain && !String(alg).includes("ED25519")) {
    const err = new Error(
      `KMS_SIGNING_ALGORITHM must be ED25519_SHA_512 when on-chain vouchers are enabled (got ${alg})`
    );
    err.code = "ONCHAIN_VOUCHER_CONFIG";
    throw err;
  }
}

if (KMS_KEY_ID) {
  assertEd25519Algorithm(DEFAULT_SIGNING_ALG, ONCHAIN_VOUCHERS);
} else {
  console.warn("[kmsSigner] KMS signing key not set for this cluster. KMS signing disabled. Using local signing instead (FREE). See docs/LOCAL_SIGNING_SETUP.md");
}

/** Last 32 bytes of an Ed25519 SPKI DER public key. */
function ed25519PublicKeyFromSpkiDer(der) {
  const buf = Buffer.from(der);
  if (buf.length < 32) throw new Error("SPKI DER too short for Ed25519");
  return buf.subarray(buf.length - 32);
}

function buildSignCommandInput(messageBuffer, keyId, alg = DEFAULT_SIGNING_ALG) {
  assertEd25519Algorithm(alg, ONCHAIN_VOUCHERS);
  return {
    KeyId: keyId,
    Message: messageBuffer,
    MessageType: "RAW",
    SigningAlgorithm: alg,
  };
}

let client = null;
function kmsClient() {
  if (!client) {
    const { KMSClient } = loadKms();
    client = new KMSClient({ region: REGION, maxAttempts: 3 });
  }
  return client;
}

async function retry(fn, attempts = 3, delayMs = 200) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, delayMs * (i + 1)));
    }
  }
  throw lastErr;
}

/**
 * signMessageWithKms
 * - messageBuffer: Buffer
 * - keyId: optional KMS key id/arn; falls back to KMS_KEY_ID
 * Returns: { keyIdUsed, signatureBase58, signatureBytes: Buffer }
 */
async function signMessageWithKms(messageBuffer, keyId = null) {
  if (!messageBuffer || !Buffer.isBuffer(messageBuffer)) {
    throw new Error("messageBuffer must be a Buffer");
  }
  const useKey = keyId || KMS_KEY_ID;
  if (!useKey) throw new Error("No KMS key configured (KMS_SIGNING_KEY_ID missing)");

  // Do not log messageBuffer or the signature.
  const { SignCommand } = loadKms();
  const cmd = new SignCommand(buildSignCommandInput(messageBuffer, useKey, DEFAULT_SIGNING_ALG));

  const res = await retry(() => kmsClient().send(cmd), 3, 250);
  if (!res || !res.Signature) throw new Error("KMS did not return a signature");

  const sigBytes = Buffer.from(res.Signature);
  const signatureBase58 = bs58encode(sigBytes);

  return { keyIdUsed: useKey, signatureBase58, signatureBytes: sigBytes };
}

/**
 * getPublicKeyFromKms
 * - keyId: KMS key id or ARN
 * Returns: { keyId, publicKeyBase58 (raw Ed25519, last 32 bytes of SPKI), publicKeyDerBase58, algorithm }
 */
async function getPublicKeyFromKms(keyId) {
  if (!keyId) throw new Error("keyId required");
  const { GetPublicKeyCommand } = loadKms();
  const cmd = new GetPublicKeyCommand({ KeyId: keyId });
  const res = await retry(() => kmsClient().send(cmd), 3, 250);
  if (!res || !res.PublicKey) throw new Error("KMS did not return public key");
  const pubDer = Buffer.from(res.PublicKey); // SPKI DER
  const raw = ed25519PublicKeyFromSpkiDer(pubDer);
  const publicKeyBase58 = bs58encode(raw);
  const publicKeyDerBase58 = bs58encode(pubDer);
  const algorithm = res.SigningAlgorithms ? res.SigningAlgorithms.join(",") : null;
  return { keyId, publicKeyBase58, publicKeyDerBase58, algorithm };
}

module.exports = {
  signMessageWithKms,
  getPublicKeyFromKms,
  assertEd25519Algorithm,
  ed25519PublicKeyFromSpkiDer,
  buildSignCommandInput,
  DEFAULT_SIGNING_ALG,
};
