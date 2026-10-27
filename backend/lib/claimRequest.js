"use strict";

const crypto = require("crypto");

// SIWS-style claim request. Distinct from the 169-byte on-chain voucher.
const CLAIM_DOMAIN = "atomicfizzcaps.xyz";
const NONCE_TTL_SECONDS = 120;
const LOOT_ID_SPACE = 2 ** 48;

function buildClaimRequestMessage({ domain, wallet, lootId, nonce, issuedAt }) {
  if (domain !== CLAIM_DOMAIN) throw new Error("domain");
  if (!wallet || !nonce) throw new Error("claim request");
  const id = String(lootId);
  if (!/^[1-9][0-9]*$/.test(id)) throw new Error("loot_id");
  const issued = Number(issuedAt);
  if (!Number.isSafeInteger(issued)) throw new Error("issued_at");
  return Buffer.from(
    [
      "FIZZCAPS:CLAIM_REQUEST:v1",
      `domain:${domain}`,
      `wallet:${wallet}`,
      `loot_id:${id}`,
      `nonce:${nonce}`,
      `issued_at:${issued}`,
    ].join("\n"),
    "utf8"
  );
}

/**
 * Stable loot id for a locations.json record. A numeric lootId on the record
 * wins when it sits in the 48-bit space. Otherwise the id is the first 48 bits
 * of sha256(location id), which is deterministic and not chosen by the client.
 */
function lootIdForLocation(loc) {
  if (!loc || !loc.id) throw new Error("location");
  if (loc.lootId != null && /^[0-9]+$/.test(String(loc.lootId))) {
    const n = BigInt(loc.lootId);
    if (n > 0n && n < BigInt(LOOT_ID_SPACE)) return n.toString();
  }
  const digest = crypto.createHash("sha256").update(String(loc.id), "utf8").digest();
  let n = BigInt("0x" + digest.subarray(0, 6).toString("hex")) % BigInt(LOOT_ID_SPACE);
  if (n === 0n) n = 1n;
  return n.toString();
}

function hintFromLocation(loc) {
  const raw = String((loc && (loc.hint || loc.name)) || "Wasteland");
  let buf = Buffer.from(raw, "utf8");
  if (buf.length > 64) buf = buf.subarray(0, 64);
  while (buf.length && (buf[buf.length - 1] & 0xc0) === 0x80) {
    buf = buf.subarray(0, buf.length - 1);
  }
  const hint = buf.toString("utf8").trim();
  return hint || "Wasteland";
}

module.exports = {
  CLAIM_DOMAIN,
  NONCE_TTL_SECONDS,
  LOOT_ID_SPACE,
  buildClaimRequestMessage,
  lootIdForLocation,
  hintFromLocation,
};
