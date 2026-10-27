#!/usr/bin/env node
"use strict";

// Download the public Metaplex Token Metadata program (mainnet) without the
// Solana CLI. The ELF begins after the 45-byte upgradeable-loader header.
const fs = require("fs");
const path = require("path");

const PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const RPC = process.env.SOLANA_RPC || "https://api.mainnet-beta.solana.com";
const ROOT = path.resolve(__dirname, "..");
const DESTINATIONS = [
  path.join(ROOT, "anchor-tests", "fixtures", "mpl_token_metadata.so"),
  path.join(ROOT, "programs", "fizzcaps-onchain", "tests", "fixtures", "mpl_token_metadata.so"),
];

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`rpc http ${res.status}`);
  const json = await res.json();
  if (json.error) throw new Error(JSON.stringify(json.error));
  return json.result;
}

function accountData(result) {
  if (!result || !result.value) throw new Error("account missing");
  const [b64] = result.value.data;
  return Buffer.from(b64, "base64");
}

async function main() {
  if (DESTINATIONS.every((p) => fs.existsSync(p) && fs.statSync(p).size > 1000)) {
    console.log("mpl_token_metadata.so already present");
    return;
  }
  const program = accountData(
    await rpc("getAccountInfo", [PROGRAM_ID, { encoding: "base64" }])
  );
  if (program.readUInt32LE(0) !== 2) throw new Error("unexpected program account");
  const programData = bs58Encode(program.subarray(4, 36));
  const data = accountData(
    await rpc("getAccountInfo", [programData, { encoding: "base64" }])
  );
  const elf = data.subarray(45);
  if (elf.subarray(0, 4).toString("hex") !== "7f454c46") {
    throw new Error("programdata did not contain an ELF");
  }
  for (const dest of DESTINATIONS) {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, elf);
    console.log("wrote", dest, elf.length);
  }
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58Encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  const digits = [0];
  for (let i = zeros; i < bytes.length; i += 1) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j += 1) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) out += ALPHABET[digits[i]];
  return out;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
