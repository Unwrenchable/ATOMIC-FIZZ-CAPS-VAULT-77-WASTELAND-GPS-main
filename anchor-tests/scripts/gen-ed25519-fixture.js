"use strict";

// Regenerate the Ed25519 instruction fixture from the real web3.js helper.
//   node anchor-tests/scripts/gen-ed25519-fixture.js
//
// The Rust parser test includes these files. Do not hand-edit the offsets.

const fs = require("fs");
const path = require("path");
const { Ed25519Program } = require("@solana/web3.js");

const outDir = path.join(__dirname, "..", "fixtures");
fs.mkdirSync(outDir, { recursive: true });

const publicKey = Buffer.alloc(32, 0x11);
const signature = Buffer.alloc(64, 0xab);
const message = Buffer.alloc(169, 0x22);

const ix = Ed25519Program.createInstructionWithPublicKey({
  publicKey,
  signature,
  message,
});

if (ix.keys.length !== 0) {
  throw new Error("Ed25519 instruction must have no accounts");
}

fs.writeFileSync(path.join(outDir, "ed25519_ix.hex"), Buffer.from(ix.data).toString("hex") + "\n");
fs.writeFileSync(path.join(outDir, "ed25519_pubkey.hex"), publicKey.toString("hex") + "\n");
fs.writeFileSync(path.join(outDir, "ed25519_sig.hex"), signature.toString("hex") + "\n");
fs.writeFileSync(path.join(outDir, "ed25519_msg.hex"), message.toString("hex") + "\n");

const data = Buffer.from(ix.data);
const sigOff = data.readUInt16LE(2);
const pkOff = data.readUInt16LE(6);
if (sigOff !== 48 || pkOff !== 16) {
  throw new Error(`unexpected web3.js offsets sig=${sigOff} pk=${pkOff}`);
}
console.log(`wrote ed25519 fixture (${data.length} bytes, sigOff=${sigOff}, pkOff=${pkOff})`);
