"use strict";

// Write the shared 169-byte golden message. Rust and JS tests both include it.
//   node anchor-tests/scripts/gen-golden.js

const fs = require("fs");
const path = require("path");
const { buildVoucherMessageV1, PROGRAM_ID } = require("../../backend/lib/voucherV1");

const message = buildVoucherMessageV1({
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
});

if (message.length !== 169) throw new Error("len");
const out = path.join(__dirname, "..", "fixtures", "voucher_v1_golden.hex");
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, message.toString("hex") + "\n");
console.log("wrote " + out);
