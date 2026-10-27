"use strict";

// Print the Ed25519 server public key (base58, raw 32 bytes) for fizz_set_server_key.
// Requires KMS_SIGNING_KEY_ID or a cluster-specific KMS_SIGNING_KEY_ID_* plus
// SOLANA_CLUSTER and FIZZCAPS_PROGRAM_ID. Does not print private material.

const { getPublicKeyFromKms } = require("../lib/kmsSigner");
const { resolveClusterKmsKeyId, assertOnchainVoucherConfig } = require("../lib/voucherV1");

async function main() {
  const { cluster } = assertOnchainVoucherConfig();
  const keyId = resolveClusterKmsKeyId();
  if (!keyId) {
    console.error("No KMS key id configured for cluster " + cluster);
    process.exit(1);
  }
  const pub = await getPublicKeyFromKms(keyId);
  process.stdout.write(pub.publicKeyBase58 + "\n");
}

main().catch((err) => {
  console.error(err && err.message ? err.message : err);
  process.exit(1);
});
