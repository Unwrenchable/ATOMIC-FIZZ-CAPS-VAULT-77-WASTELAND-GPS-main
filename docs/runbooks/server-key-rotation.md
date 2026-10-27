# Runbook: Fizz voucher server key and claim pause

This repo's `programs/fizzcaps-onchain` is a **duplicate**. The canonical program is [Unwrenchable/ATOMIC-FIZZ-CAPS-VAULT-77-WASTELAND-GPS](https://github.com/Unwrenchable/ATOMIC-FIZZ-CAPS-VAULT-77-WASTELAND-GPS). Do not deploy this copy. Do not merge this change into a mainnet release without security review.

`claim_loot` trusts only the Ed25519 key stored in the `voucher-guard` PDA for the cluster this binary was compiled for (`1` mainnet-beta, `2` devnet, `3` localnet). A key supplied by the claim transaction is ignored because there is no such account. `config.server_key` is a legacy mirror of the active cluster's slot, not the verification source.

## Build

Exactly one cluster feature. There is no default.

```bash
anchor build -- --features localnet
anchor build -- --features devnet
anchor build -- --features mainnet
```

`declare_id!` must match `Anchor.toml` for that cluster. `python3 scripts/check-program-id.py` enforces it. Do not run `anchor keys sync` before a mainnet build.

## Keys

Generate a fresh Ed25519 key per cluster. Do not reuse a key that has been in `.env`, CI logs, or another cluster.

- AWS KMS: key spec `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY`, algorithm `ED25519_SHA_512`, `MessageType: RAW`.
- Env: `KMS_SIGNING_KEY_ID_MAINNET`, `KMS_SIGNING_KEY_ID_DEVNET`, `KMS_SIGNING_KEY_ID_LOCALNET`. These must be distinct. `KMS_SIGNING_KEY_ID` is only a fallback when the cluster-specific id is unset.
- Local dev: `SERVER_SECRET_KEY_LOCALNET` (64-byte secret, base58). Same distinctness rule for `SERVER_SECRET_KEY_*`.
- `SOLANA_CLUSTER` is `mainnet-beta`, `devnet`, or `localnet`. `FIZZCAPS_PROGRAM_ID` must be that cluster's id: localnet `H2nT8nZcJ1WvLjvZR3EZEYEjxQWiB3LEqeYBY52nkNyZ`, devnet `GEoBZ4ReipZW6sZv76TYXqgsziv1NVDtVLnn3E4TpUrk`, mainnet-beta `CgjmUQQPHeYJHP1wJAqXpnFcSgK58sgxRn7FvKKczsBF`. The process refuses to start if either is missing or the program id does not match the cluster. These ids are not the canonical repo's localnet `HnWTnCKuKhJa6cXj4ZocW2D8Jtf4f5QFb6f6UnkF27FB`, devnet `GvTeKyGiFqtpJn2cJQxFb2iPVCYotvnMjMZKGAnPgZkc`, or mainnet `DXxzKfZh6aJCff7sEusMU1E9w4ZDwgJkYGgKStRRGRyP`.
- Voucher ids are 16 bytes from `crypto.randomBytes`. TTL is at most 300 seconds.
- Print the raw 32-byte public key: `node backend/scripts/print-server-pubkey.js`

## Init and rotation

`fizz_init` and `fizz_init_voucher_guard` succeed only when the signer is the upgrade authority recorded on this program's loader `ProgramData` account. Pass `program` and `program_data` (PDA of the program id under the upgradeable loader).

1. Deploy the cluster-specific binary to that cluster's program id. This draft does not deploy. Devnet and mainnet keypairs are not in the repo.
2. `initialize_caps` with the upgrade authority. This creates the `["caps-mint"]` PDA with decimals 9 and no freeze authority. Then `fizz_init(server_key)`, which requires that mint. If `FizzConfig` already exists, `fizz_init_voucher_guard(server_key)` writes `server_keys[CLUSTER_TAG]` only.
3. Switch the backend to that key.
4. Rotate later with `fizz_set_server_key(cluster_tag, new_key)`. The config authority (set at init, expected to be a multisig on mainnet) must sign. The same pubkey cannot occupy two cluster slots. The instruction emits `ServerKeyRotated`.
5. A non-authority signer fails the `has_one` constraint.

`FizzConfig`'s byte layout is unchanged so an existing launchpad config still deserializes. The new guard is a separate account. Claims fail closed until the guard exists and its active slot is non-default.

## Pause

`fizz_set_paused(true)` stops `claim_loot`. Launchpad buy, sell, and create are unchanged. The config authority signs. Emits `ClaimsPaused`.

## Replay and players

Each claim creates two PDAs, both paid by the player:

- `["voucher-claim", voucher_id]` — one use of a voucher id, for any player
- `["loot-claim", loot_id_le]` — one NFT per loot id

The signed message also binds `player`, `program_id`, and `cluster_tag`. A second claim fails with the system program error "already in use".

## Rollback

Do not roll back to a binary that accepts unsigned vouchers. Pause claims, or upgrade to a build whose `claim_loot` returns an error, until a fixed binary is reviewed.
