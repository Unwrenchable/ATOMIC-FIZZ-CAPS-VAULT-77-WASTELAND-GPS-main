#!/usr/bin/env python3
"""Fail if declare_id! for a cluster feature disagrees with Anchor.toml.

Also rejects a Cargo default that enables localnet, devnet, or mainnet.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANCHOR = (ROOT / "Anchor.toml").read_text()
LIB = (ROOT / "programs" / "fizzcaps-onchain" / "src" / "lib.rs").read_text()
CARGO = (ROOT / "programs" / "fizzcaps-onchain" / "Cargo.toml").read_text()

FEATURES = {
    "localnet": "localnet",
    "devnet": "devnet",
    "mainnet": "mainnet",
}


def fail(msg: str) -> None:
    print(f"check-program-id: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    default = re.search(r"(?m)^default\s*=\s*\[([^\]]*)\]", CARGO)
    if not default:
        fail("programs/fizzcaps-onchain/Cargo.toml is missing default = []")
    for feat in ("localnet", "devnet", "mainnet"):
        if re.search("['\"]" + feat + "['\"]", default.group(1)):
            fail(f"default features must not include {feat}")

    if "compile_error!" not in LIB or "exactly one cluster feature" not in LIB:
        fail("lib.rs must compile_error! unless exactly one cluster feature is set")

    ids: list[str] = []
    for feat, section in FEATURES.items():
        block = re.search(
            rf"(?ms)^\[programs\.{re.escape(section)}\](.*?)(?=^\[|\Z)",
            ANCHOR,
        )
        if not block:
            fail(f"Anchor.toml is missing [programs.{section}]")
        found = re.search(r'fizzcaps_onchain\s*=\s*"([^"]+)"', block.group(1))
        if not found:
            fail(f"Anchor.toml [programs.{section}] is missing fizzcaps_onchain")
        decl = re.search(
            rf'#\[cfg\(feature = "{feat}"\)\]\s*declare_id!\("([^"]+)"\);',
            LIB,
        )
        if not decl:
            fail(f'lib.rs is missing #[cfg(feature = "{feat}")] declare_id!(...)')
        if decl.group(1) != found.group(1):
            fail(
                f"{feat}: declare_id {decl.group(1)} != "
                f"Anchor.toml [programs.{section}] {found.group(1)}"
            )
        print(f"{feat}: {decl.group(1)} matches [programs.{section}]")
        ids.append(decl.group(1))

    if len(ids) != len(set(ids)):
        fail(f"each cluster needs its own program id, got {ids}")


if __name__ == "__main__":
    main()
