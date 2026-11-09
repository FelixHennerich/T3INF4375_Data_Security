"""Create master key files for all tenants (M1, A2).

Usage:
    uv run python scripts/create_keys.py SWN SWB

Keys are written to keys/<TENANT>.key (gitignored, mode 0600). Existing
keys are never overwritten by default - a destroyed master key destroys
the tenant's data. Use --overwrite only if you intentionally want to
re-key (existing ciphertexts become unreadable).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gridvault.services.keys import KeyServiceError, create_master_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tenants", nargs="+", help="tenant codes, e.g. SWN SWB")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing keys (existing ciphertexts become unreadable)",
    )
    args = parser.parse_args()

    for tenant in args.tenants:
        try:
            create_master_key(tenant, overwrite=args.overwrite)
        except KeyServiceError as exc:
            print(f"[skip] {exc}")
            continue
        print(f"[ok]   master key created for {tenant}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
