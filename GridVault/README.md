# GridVault

Backend for the DHBW Data Security Programmentwurf (M2, Teil A): a local HTTP API
that stores smart-meter load profiles with encryption at rest (AES-256-GCM with
context binding), strict tenant separation, a central authorization gateway,
role-based output adaptation, a hash-chained audit trail with an external
anchor, configurable retention deletion and crypto-shredding for customer
deletion requests.

Runs fully local, no network access and no external services required
(all crypto primitives from established libraries).

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Quick start (fresh clone)

```bash
uv sync                                   # install dependencies
cp .env.example .env                       # local config (db url defaults to gridvault.db)
uv run python scripts/generate_testdata.py # master keys + test dataset (real ciphertexts)
uv run fastapi dev                         # API at http://127.0.0.1:8000
```

On startup all database tables are created automatically. The generator is
idempotent (drops and rebuilds all tables) and creates missing master keys in
`keys/` and HMAC keys in `hmac_keys/` (both gitignored, mode 0600).

## Module structure (A9)

| Module | Responsibility |
| ------ | -------------- |
| `gridvault/services/keys.py`     | Schlüsseldienst: per-tenant master keys + HMAC pseudonym keys, outside DB and source |
| `gridvault/services/crypto.py`  | AES-256-GCM with context binding (Weg b: context as AAD), data-key wrapping |
| `gridvault/services/audit.py`   | Append-only hash chain + anchor mirror (WORM stand-in), data-poor entries by construction |
| `gridvault/services/sessions.py`| Session lifecycle, only token hashes in the DB |
| `gridvault/services/gateway.py` | THE central check chain: session -> role -> tenant -> object -> decrypt -> mask/aggregate -> audit |
| `gridvault/routers/*`           | Transport only - declare parameters, call the gateway, never check or audit themselves |

Runtime artifacts (gitignored, regenerated): `gridvault.db`,
`audit_trail.log`, `audit_anchor/`, `keys/`, `hmac_keys/`, `backups/`.

## Test data

Canonical test dataset: 2 utilities, 6 users covering all 5 roles, 8 metering
points, 24 hourly values each (one full day, deterministic day/night profile).

### Test users (also used by the Bruno collection in `bruno/`)

| Username          | Password               | Utility | Role            | Owns    |
| ----------------- | ---------------------- | ------- | --------------- | ------- |
| `kunde_swn`       | `Kunde-SWN-2026`       | SWN     | kunde           | SWN-001 |
| `abrechnung_swn`  | `Abrechnung-SWN-2026`  | SWN     | abrechnung      | -       |
| `netzanalyst_swn` | `Netzanalyst-SWN-2026` | SWN     | netzanalyst     | -       |
| `stoerung_swn`    | `Stoerung-SWN-2026`    | SWN     | stoerungsdienst | -       |
| `leitstelle_swn`  | `Leitstelle-SWN-2026`  | SWN     | leitstelle      | -       |
| `kunde_swb`       | `Kunde-SWB-2026`       | SWB     | kunde           | SWB-001 |

Passwords are stored as Argon2 hashes only - the plaintext passwords above
are test credentials and intentionally documented (A9). No real secrets exist
in this repository.

### Data layout

| Metering point | Utility | PLZ   | Cohort size in PLZ |
| -------------- | ------- | ----- | ------------------ |
| SWN-001..003   | SWN     | 71543 | 3 (T3 positive)    |
| SWN-004        | SWN     | 71560 | 1 (small cell)     |
| SWB-001..003   | SWB     | 71332 | 3                  |
| SWB-004        | SWB     | 73431 | 1 (small cell)     |

## Reproducing the B4 tests

With the server running (`uv run fastapi dev`), each test is one command
(Bruno collection: open `bruno/`, select environment `Localhost`).

### T1 - login wrong then correct (Bruno)

`auth/login_wrong_password` -> 401 without user-existence hint, then
`auth/login_kunde_swn` -> 200 with role and tenant. Both events appear in
`audit_trail.log`; verify the chain afterwards (see T6).

### T2 - Abrechnung own / foreign tenant / foreign role (Bruno)

Log in as `abrechnung_swn`, then:

| Request | Expected (B4/T2) |
| ------- | ---------------- |
| `metering/get_billing_summary` (SWN-001) | (a) sum + amount, load profile `[NICHT FREIGEGEBEN]` |
| `metering/get_other_tenant_swb` (SWB-001) | (b) denied |
| `analysis/hourly_sum_ok` as Abrechnung | (c) denied (Netzanalyst action, role_not_allowed) |

### T3 - cohort k-cell protection and pseudonym export (Bruno)

Log in as `netzanalyst_swn`, then `analysis/hourly_sum_ok` (PLZ 71543, n=3:
hourly sum), `analysis/hourly_sum_small_cell` (PLZ 71560: rejected with n=1
and k=3), `analysis/export` (only HMAC pseudonyms).

### T4 - outage approval chain (Bruno)

`login_stoerung_swn` -> `segment_read_without_grant` (denied) ->
`create_approval_request` (open; the created request_id is written into the
environment automatically) -> `login_leitstelle_swn` -> `list_open_requests`
-> `grant_approval` (four-eyes, 30 min validity) -> `login_stoerung_swn` ->
`segment_read_in_segment` (value visible, name `[HIDDEN]`) -> change PLZ to
`71560` in the request URL (denied, outside the segment) -> after the grant
window (shorten via `GRANT_VALIDITY_MINUTES` in `.env`) denied again.

### T5 - swapped ciphertexts (script)

```bash
uv run python scripts/t5_swap_and_read.py
```

Swaps the `enc_value` blobs of two hourly rows of `SWN-001` directly in the
database, reads the metering point as Abrechnung -> 409 integrity violation
naming metering point and timestamp, prints the audit entry and restores the
ciphertexts. B4 reasoning why AEAD alone does not detect the relocation of
two valid ciphertexts (only the AAD context binding does): see the script
docstring.

### T6 - audit chain tampering (script)

```bash
# intact chain + anchor
uv run python scripts/verify_audit.py            # exit 0

# (a) delete a middle entry -> chain break with line number
sed -i '' '3d' audit_trail.log
uv run python scripts/verify_audit.py            # exit 1, line number reported

# (b) truncate the tail -> only the anchor exposes it
# (restore a middle-entry deletion first, e.g. regenerate data, then)
head -n 5 audit_trail.log > tmp && mv tmp audit_trail.log
uv run python scripts/verify_audit.py            # exit 1, TRUNCATED TAIL
```

Why the hash chain alone cannot detect the cut tail (the attacker removes the
evidence with it; only the comparison against the external anchor in
`audit_anchor/` exposes it): see the docstring of `scripts/verify_audit.py`.

### Bonus - deletion + backup evidence (script)

```bash
uv run python scripts/backup_restore_simulation.py
```

Pulls a backup copy -> deletion run (dry + real, retention window 30 days) ->
proof that the previously pulled backup still contains the ciphertexts ->
crypto-shredding of `SWN-001` (data key destroyed, remaining ciphertext
unreadable) -> restores the backup (resurrected rows) -> re-applies the
deletion run and the key destruction. The script CLEANS the working dataset;
regenerate afterwards with `scripts/generate_testdata.py`.

## Test suite

```bash
uv run pytest tests/ -q   # 97 tests: crypto, audit, auth, gateway hardening (A7/A8), deletion, backup semantics
uv run ruff check src scripts tests
```

## Housekeeping

Broken venv (e.g. after moving the project folder): rebuild with
`rm -rf .venv && uv sync`. The `.env` file is gitignored and holds only the
database URL - real environment variables take precedence.
