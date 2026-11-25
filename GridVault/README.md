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

Every B4 test is a standalone console script in `test/` - one command
each, no server process needed (the app runs in-process against the `.env`
environment). Each script prints every step, the matching audit entries and
a PASS/FAIL summary; exit code 0 means every check passed. Run after
`scripts/generate_testdata.py` so the dataset is canonical. T4 removes
leftover granted tickets first, T5 and T6 restore their tampering - a
protocol run leaves dataset and audit chain intact.

| Test | Command | Expected (B4) |
| ---- | ------- | -------------- |
| T1 | `uv run python test/t1_login.py` | 401 ohne Hinweis auf Existenz, dann 200 mit Rolle und Stadtwerk, beides im Audit |
| T2 | `uv run python test/t2_abrechnung.py` | (a) Summe + Betrag, Lastgang maskiert; (b)/(c) abgelehnt |
| T3 | `uv run python test/t3_kohorte.py` | Kleinzelle mit n und k abgelehnt, Stundensumme, Export nur Pseudonyme |
| T4 | `uv run python test/t4_freigabe.py` | abgelehnt / offen / genehmigt / Wert sichtbar, Name maskiert / abgelehnt / abgelehnt |
| T5 | `uv run python test/t5_chiffrat_swap.py` | Integritätsverletzung mit Zählpunkt und Zeitstempel, Audit-Eintrag |
| T6 | `uv run python test/t6_audit_kette.py` | (a) Kettenbruch mit Zeilenangabe; (b) über den Anker erkannt |

All six in one sweep, stopping at the first failure:

```bash
for t in test/t1_login.py test/t2_abrechnung.py test/t3_kohorte.py \
         test/t4_freigabe.py test/t5_chiffrat_swap.py test/t6_audit_kette.py; do
  uv run python "$t" || break
done
```

The same flows can also be run interactively with the Bruno collection in
`bruno/` (server: `uv run fastapi dev`, environment `Localhost`).

### T1 - login wrong then correct

`GET`/`POST` flow of the script: wrong password -> 401 without
user-existence hint (identical to an unknown user), then correct password
-> 200 with role and tenant. Both events appear in `audit_trail.log`.

### T2 - Abrechnung own / foreign tenant / foreign role

Log in as `abrechnung_swn`, then: (a) `GET /metering-points/SWN-001` ->
sum 18.17 kWh + amount, load profile `[NICHT FREIGEGEBEN]`; (b)
`GET /metering-points/SWB-001` -> denied; (c) `GET /analysis/plz/71543/hourly-sum`
as Abrechnung -> denied (Netzanalyst action, role_not_allowed). The true
denial reasons appear only in the audit trail.

### T3 - cohort k-cell protection and pseudonym export

Log in as `netzanalyst_swn`: PLZ 71543 (n=3) -> hourly sums, PLZ 71560
(n=1) -> rejected with n and k=3, `POST /analysis/plz/71543/export` ->
only HMAC pseudonyms.

### T4 - outage approval chain

Störungsdienst reads without grant (denied) -> creates the approval
request (open) -> Leitstelle lists and grants (four-eyes, 30 min
validity) -> Störungsdienst reads inside the segment (value visible,
name `[HIDDEN]`) -> reads outside the segment (denied) -> after expiry
(denied). The free-text reason stays in the ticket system; the audit
trail carries the ticket reference only.

### T5 - swapped ciphertexts (and why AEAD alone is not enough)

`uv run python test/t5_chiffrat_swap.py` swaps the `enc_value` blobs of
two hourly rows of `SWN-001` directly in the database, reads the metering
point as Abrechnung -> 409 integrity violation naming metering point and
timestamp, prints the audit entry and restores the ciphertexts.

Why authenticated encryption alone does not detect the relocation: both
GCM tags still verify in their new location, no single character was
modified - only the context binding (Weg b: context as AAD) ties each
ciphertext to its metering point and timestamp, so the read fails. Full
reasoning: docstring of `test/t5_chiffrat_swap.py`.

### T6 - audit chain tampering (manual variant)

`uv run python test/t6_audit_kette.py` performs both manipulations,
prints the verification tool output and restores the log. The same can
be done by hand against the real log:

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

## Tests

The six B4 protocol scripts in `test/` (see above) are the test suite -
each exits 0 only if every check passes and prints the matching audit
entries as evidence. Lint:

```bash
uv run ruff check src scripts test
```

## Housekeeping

Broken venv (e.g. after moving the project folder): rebuild with
`rm -rf .venv && uv sync`. The `.env` file is gitignored and holds only the
database URL - real environment variables take precedence.
