# GridVault

Backend for the DHBW Data Security Programmentwurf (M2, Teil A): a local HTTP API
that stores smart-meter load profiles with encryption at rest, tenant
separation, role-based access control and an audit trail.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

1. Install dependencies:

   ```bash
   uv sync
   ```

2. Create your local configuration file by copying the template:

   ```bash
   cp .env.example .env
   ```

   The `.env` file is ignored by git and holds local settings such as the
   database URL (defaults to a local SQLite database `gridvault.db`).
   Real environment variables take precedence over `.env` entries.

## Run

```bash
uv run fastapi dev
```

The API is served at <http://127.0.0.1:8000>, interactive docs at
<http://127.0.0.1:8000/docs>. On startup, all database tables are created
automatically if they do not exist yet.

## Test data

Generate the canonical test dataset (2 utilities, 6 users, 8 metering
points, 24 hourly values each with real ciphertexts):

```bash
uv run python scripts/generate_testdata.py
```

Missing master keys in `keys/` are created automatically. The script is
idempotent: it rebuilds all tables, so re-runs are reproducible.

### Test users (also used by the Bruno collection in `bruno/`)

| Username          | Password               | Utility | Role            | Owns    |
| ----------------- | ---------------------- | ------- | --------------- | ------- |
| `kunde_swn`       | `Kunde-SWN-2026`       | SWN     | kunde           | SWN-001 |
| `abrechnung_swn`  | `Abrechnung-SWN-2026`  | SWN     | abrechnung      | -       |
| `netzanalyst_swn` | `Netzanalyst-SWN-2026` | SWN     | netzanalyst     | -       |
| `stoerung_swn`    | `Stoerung-SWN-2026`    | SWN     | stoerungsdienst | -       |
| `leitstelle_swn`  | `Leitstelle-SWN-2026`  | SWN     | leitstelle      | -       |
| `kunde_swb`       | `Kunde-SWB-2026`       | SWB     | kunde           | SWB-001 |

### Data layout

| Metering point | Utility | PLZ   | Cohort size in PLZ |
| -------------- | ------- | ----- | ------------------ |
| SWN-001..003   | SWN     | 71543 | 3 (T3 positive)    |
| SWN-004        | SWN     | 71560 | 1 (small cell)     |
| SWB-001..003   | SWB     | 71332 | 3                  |
| SWB-004        | SWB     | 73431 | 1 (small cell)     |
