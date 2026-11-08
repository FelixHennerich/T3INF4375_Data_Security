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
