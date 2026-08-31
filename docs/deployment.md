# Deployment

The server ships as a single OCI container (and a bare static binary). It stores
a SQLite database on one mounted volume by default; PostgreSQL is available by
building with `--features postgres` and setting `VAULT_DATABASE_URL` to a
`postgres://` URL.

## Quick start (one container, one volume)

```bash
cp .env.example .env   # set VAULT_OPERATOR_TOKEN and VAULT_TOKEN_KEY
docker compose up -d
```

Then open your instance URL and create the first account. A fresh instance
initialises its database, serves the API, and is ready within seconds (verified
by `scripts/first-run-test.sh`).

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `VAULT_BIND` | `0.0.0.0:8080` | Listen address. |
| `VAULT_DATABASE_URL` | `sqlite:///data/vault.db` | sqlx URL (SQLite or Postgres). |
| `VAULT_REGISTRATION` | `invite` | `open` for self-signup, else invite-only. |
| `VAULT_PUBLIC_ORIGIN` | `http://localhost:8080` | Browser-visible URL (WebAuthn RP). |
| `VAULT_OPERATOR_TOKEN` | _unset_ | Guards `/api/v1/admin/*`. Unset ⇒ admin disabled. |
| `VAULT_TOKEN_KEY` | random | Access-token signing key; set for stable sessions. |
| `VAULT_ACCESS_TTL_SECS` | `900` | Access-token lifetime (≤ 900, per spec). |
| `VAULT_BACKUP_DIR` | `data/backups` | Local backup directory. |
| `VAULT_BACKUP_INTERVAL_SECS` | _unset_ | If set, run periodic backups. |
| `RUST_LOG` / `VAULT_LOG_FORMAT` | `info` / `json` | Log level / format. |

## TLS via a reverse proxy (recommended)

The container listens on plain HTTP; terminate TLS at a reverse proxy so the
self-host story stays "one container". Bind the container to localhost and put
Caddy, nginx, or Traefik in front.

### Caddy

```
vault.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy obtains and renews a certificate automatically. Set
`VAULT_PUBLIC_ORIGIN=https://vault.example.com`.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name vault.example.com;
    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        # These headers drive per-IP rate limiting and audit-log source IPs.
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

> The server reads `X-Forwarded-For` / `X-Real-IP` for rate limiting and audit
> logging. Only set these from a trusted proxy.

## Registration control

Registration is closed by default. Mint a single-use invite (operator token
required):

```bash
curl -sX POST https://vault.example.com/api/v1/admin/invite \
  -H "x-operator-token: $VAULT_OPERATOR_TOKEN"
# => {"code":"..."}
```

Share the code; the client supplies it during enrolment.
