# HTTPS with automatic TLS via nginx ACME module

This example wires up HTTPS for the `webres6-viewer` container using the
[`ngx_http_acme_module`](https://github.com/nginx/nginx-acme) already present in
the `nginx:mainline` base image. Certificates are obtained and renewed automatically
from Let's Encrypt via ACMEv2 — no certbot sidecar required.

## How it works

The viewer image uses the standard nginx entrypoint which:
1. Runs scripts in `/docker-entrypoint.d/` before starting nginx.
2. Processes templates in `/etc/nginx/templates/` through `envsubst` and drops
   the results into `/etc/nginx/conf.d/`.

Three volume mounts are enough:

| File | Mounted at | Purpose |
|------|-----------|---------|
| `05-load-acme-module.sh` | `/docker-entrypoint.d/05-load-acme-module.sh` | Prepends `load_module` to `nginx.conf` (required in main context) |
| `webres6-https.conf.template` | `/etc/nginx/templates/webres6-https.conf.template` | ACME issuer config + HTTPS vhost (processed by `envsubst`) |
| *(named volume)* | `/var/cache/nginx/acme` | Persists account key and certificates across restarts |

The HTTPS vhost proxies all traffic to `127.0.0.1:${NGINX_PORT}` (the existing HTTP
vhost), so there is no duplication of location blocks. The ACME module intercepts
`/.well-known/acme-challenge/` requests automatically for HTTP-01 validation.

## Usage

```bash
DOMAIN=yourdomain.com docker-compose \
  -f docker-compose.dev.yml \
  -f doc/acme/docker-compose.https.yml \
  up -d
```

Port 80 and 443 must be reachable from the internet for HTTP-01 challenge validation.

## First-run / staging

On the first start nginx will obtain a certificate before serving HTTPS traffic.
To test without hitting Let's Encrypt rate limits, swap the `uri` in
`webres6-https.conf.template` to the staging endpoint first:

```
uri https://acme-staging-v02.api.letsencrypt.org/directory;
```

Then switch back to the production endpoint and remove the `acme-state` volume
to trigger a fresh certificate issuance:

```bash
docker-compose -f docker-compose.dev.yml -f doc/acme/docker-compose.https.yml down -v
DOMAIN=yourdomain.com docker-compose \
  -f docker-compose.dev.yml \
  -f doc/acme/docker-compose.https.yml \
  up -d
```

## Files

- `05-load-acme-module.sh` — entrypoint script that injects `load_module`
- `webres6-https.conf.template` — ACME + HTTPS vhost config template
- `docker-compose.https.yml` — compose override that wires everything together
