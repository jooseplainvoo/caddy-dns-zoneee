# caddy-dns-zoneee

Caddy DNS provider module for [Zone.ee](https://www.zone.ee) (API v2),
for ACME DNS-01 challenges. Scope: TXT append/delete only.

## Build

```dockerfile
FROM caddy:2.11.8-builder AS builder
RUN xcaddy build --with github.com/jooseplainvoo/caddy-dns-zoneee@v0.1.0

FROM caddy:2.11.8
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

## Caddyfile

```
tls {
	dns zoneee {
		username {env.ZONEEE_USER}
		api_key  {env.ZONEEE_KEY}
	}
	propagation_timeout 10m
}
```

## Behavior

- Deletes only TXT records matching name **and** value exactly. An empty
  value is rejected, not treated as a wildcard, so unrelated TXT records
  (SPF, DKIM) can never be removed.
- Never follows HTTP redirects (the Authorization header stays on api.zone.eu).
- Fails at startup if credentials are missing.
