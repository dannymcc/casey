# Deploying Casey to Helios

## Quick Deploy

```bash
# 1. Copy to helios
cd ~/.openclaw/workspace
scp -r casey helios:~/

# 2. SSH to helios
ssh helios
cd ~/casey

# 3. Create .env file
cp .env.example .env
# Edit .env and set SECRET_KEY to a random string

# 4. Build and run
docker compose up -d

# 5. (Optional) Seed demo data
docker exec casey python seed_demo_data.py

# 6. Check logs
docker compose logs -f casey
```

Access at: http://helios:5090 (via Tailscale)

## Add Public Domain (Optional)

If you want public access via `casey.dmcc.io`:

1. Edit Caddyfile on helios:
```bash
nano ~/docker/caddy/Caddyfile
```

2. Add:
```
casey.dmcc.io {
    reverse_proxy casey:5090
}
```

3. Restart Caddy:
```bash
docker restart caddy
```

4. Access at: https://casey.dmcc.io

## Backup Automation

Add to crontab on helios:

```bash
crontab -e
```

Add:
```
0 2 * * * docker cp casey:/app/casey.db /home/danny/backups/casey-$(date +\%Y-\%m-\%d).db
```

This backs up the database daily at 2am.

## Updating

```bash
# On helios
cd ~/casey
git pull  # If you've pushed to GitHub
docker compose down
docker compose build
docker compose up -d
```

## Troubleshooting

**Container won't start:**
```bash
docker compose logs casey
```

**Database locked:**
```bash
docker exec casey ls -la /app/casey.db
# Check permissions
```

**Port conflict (5090 in use):**
Edit `docker-compose.yml` and change:
```yaml
ports:
  - "5091:5090"  # Change external port
```

---

Built with ❤️ as part of the Valdan product suite.
