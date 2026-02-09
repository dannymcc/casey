# Deploying Casey

## CI/CD with GitHub Actions

Casey uses GitHub Actions to automatically build and publish Docker images to GitHub Container Registry (ghcr.io) on every push to `main` and on version tags.

### Deployment Process

**Production (helios):**

1. Push changes to GitHub:
   ```bash
   git add .
   git commit -m "Your changes"
   git push origin main
   ```

2. GitHub Actions automatically builds the Docker image and tags it as `latest`

3. On helios, pull and restart:
   ```bash
   ssh helios
   cd ~/casey
   docker compose pull
   docker compose up -d
   ```

### Versioning & Releases

To create a versioned release:

1. Tag the release:
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```

2. GitHub Actions builds and pushes with tags:
   - `ghcr.io/dannymcc/casey:v1.0.1`
   - `ghcr.io/dannymcc/casey:1.0`
   - `ghcr.io/dannymcc/casey:latest`

3. The version number in Settings automatically reflects the Docker image tag

### Using Pre-built Images

Update `docker-compose.yml` to use GitHub Container Registry images instead of building locally:

```yaml
services:
  casey:
    image: ghcr.io/dannymcc/casey:latest
    # ... rest of config
```

Then deploy:
```bash
docker compose pull
docker compose up -d
```

## Local Development

For local development, build from source:

```bash
# Build and run locally
docker compose up -d --build

# View logs
docker compose logs -f casey

# Seed demo data
docker exec casey python seed_demo_data.py
```

## Initial Setup (First Deploy)

1. Copy to helios:
   ```bash
   cd ~/.openclaw/workspace
   scp -r casey helios:~/
   ```

2. Create `.env` file:
   ```bash
   ssh helios
   cd ~/casey
   cp .env.example .env
   # Edit .env and set SECRET_KEY to a random string
   ```

3. Start container:
   ```bash
   docker compose up -d
   ```

4. Add to Caddy for public access (if needed):
   ```bash
   nano ~/docker/caddy/Caddyfile
   ```
   
   Add:
   ```
   casey.dmcc.io {
       reverse_proxy casey:5090
   }
   ```
   
   Restart Caddy:
   ```bash
   docker restart caddy
   ```

Access at: https://casey.dmcc.io

## Backup Automation

Add to crontab on helios:

```bash
crontab -e
```

Add:
```
0 2 * * * docker cp casey:/app/data/casey.db /home/danny/backups/casey-$(date +\%Y-\%m-\%d).db
```

This backs up the database daily at 2am.

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

Built for personal productivity.
