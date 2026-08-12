# Casey

Personal productivity app — journaling, tasks, and blips (random thought surfacing).

## Stack

- Flask + Jinja2 templates, SQLite
- Docker deployment to hyperion via GitHub Container Registry
- GitHub Actions builds Docker image on push

## Ship workflow

When the user says "ship it", "commit push tag release deploy", or similar — run the full pipeline:

0. Bump `CACHE_VERSION` in `static/sw.js` (e.g. `casey-sw-1` → `casey-sw-2`) and include it in the release commit — installed PWAs only drop cached static assets when this changes, so skipping it serves stale CSS/icons to installed clients
1. `git add` the changed files (by name, not `-A`)
2. `git commit` with a concise message (never add Co-Authored-By lines)
3. `git push origin master`
4. Determine next version tag (check `git tag --list 'v*' --sort=-v:refname | head -1` and increment patch)
5. `git tag vX.Y.Z && git push origin vX.Y.Z`
6. `gh release create vX.Y.Z` with a short title and notes summarizing changes
7. Wait for GitHub Actions build: `gh run watch <id> --exit-status`
8. Deploy: `ssh hyperion "cd ~/docker/casey && docker compose pull && docker compose up -d"`

## Conventions

- Never add `Co-Authored-By` lines to commits
- Commit messages: imperative mood, concise, no period at end
- Version tags: `vMAJOR.MINOR.PATCH` (semver)
- Deploy target: hyperion (via SSH, Docker Compose, `~/docker/casey`)
