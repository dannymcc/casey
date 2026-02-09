# Casey 📝

A productivity system inspired by Casey Newton's workflow from the Hard Fork podcast. Built with Python, Flask, and SQLite.

## Features

### 1. Daily Journaling
- Write each morning to clear your head
- One entry per day (auto-saves)
- Full history view of past entries

### 2. Task Management
- Lightweight to-do list integrated with journal
- Quick add, complete, and delete
- View completed tasks archive

### 3. Blips System 💡
Inspired by Andy Matuschak's spaced repetition for ideas:
- Capture quick thoughts and ideas
- 3 random blips surface each day in your journal
- Reminds you to:
  - Add supporting articles
  - Develop thoughts further
  - Potentially expand into newsletter content

## How It Works

The blips system is the key differentiator. Unlike traditional note-taking where ideas get buried, Casey randomly surfaces old notes alongside your daily journal. This creates serendipitous connections and ensures good ideas don't die in your archive.

**Daily workflow:**
1. Open Casey in the morning
2. See 3 random blips from your backlog
3. Journal freely (blips spark new connections)
4. Add tasks as they come up
5. Capture new blips throughout the day

## Tech Stack

- **Backend:** Python 3.11 + Flask
- **Database:** SQLite (single-file, portable)
- **Frontend:** Minimal HTML/CSS (Valdan design system)
- **Deployment:** Docker + docker-compose

## Installation

### Local Development

```bash
# Clone or navigate to directory
cd casey

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

Visit http://localhost:5090

### Docker Deployment (Recommended)

```bash
# Build and run
docker compose up -d

# View logs
docker compose logs -f casey

# Stop
docker compose down
```

**For helios deployment:**

1. Copy to helios:
```bash
scp -r casey helios:~/
ssh helios
cd ~/casey
```

2. Deploy:
```bash
docker compose up -d
```

3. Add to Caddy (if you want public access):
```
casey.dmcc.io {
    reverse_proxy casey:5090
}
```

Restart Caddy: `docker restart caddy`

## Database Schema

### `journal_entries`
- One per day, stores journal content
- Auto-creates on first write for each date

### `tasks`
- Lightweight to-dos with completion status
- Completed tasks archived (not deleted)

### `blips`
- Quick notes/ideas that surface randomly
- Tracks surface count and last surfaced date

### `daily_blips`
- Junction table: which blips showed on which day
- Ensures same 3 blips per day (consistent daily view)

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

```
SECRET_KEY=your-secret-key-here
FLASK_DEBUG=False
```

## Design Philosophy

**Minimal but intentional:**
- No authentication (single-user, private deployment)
- No fancy JS frameworks (pure HTML forms)
- No cloud sync (just backup your SQLite file)
- Things-inspired aesthetic (clean, crisp, elegant)
- Soft colors and excellent spacing

**Built for focus:**
- One page for today (journal + tasks + blips)
- Blips page for quick capture
- History for reflection
- That's it.

## Port

Runs on port **5090** (chosen to avoid conflicts with other Valdan apps).

## Data Backup

Your data lives in `casey.db` (SQLite file in the container volume).

**Backup strategy:**
```bash
# Local copy
docker cp casey:/app/casey.db ./backup-$(date +%Y-%m-%d).db

# Automated (add to cron)
0 2 * * * docker cp casey:/app/casey.db /home/danny/backups/casey-$(date +\%Y-\%m-\%d).db
```

## Future Ideas

- Export journal entries to markdown
- Tag system for blips (categorize ideas)
- Weekly review mode (auto-surface blips that haven't been seen in 7+ days)
- RSS feed of journal entries
- Email daily blips + tasks in the morning

## Why "Casey"?

Named after Casey Newton, whose productivity system inspired this tool. Built in one night as a focused alternative to complex note-taking apps.
