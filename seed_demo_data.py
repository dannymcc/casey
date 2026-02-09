"""
Seed demo data for Casey

Run this after deploying to populate with example content:
docker exec casey python seed_demo_data.py
"""

import sqlite3
from datetime import datetime, timedelta

DATABASE = 'casey.db'

def seed_demo():
    db = sqlite3.connect(DATABASE)
    
    # Add sample blips
    blips = [
        "What if vet practices had a shared 'locum pool' app where vets could pick up shifts across multiple clinics?",
        "VetComms pricing: flat £99/month vs per-user might be the differentiator. Research competitors.",
        "Blog post idea: 'Why I built my productivity tools instead of using Notion'",
        "Casey blips system could integrate with RSS feeds - surface random articles alongside notes",
        "Helios Docker setup could be templated for other self-hosters. Document the Caddy + Tailscale pattern.",
        "Mission Control dashboard: what if it tracked uptime AND feature requests in one place?",
        "TRMNL plugin for veterinary appointment reminders? Check if Provet API supports it.",
        "ClientPath invoicing could auto-generate PDFs. Look into WeasyPrint or similar.",
        "Write about the 'anti-app store' philosophy - web-first, no Apple tax",
        "LocumVet could offer batch prescription generation for routine vaccinations"
    ]
    
    for blip in blips:
        db.execute('INSERT INTO blips (content, created_at) VALUES (?, ?)',
                  (blip, (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat()))
    
    # Add sample tasks
    tasks = [
        "Review Casey deployment on helios",
        "Update VetComms pricing page",
        "Write blog post about productivity systems",
        "Check Dependabot alerts on May repo"
    ]
    
    for task in tasks:
        db.execute('INSERT INTO tasks (title, completed) VALUES (?, 0)', (task,))
    
    # Add sample journal entry from yesterday
    yesterday = (datetime.now() - timedelta(days=1)).date().isoformat()
    journal_content = """Finished building Casey last night - took about 2 hours from idea to working Docker container.

The blips system is interesting. I like the idea of random note surfacing rather than manual review. Feels more organic than traditional note systems.

Next step: deploy to helios and use it for a week to see if it actually improves my workflow or just becomes another abandoned productivity tool."""
    
    db.execute('INSERT INTO journal_entries (date, content) VALUES (?, ?)',
              (yesterday, journal_content))
    
    db.commit()
    db.close()
    
    print("✅ Demo data seeded successfully!")
    print("- 10 blips added")
    print("- 4 tasks added")
    print("- 1 journal entry (yesterday)")

if __name__ == '__main__':
    import random
    seed_demo()
