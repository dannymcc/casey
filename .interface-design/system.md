# Casey Design System

## Direction
The day is a page. Casey is a dated notebook, not a dashboard. Warm like personal
stationery, quiet like paper. The interface should disappear — you're writing,
not using an app.

## Intent
- **Who:** Someone opening Casey first thing in the morning, coffee in hand, before email
- **What:** Write a journal entry, check tasks, read resurfaced blips
- **Feel:** Warm, unhurried, personal. Like a well-worn notebook on a warm desk

## Signature
The datestamp at the head of the Today page — the day numeral set large in Source
Serif, with the weekday and month beside it in tracked mono. It says "this is a
page in a book" before you read a word. Its companion is the clay margin rule
down the left of every writing surface, which doubles as the focus indicator.

## Typography — three faces, three jobs
This is the rule the whole interface follows. Breaking it is how the design comes
apart.

- **Source Serif 4** (`--display`) — reading matter. Journal entries, blips,
  long-form pages (About, Terms, Privacy), and display headings. 600 for display,
  400 for body, 400 italic for pull quotes.
- **DM Sans** (`--font`) — the interface talking. Buttons, labels, navigation,
  descriptions, form fields that are not prose.
- **JetBrains Mono** (`--mono`) — anything countable or fixed. Dates, counts,
  word counts, version strings, section markers, keyboard hints.

Section markers are mono uppercase at 10.5px / 0.16em tracking, never bold sans.
Page titles are Source Serif 600, 1.75rem, -0.02em.

## Token Architecture

### Surfaces (warm parchment tones, same hue, shift only lightness)
- `--parchment`: Canvas background — `#F0EDE6` / dark: `#1C1B18`
- `--surface`: Card/elevated background — `#FAF9F6` / dark: `#242220`
- `--surface-hover`: Hover state — `#F5F3EE` / dark: `#2C2A26`
- `--surface-inset`: Inputs, recessed areas — `#EAE7E0` / dark: `#1A1917`

### Ink (warm charcoal, 4-level hierarchy)
- `--ink`: Primary text — `#2C2825` / dark: `#E6E2DA`
- `--ink-secondary`: Supporting text — `#6D665E` / dark: `#ACA69D`
- `--ink-muted`: Metadata, labels — `#9C958B` / dark: `#837C73`
- `--ink-faint`: Placeholders, disabled — `#B8B2A8` / dark: `#5A554E`

### Clay (terracotta accent — earthy, warm)
Clay is for attention and marking, never for large fills. Primary buttons are ink.
- `--clay`: Accent — `#C4684A` / dark: `#DE8A66`
- `--clay-hover`: Hover — `#B35C40` / dark: `#E89B79`
- `--clay-subtle`: Tinted background — `#F6EDE9` / dark: `#2E2520`
- `--clay-rule`: Margin rules at rest — `rgba(196,104,74,0.32)` / dark: `rgba(222,138,102,0.34)`
- `--clay-ring`: Focus ring — `rgba(196,104,74,0.18)` / dark: `rgba(222,138,102,0.22)`

### Borders (warm rgba — blend naturally with any surface)
- `--border`: Standard separation — `rgba(44,40,37,0.10)` / dark: `rgba(230,226,218,0.12)`
- `--border-light`: Soft separation — `rgba(44,40,37,0.06)` / dark: `rgba(230,226,218,0.06)`
- `--border-emphasis`: Strong borders — `rgba(44,40,37,0.16)` / dark: `rgba(230,226,218,0.20)`

### Semantic
- `--success`: `#5A8A65` / dark: `#7FAE89`
- `--danger`: `#C25550` / dark: `#E08079`
- `--warning`: `#B07A2F` / dark: `#D9A863`
- Each with a `-bg` variant for tinted backgrounds

## Depth Strategy
**Borders and rules only.** No box-shadows anywhere. Elevation is communicated
through background shifts (surface-inset < parchment < surface) and hairlines.

## Rules — the structural device
Two kinds of vertical rule, and they mean different things:
- **Clay rule** — a writing surface or a blip. The journal margin, the blip
  composer, every blip wherever it appears, pull quotes.
- **Neutral rule** — read-only content indented under its heading. History
  entries, search results, About list items.

The clay rule on a writing surface brightens to full `--clay` on `:focus-within`.
That is the focus indicator for the journal; no outline is drawn on the textarea.

## Component Patterns

### Wordmark
`casey.` in Source Serif 600 lowercase, with the full stop in clay. It writes out
the `ca.` favicon mark in full. Body copy still says "Casey".

### Datestamp
Day numeral (Source Serif 600, 3.25rem) + weekday/month stacked in mono uppercase,
greeting and streak right-aligned opposite. Stacks to a column below 480px.

### Journal sheet
A `--surface` panel. Inside it the textarea is transparent and borderless with a
clay margin rule to its left, so you are writing on the page rather than filling a
form field. Serif, 1.0625rem, 1.8 line-height.

### Mood
A five-point scale of rings that grow with the level, filling clay when selected,
with the word (Rough / Meh / Okay / Good / Great) shown alongside. The same mark
(`.mood-mark.m1`–`.m5`) is the read-only notation in History and Calendar. No emoji.

### Blips
Always a clay margin rule, never a filled box. The resurfacing count is drawn as
clay tally ticks (`.tally`, capped at five plus a faint sixth) followed by
"surfaced N×" in mono.

### Navigation
Active page is inked and underlined with a 2px clay rule sitting on the header's
bottom border, like a tab. No pills.

### Buttons
Primary: `--ink` bg, `--parchment` text, darkens to `--ink-secondary` on hover.
Secondary: bordered, transparent or surface. Ghost: transparent, `--ink-muted`.

### Filter tabs
Underlined tabs on a shared hairline, matching the nav. Not pills.

## Spacing
- **Base unit:** 8px
- **Component:** 0.375–0.75rem — within buttons, cards
- **Section:** 1–1.75rem — between groups
- **Major:** 2–2.5rem — between distinct areas

## Border Radius
- `--radius`: 8px — cards, panels
- `--radius-sm`: 6px — inputs, buttons
- `--radius-xs`: 4px — badges, menu items

## Quality floor
- Visible keyboard focus everywhere via a global `:focus-visible` clay outline
- `prefers-reduced-motion` disables animation and transitions
- No horizontal overflow at 320px; touch targets 44px minimum on mobile
- Both colour schemes are first-class; dark is warm charcoal, never neutral grey

## Standalone pages
`landing.html`, `login.html` and `register.html` carry their own `<head>` and their
own copy of the tokens. Any change to fonts or tokens in `base.html` has to be
mirrored in all three.
