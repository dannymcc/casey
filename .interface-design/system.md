# Casey Design System

## Direction
Morning ritual tool. Warm like a personal notebook, quiet like paper. The interface should disappear — you're writing, not using an app.

## Intent
- **Who:** Someone opening Casey first thing in the morning, coffee in hand, before email
- **What:** Write a journal entry, check tasks, read resurfaced blips
- **Feel:** Warm, unhurried, personal. Like a well-worn notebook on a warm desk

## Signature
Blips resurfacing — ideas from weeks ago that randomly return. The "surfaced 3×" counter with a clay dot indicator. No other productivity tool does this.

## Token Architecture

### Surfaces (warm parchment tones, same hue, shift only lightness)
- `--parchment`: Canvas background — `#F0EDE6` / dark: `#1C1B18`
- `--surface`: Card/elevated background — `#FAF9F6` / dark: `#252320`
- `--surface-hover`: Hover state — `#F5F3EE` / dark: `#2C2A26`
- `--surface-inset`: Inputs, recessed areas — `#EAE7E0` / dark: `#1A1917`

### Ink (warm charcoal, 4-level hierarchy)
- `--ink`: Primary text — `#2C2825` / dark: `#E0DDD6`
- `--ink-secondary`: Supporting text — `#6D665E` / dark: `#A09B93`
- `--ink-muted`: Metadata, labels — `#9C958B` / dark: `#706B63`
- `--ink-faint`: Placeholders, disabled — `#B8B2A8` / dark: `#4A4640`

### Clay (terracotta accent — earthy, warm)
- `--clay`: Primary accent — `#C4684A` / dark: `#D4805E`
- `--clay-hover`: Hover — `#B35C40` / dark: `#C4684A`
- `--clay-subtle`: Tinted background — `#F6EDE9` / dark: `#2E2520`

### Borders (warm rgba — blend naturally with any surface)
- `--border`: Standard separation — `rgba(44, 40, 37, 0.10)` / dark: `rgba(224, 221, 214, 0.10)`
- `--border-light`: Soft separation — `rgba(44, 40, 37, 0.06)` / dark: `rgba(224, 221, 214, 0.05)`
- `--border-emphasis`: Focus rings, strong borders — `rgba(44, 40, 37, 0.16)` / dark: `rgba(224, 221, 214, 0.16)`

### Semantic
- `--success`: `#5A8A65` / dark: `#6B9E76`
- `--danger`: `#C25550` / dark: `#D46B66`
- `--warning`: `#C48A3F` / dark: `#D49E56`
- Each with `-bg` variant for tinted backgrounds

## Depth Strategy
**Borders only.** No box-shadows anywhere. Cards use `border: 1px solid var(--border)`. This keeps the interface flat like paper. Elevation is communicated through background color shifts (surface-inset < parchment < surface).

## Typography
- **Font:** DM Sans — warm geometric sans with personality
- **Mono:** JetBrains Mono — for code, timestamps, data
- **Headings:** 600 weight, tight letter-spacing (-0.025em)
- **Body:** 400 weight, 14px base, 1.6 line-height
- **Labels:** 500 weight, 13px
- **Section headers:** 11px, 600 weight, uppercase, 0.08em letter-spacing
- **Data/stats:** 700 weight for numbers, 10-11px uppercase labels

## Spacing
- **Base unit:** 8px
- **Micro:** 0.25rem (2px) — icon gaps
- **Component:** 0.375-0.75rem — within buttons, cards
- **Section:** 1-1.5rem — between groups
- **Major:** 2rem — between distinct areas

## Border Radius
- `--radius`: 8px — cards, modals
- `--radius-sm`: 6px — inputs, buttons
- `--radius-xs`: 4px — badges, small elements
- Pills: 99px — nav items, filter tabs

## Component Patterns

### Cards
Background: `--surface`. Border: `1px solid var(--border)`. Padding: 1.5rem. No shadows.

### Inputs
Background: `--surface-inset` (darker = recessed). On focus: background becomes `--surface`, border becomes `--clay`, 3px clay focus ring at 10% opacity.

### Buttons
Primary: `--ink` bg, `--parchment` text. Secondary: `--surface` bg with border. Ghost: transparent, `--ink-muted` text.

### Blips on Today page
Each blip gets its own bordered card (`blip-surface`) with a clay dot indicator. More presence than tasks — this is the signature feature.

### Tasks/Blips sections on Today
No opacity trick. Both sections visible at full opacity. Visual hierarchy through typography (uppercase section labels) not dimming.

### Navigation
Active state: `--surface` background with border. Hover: `--border-light` background. Pill-shaped (99px radius).

### Settings rows
Background: `--parchment`. Hover: `--surface-hover`. Arrow indicator for drill-down rows.

## Dark Mode Notes
- Warm charcoal base, not neutral gray
- Borders use rgba with light base color (adapts naturally)
- Semantic colors slightly desaturated
- Clay accent shifts warmer/lighter for contrast
