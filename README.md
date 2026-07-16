# Four Rooms — domains.azurenexus.com

A single self-contained landing page linking the four hand-built sites:
Dragonfly, With You (Grace), For the Middle Years (Midlife), and Bond.

Same shape as the dragonfly and midlife projects: one `index.html`, no build
step, no external assets beyond Google Fonts.

## Files
- `index.html` — the whole site
- `CNAME` — custom domain (`domains.azurenexus.com`)
- `.nojekyll` — skip Jekyll processing
- `.github/workflows/deploy.yml` — Pages deployment via Actions

## Deploy
Pushing to `main` triggers the workflow automatically.

## DNS
Cloudflare CNAME: `domains` → `gummihurdal.github.io`

## Notes
- Each room links out to its live site in a new tab.
- Respects reduced motion; scales down to mobile.
- Palette: warm paper with one accent per room —
  dragonfly teal, grace rose, midlife gold, bond blue.
