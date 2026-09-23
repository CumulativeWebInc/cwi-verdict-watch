# OS Retrofit — Verdict Watch (slot 17)

Date: 2026-09-23 · OPERATION RETROFIT Wave 2 · Constitution: AGENT-OPERATING-FRAMEWORK-2026-09-23

## What changed (this retrofit)
- Brand: official CWI logo (`brand/logo.jpg`) in the page header; Cumulative Web Inc header/footer identity on every page.
- CTA + try-link: visible "Try it live" strip with a working deep link, plus a business/support secondary CTA.
- Metadata: `llms.txt`, `.well-known/agent-card.json`, `content.json`, JSON-LD `WebApplication` schema.org block, canonical + Open Graph + Twitter tags.
- Marketing: value proposition above the fold; honest-limits copy retained verbatim (truth labels NEVER upgraded).
- Business: $0 free tool; commercial/support route via hp@cumulativeweb.com; attribution via the app's own machine-readable receipts and deep links (no third-party trackers).
- OS fit: nervous-system project state `os-retrofit-17-verdict-watch` with evidence-graded claims; 21-gate theorem verdict recorded.

## Red-team pass (2026-09-23)
- ?watch=<envelope-url> and watch subjects/statements (user input, localStorage) are rendered through esc() — no XSS.
- v1 never auto-downgrades: drift flags for human review. CORS-blocked evidence reports UNREACHABLE, never DEAD — no false invalidation.
- watches.json is the machine-readable watch list; findings follow cwi.watch-finding/1.0.

## Secret scan (2026-09-23)
Pattern scan over the full repo (api keys, secrets, tokens, private keys): **0 hits**.


## Tests
node --test tests/test.js — 40/40

## Truth-label discipline
No label changed in this retrofit. UNVERIFIED stays UNVERIFIED; honest-limits copy untouched.
