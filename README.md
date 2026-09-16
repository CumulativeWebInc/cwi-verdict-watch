# Verdict Watch — CWI software brand #31

The invalidation primitive for verified claims. Verification verdicts go stale — a claim verified in September can silently rot while every badge still says VERIFIED. Verdict Watch re-checks the evidence behind signed trust claims and reports **STILL_VALID / BASELINED / CHANGED / DEAD / UNREACHABLE** with diffs.

Live: https://cumulativewebinc.github.io/cwi-verdict-watch/

## How it works

1. **Register a watch** — paste a `cwi-trust-log` envelope URL. The engine extracts the evidence `source_url` + method and picks a re-check strategy:
   - `http-hash` — static pages/JSON: verdict on SHA-256 of the fetched body
   - `oembed` — Spotify playlists (page HTML is dynamic): verdict on the playlist title via oEmbed
   - `hf-dataset` — Hugging Face datasets (page HTML is dynamic): verdict on the dataset git `sha` via the HF API
2. **Check on demand or on cadence** (daily). Each check re-fetches the evidence, compares the verdict signal to the baseline, and emits a machine-readable finding.
3. **Drift is flagged for human review** — v1 never auto-downgrades a claim. False invalidation is worse than stale verification (we learned this the hard way: 32 false-positive dead links dropped by an automated check in 2026-09). Corrections arrive as new envelopes in the append-only trust log; old proofs are never rewritten.

## Machine-readable

- `watches.json` — the watch list + latest status per claim
- `schema/findings.schema.json` — finding objects (`cwi.watch-finding/1.0`): `finding_id, watch_id, claim_id, subject, verdict, checked_at, strategy, evidence{target_url, http_status, signals}, baseline, diff, review_required, downgrade_action`
- Deep link: `?watch=<envelope-url>` pre-fills the add-watch form

## Honest limits

- Browser checks are best-effort: CORS-blocked evidence URLs report UNREACHABLE with a CORS note, never DEAD.
- Spotify position-level re-scans need the Spotify API; the oEmbed check proves reachability + playlist identity.
- Server-side runs of the identical engine (Node, `watcher.js` UMD) are authoritative.

## Dogfood

The seeded watch list is CWI's own 8 trust-log claim envelopes — our badges stay honest first. Baselines established by live server-side checks 2026-09-16; all 8 STILL_VALID at seeding.

## Dev

- `watcher.js` — zero-dependency UMD engine (browser + Node)
- `node --test tests/test.js` — 40 tests
- i18n-ready: `data-i18n` keys + the `cwi-i18n` one-line hook
