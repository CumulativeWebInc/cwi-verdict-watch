'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const W = require('../watcher.js');

const ROOT = path.join(__dirname, '..');
const envelope = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/envelope.json'), 'utf8'));
const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'schema/findings.schema.json'), 'utf8'));
const watchesDoc = JSON.parse(fs.readFileSync(path.join(ROOT, 'watches.json'), 'utf8'));

const okFetch = (body) => async () => ({ status: 200, text: body });
const prev = (signals, status) => ({ status: status || 200, signals, checked_at: '2026-09-16T13:15:00Z' });

// --- hashing ---------------------------------------------------------------
test('sha256 of known input matches reference digest', () => {
  assert.equal(W.sha256HexSync('hello'), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
});
test('sha256 is deterministic', () => {
  assert.equal(W.sha256HexSync('abc'), W.sha256HexSync('abc'));
});
test('different inputs give different hashes', () => {
  assert.notEqual(W.sha256HexSync('abc'), W.sha256HexSync('abd'));
});
test('async hash matches sync hash', async () => {
  assert.equal(await W.sha256HexAsync('verdict-watch'), W.sha256HexSync('verdict-watch'));
});

// --- evidence extraction -----------------------------------------------------
test('extractEvidence pulls source_url, method, claim_id from a real envelope', () => {
  const ev = W.extractEvidence(envelope);
  assert.equal(ev.source_url, 'https://cumulativewebinc.github.io/cwi-sync-audition/');
  assert.equal(ev.method, 'github-release-verification');
  assert.equal(ev.claim_id, 'clm_01M2N4M1NB3D6V7JREVW7GNF8J');
});
test('extractEvidence errors when evidence has no source_url', () => {
  assert.equal(W.extractEvidence({ claim_id: 'x', evidence: {} }).error, 'no-source-url');
});
test('extractEvidence errors on non-envelope input', () => {
  assert.equal(W.extractEvidence(null).error, 'not-an-envelope');
});

// --- strategies -----------------------------------------------------------------
test('spotify-playlist-scan maps to oembed strategy', () => {
  assert.equal(W.strategyFor('spotify-playlist-scan'), 'oembed');
});
test('huggingface-api-verification maps to hf-dataset strategy', () => {
  assert.equal(W.strategyFor('huggingface-api-verification'), 'hf-dataset');
});
test('github methods map to http-hash strategy', () => {
  assert.equal(W.strategyFor('github-release-verification'), 'http-hash');
  assert.equal(W.strategyFor('github-commit-and-content-verification'), 'http-hash');
});
test('oembed target wraps the playlist URL', () => {
  const t = W.strategyTarget('oembed', 'https://open.spotify.com/playlist/ABC');
  assert.ok(t.startsWith('https://open.spotify.com/oembed?url='));
  assert.ok(t.includes('open.spotify.com%2Fplaylist%2FABC'));
});
test('hf-dataset target maps the dataset page to the API', () => {
  assert.equal(
    W.strategyTarget('hf-dataset', 'https://huggingface.co/datasets/BlackLansky/cwi-catalog'),
    'https://huggingface.co/api/datasets/BlackLansky/cwi-catalog'
  );
});

// --- classification ---------------------------------------------------------------
test('fetch error classifies UNREACHABLE', () => {
  const c = W.classify(prev({ sha256: 'a' }), { ok: false, status: null, error: 'timeout' });
  assert.equal(c.verdict, 'UNREACHABLE');
});
test('HTTP 404 classifies DEAD', () => {
  const c = W.classify(prev({ sha256: 'a' }), { ok: false, status: 404 });
  assert.equal(c.verdict, 'DEAD');
});
test('HTTP 410 classifies DEAD', () => {
  const c = W.classify(prev({ sha256: 'a' }), { ok: false, status: 410 });
  assert.equal(c.verdict, 'DEAD');
});
test('HTTP 500 classifies UNREACHABLE (transient, not dead)', () => {
  const c = W.classify(prev({ sha256: 'a' }), { ok: false, status: 500 });
  assert.equal(c.verdict, 'UNREACHABLE');
});
test('first successful check classifies BASELINED', () => {
  const c = W.classify(null, { ok: true, status: 200, signals: { sha256: 'x' }, strategy: 'http-hash' });
  assert.equal(c.verdict, 'BASELINED');
});
test('matching hash classifies STILL_VALID', () => {
  const c = W.classify(prev({ sha256: 'abc' }), { ok: true, status: 200, signals: { sha256: 'abc' }, strategy: 'http-hash' });
  assert.equal(c.verdict, 'STILL_VALID');
});
test('changed hash classifies CHANGED with diff note', () => {
  const c = W.classify(prev({ sha256: 'abc' }), { ok: true, status: 200, signals: { sha256: 'def' }, strategy: 'http-hash' });
  assert.equal(c.verdict, 'CHANGED');
  assert.ok(c.note.includes('sha256'));
});
test('oembed title change classifies CHANGED', () => {
  const c = W.classify(prev({ title: 'New Rap Hits' }), { ok: true, status: 200, signals: { title: 'Renamed Playlist' }, strategy: 'oembed' });
  assert.equal(c.verdict, 'CHANGED');
});
test('oembed title match classifies STILL_VALID', () => {
  const c = W.classify(prev({ title: 'New Rap Hits' }), { ok: true, status: 200, signals: { title: 'New Rap Hits' }, strategy: 'oembed' });
  assert.equal(c.verdict, 'STILL_VALID');
});
test('hf-dataset api_sha change classifies CHANGED', () => {
  const c = W.classify(prev({ api_sha: 'aaa' }), { ok: true, status: 200, signals: { api_sha: 'bbb' }, strategy: 'hf-dataset' });
  assert.equal(c.verdict, 'CHANGED');
});

// --- diffs ---------------------------------------------------------------------------
test('diffWatch returns null when signals match', () => {
  assert.equal(W.diffWatch(prev({ sha256: 'a' }), { signals: { sha256: 'a' }, status: 200, strategy: 'http-hash' }), null);
});
test('diffWatch returns before/after on drift', () => {
  const d = W.diffWatch(prev({ sha256: 'a' }, 200), { signals: { sha256: 'b' }, status: 200, checked_at: '2026-09-16T14:00:00Z', strategy: 'http-hash' });
  assert.equal(d.before, 'a');
  assert.equal(d.after, 'b');
  assert.equal(d.signal, 'sha256');
  assert.equal(d.detected_at, '2026-09-16T14:00:00Z');
});

// --- findings --------------------------------------------------------------------------
function sampleWatch(over = {}) {
  return Object.assign({
    watch_id: 'w_test', claim_id: 'clm_test', subject: 'test',
    evidence_url: 'https://example.com/', strategy: 'http-hash',
    baseline: prev({ sha256: 'a' })
  }, over);
}
test('buildFinding carries every schema-required field', () => {
  const result = { ok: true, status: 200, signals: { sha256: 'a' }, checked_at: '2026-09-16T14:00:00Z', strategy: 'http-hash', target_url: 'https://example.com/' };
  const f = W.buildFinding(sampleWatch(), result, W.classify(sampleWatch().baseline, result));
  for (const k of schema.required) assert.ok(k in f, 'missing required field: ' + k);
  assert.equal(f.schema, 'cwi.watch-finding/1.0');
});
test('CHANGED finding requires review', () => {
  const result = { ok: true, status: 200, signals: { sha256: 'b' }, checked_at: '2026-09-16T14:00:00Z', strategy: 'http-hash', target_url: 'https://example.com/' };
  const f = W.buildFinding(sampleWatch(), result, W.classify(sampleWatch().baseline, result));
  assert.equal(f.verdict, 'CHANGED');
  assert.equal(f.review_required, true);
});
test('STILL_VALID finding does not require review', () => {
  const result = { ok: true, status: 200, signals: { sha256: 'a' }, checked_at: '2026-09-16T14:00:00Z', strategy: 'http-hash', target_url: 'https://example.com/' };
  const f = W.buildFinding(sampleWatch(), result, W.classify(sampleWatch().baseline, result));
  assert.equal(f.review_required, false);
});
test('v1 never auto-downgrades: downgrade_action is always none', () => {
  for (const v of ['STILL_VALID', 'CHANGED', 'DEAD', 'UNREACHABLE']) {
    const f = W.buildFinding(sampleWatch(), { ok: true, status: 200, signals: {}, checked_at: '2026-09-16T14:00:00Z', strategy: 'http-hash' }, { verdict: v, note: '' });
    assert.ok(f.downgrade_action.startsWith('none'), 'verdict ' + v + ' must not auto-downgrade');
  }
});
test('badgeClass covers every verdict', () => {
  for (const v of W.VERDICTS) assert.ok(W.badgeClass(v).startsWith('v-'), v);
});

// --- watch construction -------------------------------------------------------------------
test('createWatch builds an http-hash watch from a real envelope', () => {
  const { watch, error } = W.createWatch(envelope, 'https://example.com/env.json', null);
  assert.ok(!error);
  assert.equal(watch.strategy, 'http-hash');
  assert.equal(watch.claim_id, 'clm_01M2N4M1NB3D6V7JREVW7GNF8J');
  assert.ok(watch.watch_id.startsWith('w_'));
});
test('createWatch errors on a non-envelope', () => {
  assert.equal(W.createWatch({ nope: 1 }, null, null).error, 'no-source-url');
  assert.equal(W.createWatch(null, null, null).error, 'not-an-envelope');
});
test('parseWatchParam extracts the envelope URL', () => {
  assert.equal(W.parseWatchParam('?watch=https%3A%2F%2Fexample.com%2Fc.json'), 'https://example.com/c.json');
});
test('parseWatchParam returns null when absent', () => {
  assert.equal(W.parseWatchParam('?foo=bar'), null);
  assert.equal(W.parseWatchParam(''), null);
});

// --- end-to-end with injected fetch ---------------------------------------------------------
test('checkEvidence: 200 with unchanged body -> STILL_VALID (dead-link fixture)', async () => {
  const body = '<html>sentinel</html>';
  const h = W.sha256HexSync(body);
  const w = sampleWatch({ baseline: prev({ sha256: h }) });
  const result = await W.checkEvidence(w, okFetch(body));
  assert.equal(result.ok, true);
  assert.equal(result.signals.sha256, h);
  assert.equal(W.classify(w.baseline, Object.assign({ strategy: w.strategy }, result)).verdict, 'STILL_VALID');
});
test('checkEvidence: 404 fixture -> DEAD (dead-link detection)', async () => {
  const w = sampleWatch({ baseline: prev({ sha256: 'a' }) });
  const result = await W.checkEvidence(w, async () => ({ status: 404, text: 'not found' }));
  assert.equal(result.ok, false);
  assert.equal(W.classify(w.baseline, Object.assign({ strategy: w.strategy }, result)).verdict, 'DEAD');
});
test('checkEvidence: changed body -> CHANGED end to end', async () => {
  const w = sampleWatch({ baseline: prev({ sha256: W.sha256HexSync('v1') }) });
  const result = await W.checkEvidence(w, okFetch('v2'));
  const cls = W.classify(w.baseline, Object.assign({ strategy: w.strategy }, result));
  assert.equal(cls.verdict, 'CHANGED');
  const f = W.buildFinding(w, Object.assign({ strategy: w.strategy }, result), cls);
  assert.ok(f.diff && f.diff.before !== f.diff.after);
});
test('checkEvidence: network throw -> UNREACHABLE', async () => {
  const w = sampleWatch({ baseline: prev({ sha256: 'a' }) });
  const result = await W.checkEvidence(w, async () => { throw new Error('timeout'); });
  assert.equal(W.classify(w.baseline, Object.assign({ strategy: w.strategy }, result)).verdict, 'UNREACHABLE');
});
test('oembed end-to-end: title fixture match -> STILL_VALID', async () => {
  const w = sampleWatch({ strategy: 'oembed', baseline: prev({ title: 'New Rap Hits' }) });
  const result = await W.checkEvidence(w, okFetch(JSON.stringify({ title: 'New Rap Hits', html: '<iframe/>' })));
  assert.equal(result.signals.title, 'New Rap Hits');
  assert.equal(W.classify(w.baseline, Object.assign({ strategy: w.strategy }, result)).verdict, 'STILL_VALID');
});

// --- seeded watch list ---------------------------------------------------------------------------
test('watches.json seeds 8 watches with evidence URLs, strategies, and baselines', () => {
  assert.equal(watchesDoc.watches.length, 8);
  for (const w of watchesDoc.watches) {
    assert.ok(w.evidence_url, w.watch_id);
    assert.ok(['http-hash', 'oembed', 'hf-dataset'].includes(w.strategy), w.watch_id);
    assert.ok(w.baseline && w.baseline.signals, w.watch_id);
    assert.ok(w.envelope_url.includes('cwi-trust-log/claims/'), w.watch_id);
  }
});
test('all 8 seeded watches are STILL_VALID at seeding', () => {
  for (const w of watchesDoc.watches) {
    assert.equal(w.latest.verdict, 'STILL_VALID', w.watch_id);
  }
});
