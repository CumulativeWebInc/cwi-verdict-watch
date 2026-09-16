/* CWI Verdict Invalidation Watch — watcher.js (UMD, zero dependencies)
 * Re-checks signed trust claims on a cadence and reports
 * STILL_VALID / BASELINED / CHANGED / DEAD / UNREACHABLE with diffs.
 * v1 flags drift for human review — it never auto-downgrades a claim
 * (false invalidation is worse than stale verification).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('crypto'));
  } else {
    root.CWIWatch = factory(null);
  }
})(typeof self !== 'undefined' ? self : this, function (nodeCrypto) {
  'use strict';

  var VERDICTS = ['STILL_VALID', 'BASELINED', 'CHANGED', 'DEAD', 'UNREACHABLE'];

  // --- hashing -------------------------------------------------------------
  function sha256HexSync(str) {
    if (!nodeCrypto) throw new Error('sha256HexSync needs node:crypto (browser: use sha256HexAsync)');
    return nodeCrypto.createHash('sha256').update(str, 'utf8').digest('hex');
  }

  async function sha256HexAsync(str) {
    if (nodeCrypto) return sha256HexSync(str);
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    }
    throw new Error('no SHA-256 available in this runtime');
  }

  // --- evidence extraction ---------------------------------------------------
  // Pull the checkable evidence out of a trust/1.0 claim envelope.
  function extractEvidence(envelope) {
    if (!envelope || typeof envelope !== 'object') return { error: 'not-an-envelope' };
    var ev = envelope.evidence || {};
    if (!ev.source_url) return { error: 'no-source-url' };
    return {
      source_url: ev.source_url,
      method: ev.method || 'unknown',
      observed_at: ev.observed_at || null,
      claim_id: envelope.claim_id || null,
      subject: envelope.subject || null,
      statement: envelope.statement || null,
      tier: envelope.tier || null
    };
  }

  // Map the envelope's evidence method to a concrete re-check strategy.
  // http-hash : raw URL content, verdict on sha256 equality (static pages/JSON)
  // oembed    : Spotify oEmbed, verdict on playlist title equality (page HTML is dynamic)
  // hf-dataset: Hugging Face API, verdict on dataset git sha equality (page HTML is dynamic)
  function strategyFor(method) {
    if (method === 'spotify-playlist-scan') return 'oembed';
    if (method === 'huggingface-api-verification') return 'hf-dataset';
    return 'http-hash';
  }

  function strategyTarget(strategy, sourceUrl) {
    if (strategy === 'oembed') {
      return 'https://open.spotify.com/oembed?url=' + encodeURIComponent(sourceUrl);
    }
    if (strategy === 'hf-dataset') {
      var m = sourceUrl.match(/huggingface\.co\/datasets\/([^/]+\/[^/?#]+)/);
      if (m) return 'https://huggingface.co/api/datasets/' + m[1];
    }
    return sourceUrl;
  }

  // --- fetching (injectable for tests) ---------------------------------------
  // fetchImpl(url, timeoutMs) -> Promise<{status:number, text:string}>
  function nodeFetch(url, timeoutMs) {
    var lib = url.indexOf('https:') === 0 ? require('https') : require('http');
    return new Promise(function (resolve, reject) {
      var req = lib.get(url, { headers: { 'User-Agent': 'CWI-Verdict-Watch/1.0' } }, function (res) {
        var chunks = [];
        res.on('data', function (c) { chunks.push(c); });
        res.on('end', function () {
          resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') });
        });
      });
      req.on('error', reject);
      req.setTimeout(timeoutMs || 20000, function () { req.destroy(new Error('timeout')); });
    });
  }

  function browserFetch(url, timeoutMs) {
    var ctrl = new AbortController();
    var t = setTimeout(function () { ctrl.abort(); }, timeoutMs || 20000);
    return fetch(url, { signal: ctrl.signal, redirect: 'follow' }).then(function (res) {
      clearTimeout(t);
      return res.text().then(function (text) { return { status: res.status, text: text }; });
    }).catch(function (e) {
      clearTimeout(t);
      var err = new Error(e && e.name === 'AbortError' ? 'timeout' : 'fetch-failed (CORS-blocked or network)');
      err.corsHint = true;
      throw err;
    });
  }

  function defaultFetch(url, timeoutMs) {
    if (typeof window !== 'undefined' && typeof window.fetch === 'function') return browserFetch(url, timeoutMs);
    return nodeFetch(url, timeoutMs);
  }

  // Run one evidence check. Returns a result object, never throws.
  async function checkEvidence(watch, fetchImpl) {
    var impl = fetchImpl || defaultFetch;
    var checkedAt = new Date().toISOString();
    var target = strategyTarget(watch.strategy, watch.evidence_url);
    var raw;
    try {
      raw = await impl(target, 20000);
    } catch (e) {
      return { ok: false, status: null, error: (e && e.message) || 'fetch-error', checked_at: checkedAt, target_url: target, cors_hint: !!(e && e.corsHint) };
    }
    var signals = {};
    if (raw.status >= 200 && raw.status < 300) {
      try {
        if (watch.strategy === 'oembed') {
          var oe = JSON.parse(raw.text);
          signals.title = oe.title || null;
        } else if (watch.strategy === 'hf-dataset') {
          var api = JSON.parse(raw.text);
          signals.api_sha = api.sha || null;
          signals.siblings = Array.isArray(api.siblings) ? api.siblings.length : null;
        }
        signals.sha256 = await sha256HexAsync(raw.text);
      } catch (e) {
        return { ok: false, status: raw.status, error: 'signal-parse-failed', checked_at: checkedAt, target_url: target };
      }
    }
    return {
      ok: raw.status >= 200 && raw.status < 300,
      status: raw.status,
      bytes: raw.text ? raw.text.length : 0,
      signals: signals,
      checked_at: checkedAt,
      target_url: target
    };
  }

  // Which signal decides the verdict for a strategy.
  function verdictSignal(strategy) {
    if (strategy === 'oembed') return 'title';
    if (strategy === 'hf-dataset') return 'api_sha';
    return 'sha256';
  }

  // --- classification ----------------------------------------------------------
  // previous: {status, signals} | null (null = never checked before)
  function classify(previous, result) {
    if (!result.ok) {
      if (result.status === 404 || result.status === 410) {
        return { verdict: 'DEAD', note: 'evidence URL returned HTTP ' + result.status };
      }
      if (result.error) {
        return { verdict: 'UNREACHABLE', note: 'fetch failed: ' + result.error };
      }
      return { verdict: 'UNREACHABLE', note: 'evidence URL returned HTTP ' + result.status + ' (transient)' };
    }
    if (!previous || !previous.signals) {
      return { verdict: 'BASELINED', note: 'first successful check — baseline recorded' };
    }
    var key = verdictSignal(result.strategy || 'http-hash');
    var before = previous.signals[key];
    var after = result.signals[key];
    if (before !== after) {
      return { verdict: 'CHANGED', note: key + ' drifted: ' + shortHash(before) + ' -> ' + shortHash(after) };
    }
    return { verdict: 'STILL_VALID', note: key + ' matches baseline' };
  }

  function shortHash(v) {
    if (v == null) return 'null';
    v = String(v);
    return v.length > 18 ? v.slice(0, 12) + '…' : v;
  }

  function diffWatch(previous, result) {
    if (!previous || !previous.signals) return null;
    var key = verdictSignal(result.strategy || 'http-hash');
    var before = previous.signals[key], after = result.signals[key];
    if (before === after) return null;
    return {
      signal: key,
      before: before,
      after: after,
      status_before: previous.status,
      status_after: result.status,
      detected_at: result.checked_at
    };
  }

  // --- findings ------------------------------------------------------------------
  var _findingSeq = 0;
  function buildFinding(watch, result, classification) {
    _findingSeq += 1;
    var diff = diffWatch(watch.baseline || null, Object.assign({ strategy: watch.strategy }, result));
    return {
      schema: 'cwi.watch-finding/1.0',
      finding_id: 'fnd_' + Date.now().toString(36) + '_' + _findingSeq,
      watch_id: watch.watch_id,
      claim_id: watch.claim_id,
      subject: watch.subject,
      verdict: classification.verdict,
      verdict_note: classification.note,
      checked_at: result.checked_at,
      strategy: watch.strategy,
      evidence: {
        target_url: result.target_url || strategyTarget(watch.strategy, watch.evidence_url),
        http_status: result.status,
        bytes: result.bytes || 0,
        signals: result.signals || {},
        fetch_error: result.error || null
      },
      baseline: watch.baseline || null,
      diff: diff,
      review_required: classification.verdict === 'CHANGED' || classification.verdict === 'DEAD',
      downgrade_action: 'none — v1 flags drift for human review; claims are never auto-downgraded'
    };
  }

  function badgeClass(verdict) {
    return { STILL_VALID: 'v-ok', BASELINED: 'v-base', CHANGED: 'v-changed', DEAD: 'v-dead', UNREACHABLE: 'v-unreach' }[verdict] || 'v-unreach';
  }

  // --- watch construction ----------------------------------------------------------
  function createWatch(envelope, envelopeUrl, baseline) {
    var ev = extractEvidence(envelope);
    if (ev.error) return { error: ev.error };
    var strategy = strategyFor(ev.method);
    return {
      watch: {
        watch_id: 'w_' + (ev.claim_id || 'raw').replace(/^clm_/, '').toLowerCase(),
        claim_id: ev.claim_id,
        subject: ev.subject,
        statement: ev.statement,
        tier: ev.tier,
        envelope_url: envelopeUrl || null,
        evidence_url: ev.source_url,
        evidence_method: ev.method,
        strategy: strategy,
        cadence: 'daily',
        baseline: baseline || null,
        latest: null
      }
    };
  }

  function parseWatchParam(search) {
    var q = (search || '').replace(/^\?/, '');
    var m = q.match(/(?:^|&)watch=([^&]+)/);
    if (!m) return null;
    try { return decodeURIComponent(m[1]); } catch (e) { return null; }
  }

  return {
    VERDICTS: VERDICTS,
    sha256HexSync: sha256HexSync,
    sha256HexAsync: sha256HexAsync,
    extractEvidence: extractEvidence,
    strategyFor: strategyFor,
    strategyTarget: strategyTarget,
    checkEvidence: checkEvidence,
    classify: classify,
    diffWatch: diffWatch,
    buildFinding: buildFinding,
    badgeClass: badgeClass,
    createWatch: createWatch,
    parseWatchParam: parseWatchParam,
    nodeFetch: nodeFetch
  };
});
