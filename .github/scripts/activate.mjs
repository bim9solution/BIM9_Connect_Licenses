// BIM9_Connect activation service - GitHub side (runs in GitHub Actions).
// Reads the request issues opened by the add-in / LicenseKeyGen, applies them
// (core.mjs), writes the signed licenses.json and labels + closes each issue
// with its verdict ("bim9-ok" / "bim9-r-<code>"), which the add-in reads.
import { loadServiceKeys, processRequests, signRegistry, openRegistryAny } from './core.mjs';

const REPO = process.env.GITHUB_REPOSITORY;
const OWNER = REPO.split('/')[0].toLowerCase();
const TOKEN = process.env.GITHUB_TOKEN;
const API = `https://api.github.com/repos/${REPO}`;
const KEYS = loadServiceKeys(process.env.LICENSE_SERVICE_KEY);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function gh(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'bim9-license-service',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: res.status, json };
}

async function readRegistry() {
  const r = await gh('GET', '/contents/licenses.json?ref=main');
  if (r.status === 404) return { doc: null, sha: undefined };
  if (r.status !== 200) throw new Error(`read licenses.json: HTTP ${r.status}`);
  const envelope = JSON.parse(Buffer.from(r.json.content, 'base64').toString('utf8'));
  const doc = openRegistryAny(envelope, KEYS);
  if (!doc) throw new Error('licenses.json does not verify with the service key - refusing to overwrite it');
  // Still signed with the previous key (after a rotation): re-sign it now.
  const resign = !openRegistryAny(envelope, { ...KEYS, prevSignPub: null });
  return { doc, sha: r.json.sha, resign };
}

// Open request issues, plus ones closed in the last 2 days without a verdict
// (closed by someone else before the service got to them).
async function listRequests() {
  const found = new Map();
  const since = new Date(Date.now() - 2 * 86400e3).toISOString();
  for (const state of ['open', 'closed']) {
    for (let page = 1; page <= 10; page++) {
      const q = `state=${state}&per_page=100&page=${page}&sort=created&direction=asc` + (state === 'closed' ? `&since=${since}` : '');
      const r = await gh('GET', `/issues?${q}`);
      if (r.status !== 200 || !Array.isArray(r.json) || r.json.length === 0) break;
      for (const it of r.json) {
        if (it.pull_request) continue;
        if (!String(it.title ?? '').startsWith('BIM9 ')) continue;
        if ((it.user?.login ?? '').toLowerCase() !== OWNER) continue;   // only requests sent with the owner's token
        if ((it.labels ?? []).some((l) => (l.name ?? l) === 'bim9-done')) continue;
        found.set(it.number, { number: it.number, body: it.body ?? '' });
      }
      if (r.json.length < 100) break;
    }
  }
  return [...found.values()].sort((a, b) => a.number - b.number);
}

async function finish(result) {
  const verdict = result.ok ? 'bim9-ok' : `bim9-r-${result.code}`;
  const r = await gh('PATCH', `/issues/${result.number}`, {
    state: 'closed',
    state_reason: result.ok ? 'completed' : 'not_planned',
    labels: ['bim9-done', verdict],
  });
  if (r.status !== 200) console.log(`warning: could not label #${result.number} (HTTP ${r.status})`);
}

async function main() {
  for (let attempt = 1; attempt <= 6; attempt++) {
    const { doc, sha, resign } = await readRegistry();
    const requests = await listRequests();
    if (requests.length === 0 && !resign) {
      console.log('No pending requests.');
      return;
    }

    const { registry, results, changed } = processRequests({ registry: doc, requests, keys: KEYS, now: new Date() });
    if (resign && !changed) registry.seq = (Number(registry.seq) || 0) + 1;
    if (changed || resign) {
      const content = Buffer.from(JSON.stringify(signRegistry(registry, KEYS.signPriv), null, 2) + '\n').toString('base64');
      const put = await gh('PUT', '/contents/licenses.json', {
        message: `licenses: seq ${registry.seq}`,
        content,
        branch: 'main',
        ...(sha ? { sha } : {}),
      });
      if (put.status === 409 || put.status === 422) {          // someone else wrote meanwhile: redo on top of it
        console.log(`licenses.json changed meanwhile (HTTP ${put.status}) - retrying`);
        await sleep(1500 * attempt);
        continue;
      }
      if (put.status !== 200 && put.status !== 201) throw new Error(`write licenses.json: HTTP ${put.status}`);
    }

    // Verdicts only after licenses.json is saved: "bim9-ok" means "it is in the list".
    for (const r of results) await finish(r);
    for (const r of results) console.log(`#${r.number}: ${r.ok ? 'ok' : 'rejected'} (${r.code})`);
    return;
  }
  throw new Error('gave up after repeated concurrent updates');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
