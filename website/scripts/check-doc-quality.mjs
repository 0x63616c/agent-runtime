import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';

// This is deliberately a source gate rather than a rendered-page heuristic.
// Starlight renders frontmatter titles, so an author-written H1 would repeat
// the visible page title. The snippet catalog makes every public code fence an
// intentional review item: either it has a deterministic CI syntax/parser
// check or it is explicitly non-executable with a reader-facing rationale.
const website = new URL('..', import.meta.url);
const repository = resolve(new URL('../..', import.meta.url).pathname);
const manifest = JSON.parse(await readFile(new URL('./route-manifest.json', website), 'utf8'));
const catalog = JSON.parse(await readFile(new URL('./snippets.json', website), 'utf8'));

if (catalog.schemaVersion !== 1 || !Array.isArray(catalog.snippets)) {
  throw new Error('documentation snippet catalog must declare schemaVersion 1 and a snippets array');
}

const entries = new Map();
for (const entry of catalog.snippets) {
  if (!validEntry(entry) || entries.has(entry.id)) {
    throw new Error(`documentation snippet catalog has an invalid or duplicate entry: ${JSON.stringify(entry)}`);
  }
  entries.set(entry.id, entry);
}

const sourceFiles = [...new Set(manifest.routes.filter((route) => route.source).map((route) => `website/${route.source}`))].sort();
const found = [];
for (const file of sourceFiles) {
  const content = await readFile(resolve(repository, file), 'utf8');
  const title = frontmatter(content, 'title');
  const description = frontmatter(content, 'description');
  if (!title || !description) throw new Error(`${file} must declare non-empty title and description frontmatter`);
  if (/^#\s+/m.test(content)) throw new Error(`${file} contains an author H1; Starlight renders the frontmatter title and would repeat it`);

  let ordinal = 0;
  for (const fence of fences(content)) {
    ordinal++;
    const id = `${file}#${ordinal}`;
    const entry = entries.get(id);
    if (!entry) throw new Error(`${file} code fence ${ordinal} is unclassified; add it to website/snippets.json`);
    const digest = sha256(fence.body);
    if (entry.language !== fence.language || entry.digest !== digest) {
      throw new Error(`${id} differs from its reviewed catalog entry; update its language, digest, and verification rationale together`);
    }
    verify(entry, fence.body);
    found.push(id);
  }
}

if (found.length !== entries.size || [...entries.keys()].some((id) => !found.includes(id))) {
  throw new Error('documentation snippet catalog contains stale entries; remove them or restore the matching public fence');
}

console.log(`validated ${sourceFiles.length} public docs sources, no repeated rendered titles, and ${found.length} classified code fences`);

function validEntry(entry) {
  return entry && typeof entry.id === 'string' && /^website\/src\/content\/docs\/docs\/.+\.mdx#\d+$/.test(entry.id)
    && typeof entry.language === 'string' && /^[a-z0-9+-]+$/i.test(entry.language)
    && typeof entry.digest === 'string' && /^[a-f0-9]{64}$/.test(entry.digest)
    && ['shell-syntax', 'json', 'non-executable'].includes(entry.verification)
    && typeof entry.rationale === 'string' && entry.rationale.trim().length >= 20;
}

function verify(entry, body) {
  switch (entry.verification) {
    case 'shell-syntax': {
      if (!['sh', 'bash'].includes(entry.language)) throw new Error(`${entry.id} shell-syntax verification requires sh or bash`);
      // The docs may deliberately show commands that start servers or modify a
      // disposable stack. Parse only: this proves syntax without performing a
      // surprise operator action in CI.
      const result = spawnSync('/bin/sh', ['-n'], {input: body, encoding: 'utf8'});
      if (result.status !== 0) throw new Error(`${entry.id} is not valid POSIX shell: ${result.stderr.trim()}`);
      return;
    }
    case 'json':
      try { JSON.parse(`{${body}}`); } catch (error) { throw new Error(`${entry.id} is not valid JSON object content: ${error.message}`); }
      return;
    case 'non-executable':
      return;
  }
}

function frontmatter(content, key) {
  const match = content.match(new RegExp(`^---\\n[\\s\\S]*?^${key}:\\s*(.+?)\\s*$[\\s\\S]*?^---`, 'm'));
  return match?.[1]?.trim();
}

function fences(content) {
  return [...content.matchAll(/^```([^\n]*)\n([\s\S]*?)^```\s*$/gm)].map((match) => ({language: match[1].trim() || 'plain', body: match[2]}));
}

function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
