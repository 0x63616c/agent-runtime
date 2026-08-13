import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';

// A mechanical publication boundary. It does not decide whether a capability
// is true; it prevents internal delivery tracking from becoming a user-facing
// product claim.
const root = new URL('..', import.meta.url);
const repository = resolve(new URL('../..', import.meta.url).pathname);
const manifest = JSON.parse(await readFile(new URL('./route-manifest.json', root), 'utf8'));
const forbidden = [
  [/\bM(?:10|[0-9])\b/, 'milestone label'],
  [/\b(?:API|DAT|DEP|DOC|ENG|EX|HITL|INF|MOD|MON|OBS|OPS-STAT|PAY|SBX|TMP|TOL|TST)-\d{3}\b/, 'internal requirement identifier'],
  [/\brequirements ledger\b/i, 'internal requirements ledger'],
  [/\bdocs\/planning\//, 'planning-document path'],
  [/\bevidence\/requirements-/, 'requirements evidence path'],
];
const sources = new Set(['README.md']);
for (const route of manifest.routes) if (route.source) sources.add(`website/${route.source}`);
for (const source of [...sources].sort()) {
  const content = await readFile(resolve(repository, source), 'utf8');
  for (const [pattern, description] of forbidden) {
    if (pattern.test(content)) throw new Error(`${source} exposes ${description}; public docs describe product behavior and boundaries, not internal delivery tracking`);
  }
  if (/\]\(website\/src\/content\/docs\//.test(content)) throw new Error(`${source} links readers to an unpublished MDX source instead of the public documentation site`);
}
const boundaries = await readFile(resolve(repository, 'website/src/content/docs/docs/security/verified-boundaries.mdx'), 'utf8');
for (const phrase of ['can never serve as Firecracker security evidence', 'Operators remain responsible']) {
  if (!boundaries.includes(phrase)) throw new Error(`verified boundaries guide must retain the public claim boundary: ${JSON.stringify(phrase)}`);
}
console.log(`validated public-claim boundary for ${sources.size} published documentation sources`);
