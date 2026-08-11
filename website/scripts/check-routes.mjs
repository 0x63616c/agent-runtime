import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';

const root = new URL('..', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('./route-manifest.json', root), 'utf8'));

if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.routes) || manifest.routes.length === 0) {
  throw new Error('documentation route manifest must declare a non-empty schema-version 1 route list');
}

for (const route of manifest.routes) {
  if (!route.route.startsWith('/') || !route.output || !route.contains) {
    throw new Error(`documentation route manifest has an invalid route entry: ${JSON.stringify(route)}`);
  }
  const output = resolve(new URL('./dist/', root).pathname, route.output);
  const page = await readFile(output, 'utf8');
  if (!page.includes(route.contains)) {
    throw new Error(`documentation route ${route.route} rendered ${route.output} without ${JSON.stringify(route.contains)}`);
  }
  if (page.includes('__docusaurus')) {
    throw new Error(`documentation route ${route.route} still contains Docusaurus runtime output`);
  }
}

console.log(`validated ${manifest.routes.length} public and legacy documentation routes`);
