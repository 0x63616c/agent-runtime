import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';

const revision = process.env.PUBLIC_AGENT_RUNTIME_SOURCE_SHA;
if (!/^[0-9a-f]{40}$/.test(revision ?? '')) {
  throw new Error('PUBLIC_AGENT_RUNTIME_SOURCE_SHA must be an exact lowercase 40-character commit SHA');
}

const path = resolve(import.meta.dirname, '../dist/source-revision.json');
const marker = JSON.parse(await readFile(path, 'utf8'));
if (Object.keys(marker).length !== 2 || marker.schemaVersion !== 1 || marker.sourceRevision !== revision) {
  throw new Error(`source revision build marker at ${path} must contain only schemaVersion: 1 and the expected sourceRevision`);
}

console.log(`validated public source revision build marker for ${revision}`);
