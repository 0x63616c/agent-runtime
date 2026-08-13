// This is deliberately a tiny public build attestation. GitHub Pages publishes
// the static response alongside the docs, allowing an external verifier to
// distinguish the exact source revision it observes without depending on the
// deployment UI or a mutable branch reference.
const revision = import.meta.env.PUBLIC_AGENT_RUNTIME_SOURCE_SHA;

if (!/^[0-9a-f]{40}$/.test(revision)) {
  throw new Error('PUBLIC_AGENT_RUNTIME_SOURCE_SHA must be an exact lowercase 40-character commit SHA');
}

export function GET() {
  return new Response(JSON.stringify({schemaVersion: 1, sourceRevision: revision}) + '\n', {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
    },
  });
}
