import {readFile, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'docs/planning/requirements-dashboard.html');
const master = await readFile(resolve(root, 'docs/planning/requirements/master-requirements.md'), 'utf8');
const acceptance = await readFile(resolve(root, 'docs/planning/requirements/acceptance-ledger.md'), 'utf8');
const ledger = JSON.parse(await readFile(resolve(root, 'evidence/requirements-ledger.json'), 'utf8'));

const requirements = parseRequirements(master);
const proofs = parseProofs(acceptance);
const rows = ledger.requirements.map(({id, status}) => {
  const requirement = requirements.get(id);
  const proof = proofs.get(id);
  if (!requirement || !proof) throw new Error(`dashboard source is incomplete for ${id}`);
  return {id, status, ...requirement, ...proof};
}).sort((left, right) => left.id.localeCompare(right.id));

const document = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Runtime requirements</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #f6f7fb; color: #171923; }
    body { margin: 0; }
    main { max-width: 1240px; margin: 0 auto; padding: 32px 20px 64px; }
    h1 { margin: 0; font-size: clamp(1.75rem, 4vw, 2.6rem); }
    .sub { color: #5c6375; margin: 8px 0 24px; max-width: 72ch; }
    .summary { display: flex; flex-wrap: wrap; gap: 10px; margin: 0 0 20px; }
    .count, button { border: 1px solid #d7dbe7; border-radius: 999px; padding: 8px 12px; background: #fff; color: inherit; font: inherit; }
    button { cursor: pointer; }
    button[aria-pressed="true"] { outline: 3px solid #b8ccff; border-color: #5e80e8; }
    .controls { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; margin-bottom: 20px; }
    input { width: 100%; box-sizing: border-box; border: 1px solid #bfc6d7; border-radius: 8px; padding: 11px 12px; font: inherit; background: #fff; color: inherit; }
    .filters { display: flex; flex-wrap: wrap; gap: 8px; }
    .table-wrap { overflow-x: auto; border: 1px solid #d7dbe7; border-radius: 12px; background: #fff; }
    table { width: 100%; min-width: 900px; border-collapse: collapse; }
    th, td { padding: 13px 14px; vertical-align: top; border-bottom: 1px solid #e6e8ef; text-align: left; line-height: 1.45; }
    th { position: sticky; top: 0; background: #f0f3fa; z-index: 1; font-size: .84rem; letter-spacing: .03em; text-transform: uppercase; }
    tr:last-child td { border-bottom: 0; }
    .id { font-weight: 700; white-space: nowrap; }
    .area { color: #5c6375; font-size: .88rem; }
    .badge { display: inline-block; border-radius: 999px; padding: 3px 8px; font-weight: 700; font-size: .8rem; white-space: nowrap; }
    .completed { background: #d8f3dd; color: #155724; }
    .in_progress { background: #fff0bd; color: #714d00; }
    .not_started { background: #eceef5; color: #3f4658; }
    .empty { padding: 36px; text-align: center; color: #5c6375; }
    @media (prefers-color-scheme: dark) { :root { background: #10131a; color: #edf1fa; } .sub, .area, .empty { color: #b6bfd3; } .count, button, input, .table-wrap { background: #1a1f2a; border-color: #384154; } th { background: #202737; } td { border-color: #30394b; } button[aria-pressed="true"] { outline-color: #4d6cbe; } .completed { background: #174d2a; color: #d8f8df; } .in_progress { background: #624c10; color: #fff2bd; } .not_started { background: #303747; color: #e2e7f3; } }
    @media (max-width: 640px) { main { padding: 24px 12px 48px; } .controls { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <h1>Agent Runtime requirements</h1>
    <p class="sub">Every requirement, its current evidence state, the actual requirement, and the proof needed to call it done.</p>
    <div class="summary" id="summary" aria-label="Requirement totals"></div>
    <div class="controls">
      <input id="search" type="search" placeholder="Search ID, feature, or proof…" aria-label="Search requirements">
      <div class="filters" aria-label="Status filters">
        <button type="button" data-status="all" aria-pressed="true">All</button>
        <button type="button" data-status="completed" aria-pressed="false">Done</button>
        <button type="button" data-status="in_progress" aria-pressed="false">In progress</button>
        <button type="button" data-status="not_started" aria-pressed="false">Not started</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Requirement</th><th>State</th><th>What it means</th><th>What proves it</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </main>
  <script>
    const requirements = ${JSON.stringify(rows).replace(/</g, '\\u003c')};
    const labels = {completed: 'Done', in_progress: 'In progress', not_started: 'Not started'};
    const rows = document.getElementById('rows');
    const search = document.getElementById('search');
    const buttons = [...document.querySelectorAll('[data-status]')];
    let selected = 'all';
    const text = value => document.createTextNode(value);
    const cell = (row, value, className = '') => { const element = document.createElement('td'); if (className) element.className = className; element.append(text(value)); row.append(element); };
    function render() {
      const term = search.value.trim().toLowerCase();
      const visible = requirements.filter(requirement => (selected === 'all' || requirement.status === selected) && JSON.stringify(requirement).toLowerCase().includes(term));
      rows.replaceChildren();
      if (!visible.length) { const row = document.createElement('tr'); const item = document.createElement('td'); item.colSpan = 4; item.className = 'empty'; item.append(text('No requirements match this view.')); row.append(item); rows.append(row); return; }
      for (const requirement of visible) {
        const row = document.createElement('tr');
        const identifier = document.createElement('td'); identifier.innerHTML = '<div class="id"></div><div class="area"></div>'; identifier.querySelector('.id').append(text(requirement.id)); identifier.querySelector('.area').append(text(requirement.area)); row.append(identifier);
        const state = document.createElement('td'); const badge = document.createElement('span'); badge.className = 'badge ' + requirement.status; badge.append(text(labels[requirement.status])); state.append(badge); row.append(state);
        cell(row, requirement.description);
        cell(row, requirement.acceptance + ' Documentation: ' + requirement.documentation);
        rows.append(row);
      }
    }
    const summary = document.getElementById('summary');
    for (const status of ['completed', 'in_progress', 'not_started']) { const count = requirements.filter(item => item.status === status).length; const item = document.createElement('span'); item.className = 'count'; item.append(text(labels[status] + ': ' + count)); summary.append(item); }
    search.addEventListener('input', render);
    for (const button of buttons) button.addEventListener('click', () => { selected = button.dataset.status; for (const item of buttons) item.setAttribute('aria-pressed', String(item === button)); render(); });
    render();
  </script>
</body>
</html>`;

if (process.argv.includes('--check')) {
  const existing = await readFile(output, 'utf8');
  if (existing !== document) throw new Error('requirements dashboard is stale; run just requirements-dashboard');
} else {
  await writeFile(output, document);
  console.log(`wrote ${output}`);
}

function parseRequirements(source) {
  const records = new Map();
  let area = '';
  let current;
  const finish = () => {
    if (!current) return;
    current.description = current.description.replace(/\s+/g, ' ').trim();
    records.set(current.id, current);
  };
  for (const line of source.split('\n')) {
    const heading = line.match(/^### (.+)$/);
    if (heading) { area = heading[1]; continue; }
    const entry = line.match(/^- \*\*([A-Z][A-Z-]*-\d+)\*\* — (.*)$/);
    if (entry) { finish(); current = {id: entry[1], area, description: entry[2]}; continue; }
    if (current && line.trim() && !line.startsWith('##') && !line.startsWith('- **')) current.description += ' ' + line.trim();
  }
  finish();
  return records;
}

function parseProofs(source) {
  const records = new Map();
  for (const line of source.split('\n')) {
    if (!line.startsWith('| ')) continue;
    const cells = line.split('|').map(cell => cell.trim());
    if (!/^[A-Z][A-Z-]*-\d+$/.test(cells[1] || '')) continue;
    records.set(cells[1], {acceptance: cells[2], documentation: cells[3]});
  }
  return records;
}
