import {readdir, readFile, stat} from 'node:fs/promises';
import {relative, resolve} from 'node:path';

const root = new URL('..', import.meta.url);
const siteOrigin = 'https://0x63616c.github.io';
const editOrigin = 'https://github.com/0x63616c/agent-runtime/edit/main/website/';
const manifest = JSON.parse(await readFile(new URL('./route-manifest.json', root), 'utf8'));
const dist = resolve(new URL('./dist/', root).pathname);

validateManifest(manifest);

const pages = new Map();
for (const output of await htmlFiles(dist)) {
  pages.set(relative(dist, output), await readFile(output, 'utf8'));
}

for (const route of manifest.routes) {
  const page = pages.get(route.output);
  if (page === undefined) {
    throw new Error(`documentation route ${route.route} did not render ${route.output}`);
  }
  if (page.includes('__docusaurus')) {
    throw new Error(`documentation route ${route.route} still contains Docusaurus runtime output`);
  }
  if (route.redirect) {
    assertRedirect(route, page);
  } else {
    await assertPage(route, page);
  }
}

for (const [output, page] of pages) {
  await assertLinksAndAnchors(output, page);
}

console.log(`validated ${manifest.routes.length} public and legacy documentation routes, static hrefs, anchors, sidebar navigation, and edit targets`);

function validateManifest(value) {
  if (value.schemaVersion !== 2 || !Array.isArray(value.routes) || value.routes.length === 0 || !Array.isArray(value.sidebarRoutes)) {
    throw new Error('documentation route manifest must declare a non-empty schema-version 2 route list and sidebar routes');
  }
  if (!canonicalRoute(value.basePath)) {
    throw new Error(`documentation route manifest basePath is invalid: ${JSON.stringify(value.basePath)}`);
  }
  const routes = new Set();
  const outputs = new Set();
  for (const route of value.routes) {
    if (!canonicalRoute(route.route) || !canonicalOutput(route.output) || outputs.has(route.output) || routes.has(route.route)) {
      throw new Error(`documentation route manifest has an invalid route entry: ${JSON.stringify(route)}`);
    }
    if (route.redirect) {
      if (typeof route.redirect !== 'string' || !route.redirect.startsWith(`${value.basePath}/`)) {
        throw new Error(`documentation redirect ${route.route} must target the declared project base`);
      }
    } else if (typeof route.contains !== 'string' || route.contains === '') {
      throw new Error(`documentation route ${route.route} must declare rendered content`);
    } else if (route.route.startsWith('/docs/') && (typeof route.source !== 'string' || !route.source.startsWith('src/content/docs/docs/') || !route.source.endsWith('.mdx'))) {
      throw new Error(`documentation route ${route.route} must declare its canonical MDX source`);
    }
    routes.add(route.route);
    outputs.add(route.output);
  }
  for (const route of value.sidebarRoutes) {
    if (!routes.has(route) || !route.startsWith('/docs/')) {
      throw new Error(`documentation sidebar route is not a declared docs route: ${JSON.stringify(route)}`);
    }
  }
  if (new Set(value.sidebarRoutes).size !== value.sidebarRoutes.length) {
    throw new Error('documentation sidebar routes must not contain duplicates');
  }
}

function canonicalRoute(value) {
  return typeof value === 'string' && value.startsWith('/') && (value === '/' || !value.endsWith('/')) && !value.includes('..') && !value.includes('\\');
}

function canonicalOutput(value) {
  return typeof value === 'string' && value !== '' && !value.startsWith('/') && !value.includes('..') && !value.includes('\\');
}

async function assertPage(route, page) {
  if (!page.includes(route.contains)) {
    throw new Error(`documentation route ${route.route} rendered ${route.output} without ${JSON.stringify(route.contains)}`);
  }
  if (route.route.startsWith('/docs/')) {
    await assertPublishedTitle(route, page);
    assertPublishedContentBoundary(route, page);
    if (!page.includes('id="starlight__sidebar"')) {
      throw new Error(`documentation route ${route.route} rendered without the Starlight sidebar`);
    }
    for (const sidebarRoute of manifest.sidebarRoutes) {
      assertHref(page, `${manifest.basePath}${sidebarRoute}`, `documentation sidebar on ${route.route}`);
    }
    assertHref(page, `${editOrigin}${route.source}`, `documentation edit link on ${route.route}`);
  }
}

// Checking source MDX prevents the usual duplicate-title mistake, but the
// release artifact is the authority for what a reader actually sees. Keep the
// rendered invariant here so a theme or content-pipeline change cannot quietly
// introduce a second title (or publish delivery-tracking terminology).
async function assertPublishedTitle(route, page) {
  const source = await readFile(resolve(root.pathname, route.source), 'utf8');
  const expected = frontmatter(source, 'title');
  if (!expected) throw new Error(`documentation source ${route.source} has no title frontmatter`);

  const headings = [...page.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi)];
  if (headings.length !== 1) {
    throw new Error(`documentation route ${route.route} rendered ${headings.length} H1 headings; public pages must render exactly one title`);
  }
  const rendered = visibleText(headings[0][1]);
  if (rendered !== expected) {
    throw new Error(`documentation route ${route.route} rendered H1 ${JSON.stringify(rendered)}, expected frontmatter title ${JSON.stringify(expected)}`);
  }
}

function assertPublishedContentBoundary(route, page) {
  const main = page.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)?.[1];
  if (!main) throw new Error(`documentation route ${route.route} rendered without public main content`);
  const published = visibleText(main);
  const forbidden = [
    [/\bM(?:10|[0-9])\b/, 'milestone label'],
    [/\b(?:API|DAT|DEP|DOC|ENG|EX|HITL|INF|MOD|MON|OBS|OPS-STAT|PAY|SBX|TMP|TOL|TST)-\d{3}\b/, 'internal requirement identifier'],
    [/\brequirements ledger\b/i, 'internal requirements ledger'],
  ];
  for (const [pattern, description] of forbidden) {
    if (pattern.test(published)) {
      throw new Error(`documentation route ${route.route} publishes ${description} in its rendered content`);
    }
  }
}

function frontmatter(content, key) {
  const match = content.match(new RegExp(`^---\\n[\\s\\S]*?^${key}:\\s*(.+?)\\s*$[\\s\\S]*?^---`, 'm'));
  return match?.[1]?.trim();
}

function visibleText(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(?:amp|#38);/g, '&')
    .replace(/&(?:lt|#60);/g, '<')
    .replace(/&(?:gt|#62);/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function assertRedirect(route, page) {
  assertHref(page, route.redirect, `documentation redirect ${route.route}`);
  if (!page.includes(`content="0;url=${route.redirect}"`)) {
    throw new Error(`documentation redirect ${route.route} does not retain its base-prefixed meta refresh target`);
  }
  const canonical = `${siteOrigin}${route.redirect}`;
  if (!page.includes(`rel="canonical" href="${canonical}"`)) {
    throw new Error(`documentation redirect ${route.route} does not retain canonical ${canonical}`);
  }
}

async function assertLinksAndAnchors(output, page) {
  const ids = anchors(page);
  for (const href of hrefs(page)) {
    if (href.includes('.md') && !href.startsWith('https://github.com/')) {
      throw new Error(`documentation artifact ${output} still links to a source document: ${href}`);
    }
    if (href.startsWith('#')) {
      assertAnchor(output, ids, href);
      continue;
    }
    if (!href.startsWith('/') && !href.startsWith(siteOrigin) && !/^[a-z][a-z0-9+.-]*:/i.test(href)) {
      throw new Error(`documentation artifact ${output} has a relative or protocol-less href: ${href}`);
    }
    const internal = internalHref(href);
    if (!internal) {
      continue;
    }
    if (!internal.pathname.startsWith(`${manifest.basePath}/`) && internal.pathname !== manifest.basePath) {
      throw new Error(`documentation artifact ${output} has an internal href outside ${manifest.basePath}: ${href}`);
    }
    const target = outputForPath(internal.pathname);
    const targetPage = pages.get(target);
    if (targetPage === undefined && !(await fileExists(resolve(dist, internal.pathname.slice(manifest.basePath.length + 1))))) {
      throw new Error(`documentation artifact ${output} links to missing ${href}`);
    }
    if (internal.hash && targetPage !== undefined) {
      assertAnchor(target, anchors(targetPage), internal.hash);
    }
  }
}

function hrefs(page) {
  return [...page.matchAll(/\bhref=(?:"([^"]*)"|'([^']*)')/g)].map((match) => match[1] ?? match[2]);
}

function anchors(page) {
  return new Set([...page.matchAll(/\bid=(?:"([^"]*)"|'([^']*)')/g)].map((match) => match[1] ?? match[2]));
}

function assertHref(page, expected, context) {
  if (!hrefs(page).includes(expected)) {
    throw new Error(`${context} did not emit href=${JSON.stringify(expected)}`);
  }
}

function assertAnchor(output, ids, hash) {
  const anchor = decodeURIComponent(hash.slice(1));
  if (!ids.has(anchor)) {
    throw new Error(`documentation artifact ${output} links to missing anchor ${hash}`);
  }
}

function internalHref(href) {
  if (href.startsWith('/')) {
    return new URL(href, siteOrigin);
  }
  if (!href.startsWith(siteOrigin)) {
    return undefined;
  }
  return new URL(href);
}

function outputForPath(pathname) {
  const route = pathname.slice(manifest.basePath.length).replace(/^\//, '');
  if (route === '') {
    return 'index.html';
  }
  if (route === '404') {
    return '404.html';
  }
  return `${route}/index.html`;
}

async function htmlFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, {withFileTypes: true})) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await htmlFiles(path));
    } else if (entry.isFile() && entry.name.endsWith('.html')) {
      files.push(path);
    }
  }
  return files.sort();
}

async function fileExists(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}
