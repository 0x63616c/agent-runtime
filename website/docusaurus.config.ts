import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Agent Runtime',
  tagline: 'Durable sessions, explicit authority, honest evidence.',
  url: 'https://0x63616c.github.io',
  baseUrl: '/agent-runtime/',
  organizationName: '0x63616c',
  projectName: 'agent-runtime',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',
  future: {v4: true},
  customFields: {
    search: false,
    searchState: 'Awaiting public deployment and DocSearch crawl approval',
  },
  i18n: {defaultLocale: 'en', locales: ['en']},
  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/0x63616c/agent-runtime/edit/main/website/',
          showLastUpdateAuthor: false,
          showLastUpdateTime: false,
        },
        blog: false,
        theme: {customCss: './src/css/custom.css'},
        sitemap: {lastmod: null, changefreq: null, priority: null},
      } satisfies Preset.Options,
    ],
  ],
  themeConfig: {
    colorMode: {respectPrefersColorScheme: true},
    navbar: {
      title: 'Agent Runtime',
      items: [
        {type: 'docSidebar', sidebarId: 'docs', label: 'Documentation', position: 'left'},
        {to: '/docs/reference/overview', label: 'Reference', position: 'left'},
        {href: 'https://github.com/0x63616c/agent-runtime', label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {title: 'Learn', items: [{label: 'Start here', to: '/docs/start-here'}]},
        {title: 'Operate', items: [{label: 'Verified boundaries', to: '/docs/security/verified-boundaries'}]},
        {title: 'Project', items: [{label: 'GitHub', href: 'https://github.com/0x63616c/agent-runtime'}]},
      ],
      copyright: 'Agent Runtime · MIT licensed · Documentation reflects verified implementation state.',
    },
    prism: {theme: prismThemes.github, darkTheme: prismThemes.dracula},
  } satisfies Preset.ThemeConfig,
};

export default config;
