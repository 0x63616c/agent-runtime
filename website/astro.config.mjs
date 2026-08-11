import {defineConfig} from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://0x63616c.github.io',
  base: '/agent-runtime',
  trailingSlash: 'never',
  redirects: {
    '/start-here': '/docs/start-here',
    '/reference/overview': '/docs/reference/overview',
    '/reference/postgresql-data-authority': '/docs/reference/postgresql-data-authority',
    '/reference/runtime-go-contract': '/docs/reference/runtime-go-contract',
    '/reference/temporal-payloads': '/docs/reference/temporal-payloads',
  },
  integrations: [
    starlight({
      title: 'Agent Runtime',
      description: 'Durable sessions, explicit authority, honest evidence.',
      customCss: ['./src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/0x63616c/agent-runtime/edit/main/website/src/content/docs/',
      },
      social: [
        {icon: 'github', label: 'GitHub', href: 'https://github.com/0x63616c/agent-runtime'},
      ],
      sidebar: [
        {label: 'Start here', items: [{label: 'Foundation', slug: 'docs/start-here'}]},
        {
          label: 'Build and run',
          items: [
            {label: 'Local foundation', slug: 'docs/build-and-run/local-foundation'},
            {label: 'Isolated local Stack', slug: 'docs/build-and-run/local-stack'},
          ],
        },
        {label: 'Concepts', items: [{label: 'Runtime language', slug: 'docs/concepts/runtime-language'}]},
        {
          label: 'Reference',
          items: [
            {label: 'Overview', slug: 'docs/reference/overview'},
            {label: 'Runtime Go contract', slug: 'docs/reference/runtime-go-contract'},
            {label: 'Runtime HTTP API', slug: 'docs/reference/runtime-http-api'},
            {label: 'PostgreSQL data authority', slug: 'docs/reference/postgresql-data-authority'},
            {label: 'Temporal payloads', slug: 'docs/reference/temporal-payloads'},
            {label: 'Sandbox control ledger', slug: 'docs/reference/sandbox-control-ledger'},
            {label: 'Sandbox host control', slug: 'docs/reference/sandbox-host-control'},
            {
              label: 'Generated reference',
              items: [
                {label: 'HTTP operations', slug: 'docs/reference/generated/http-operations'},
                {label: 'Go SDK symbols', slug: 'docs/reference/generated/go-sdk-symbols'},
                {label: 'Source inventory', slug: 'docs/reference/generated/source-inventory'},
              ],
            },
          ],
        },
        {
          label: 'Security and operations',
          items: [
            {label: 'Verified boundaries', slug: 'docs/security/verified-boundaries'},
            {label: 'Publication operations', slug: 'docs/help/publication-operations'},
          ],
        },
        {label: 'Examples', items: [{label: 'Examples', slug: 'docs/examples'}]},
      ],
    }),
  ],
});
