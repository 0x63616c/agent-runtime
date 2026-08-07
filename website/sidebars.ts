import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'start-here/index',
    {type: 'category', label: 'Concepts', items: ['concepts/runtime-language']},
    {type: 'category', label: 'Build and run', items: ['build-and-run/local-foundation']},
    {type: 'category', label: 'Reference', items: ['reference/overview', 'reference/generated/source-inventory']},
    {type: 'category', label: 'Security and reliability', items: ['security/verified-boundaries']},
    {type: 'category', label: 'Examples', items: ['examples/index']},
    {type: 'category', label: 'Help', items: ['help/publication-operations']},
  ],
};

export default sidebars;
