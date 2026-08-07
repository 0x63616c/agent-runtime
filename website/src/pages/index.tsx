import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import styles from './index.module.css';

const principles = [
  ['Durable by design', 'Sessions and Turns are designed around durable state, resumable observation, and explicit terminal outcomes.'],
  ['Authority is explicit', 'A model tool call is intent. Policy, approval, capability grants, and recorded execution remain separate.'],
  ['Evidence before claims', 'The docs distinguish planned architecture from locally verified behavior and Linux/KVM security evidence.'],
];

export default function Home(): ReactNode {
  return (
    <Layout title="Durable agent infrastructure" description="Modern documentation for Agent Runtime.">
      <main>
        <section className={styles.hero}>
          <div className={styles.eyebrow}>OPEN SOURCE · DURABLE · EXPLICIT</div>
          <Heading as="h1">Build agents that can survive the real world.</Heading>
          <p>Agent Runtime is a monorepo for durable sessions, governed tools, human approvals, artifacts, and isolated execution.</p>
          <div className={styles.actions}>
            <Link className="button button--primary button--lg" to="/docs/start-here">Explore the foundation</Link>
            <Link className="button button--secondary button--lg" to="/docs/security/verified-boundaries">Read the safety boundary</Link>
          </div>
        </section>
        <section className={styles.grid} aria-label="Project principles">
          {principles.map(([title, body]) => (
            <article className={styles.card} key={title}>
              <Heading as="h2">{title}</Heading>
              <p>{body}</p>
            </article>
          ))}
        </section>
        <aside className={styles.status}>
          <strong>Current status: M0 foundation.</strong> The public runtime, SDK, examples, and production deployment are not implemented yet.
        </aside>
      </main>
    </Layout>
  );
}
