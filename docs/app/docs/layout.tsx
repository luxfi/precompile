import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { source } from '@/lib/source';
import type { ReactNode } from 'react';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: 'Lux Precompiles',
      }}
      links={[
        {
          text: 'Standard Contracts',
          url: 'https://standard.lux.network',
          external: true,
        },
      ]}
    >
      {children}
    </DocsLayout>
  );
}
