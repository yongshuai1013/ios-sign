import type { ReactNode } from 'react';

type Tone = 'default' | 'success' | 'accent' | 'danger';

export function Chip({ tone = 'default', children }: { tone?: Tone; children: ReactNode }) {
  const dataTone = tone === 'default' ? undefined : tone;
  return (
    <span className="chip" data-tone={dataTone}>
      {children}
    </span>
  );
}
