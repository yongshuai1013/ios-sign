import { useEffect, useRef } from 'react';

interface ProgressCardProps {
  percent: number;
  status: string;
  busy: boolean;
  logLines: string[];
  onDismiss?: () => void;
}

export function ProgressCard({ percent, status, busy, logLines, onDismiss }: ProgressCardProps) {
  const clamped = Math.max(0, Math.min(100, percent));
  const done = !busy && clamped === 100;
  const failed = !busy && status === 'failed';
  const showModal = busy || done || failed;

  const logRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logLines]);

  const statusText = busy ? `${status} · ${clamped}%` : done ? 'Complete' : failed ? 'Failed' : 'idle';

  if (!showModal) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-[70] flex flex-col bg-bg/95 backdrop-blur-sm" style={{ opacity: 1 }}>
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <h2 className="text-[15px] font-semibold tracking-tight text-ink">
          {busy ? 'Working…' : done ? 'Done' : 'Failed'}
        </h2>
        {!busy && (
          <button
            type="button"
            onClick={onDismiss}
            className="flex h-7 w-7 items-center justify-center rounded-full text-muted transition-colors hover:bg-surface hover:text-ink"
          >
            <svg
              className="h-4 w-4"
              viewBox="0 0 16 16"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            >
              <path d="M4 4l8 8M12 4l-8 8" />
            </svg>
          </button>
        )}
      </div>

      <div className="mx-auto flex w-full max-w-[760px] flex-1 flex-col gap-6 overflow-hidden px-6 py-8">
        <div className="text-center">
          {busy && (
            <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-[3px] border-border border-t-ink" />
          )}
          {done && (
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-[var(--color-success-soft)]">
              <svg
                className="h-6 w-6 text-[var(--color-success)]"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                viewBox="0 0 24 24"
              >
                <path d="M5 13l4 4L19 7" />
              </svg>
            </div>
          )}
          {failed && (
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-[var(--color-danger-soft)]">
              <svg
                className="h-6 w-6 text-[var(--color-danger)]"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                viewBox="0 0 24 24"
              >
                <path d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
          )}
          <p className="font-mono text-[13px] text-muted">{statusText}</p>
        </div>

        <div className="progress-track" aria-hidden="true">
          <div className="progress-fill" data-busy={busy ? 'true' : 'false'} style={{ width: `${clamped}%` }} />
        </div>

        <pre ref={logRef} className="log flex-1 min-h-0 overflow-auto">
          {logLines.length > 0 ? logLines.join('\n') : 'Waiting for output…'}
        </pre>
      </div>

      {!busy && (
        <div className="border-t border-border px-6 py-4 text-center">
          <button type="button" onClick={onDismiss} className="btn btn-primary min-w-[160px]">
            {done ? 'Done' : 'Close'}
          </button>
        </div>
      )}
    </div>
  );
}
