import { Button } from './ui/Button';
import type { StoredAccountSummary } from '../lib/account-session';

interface SavedAccountsListProps {
  accounts: StoredAccountSummary[];
  activeKey: string | null;
  cachedKeys: Set<string>;
  onSwitch: (summary: StoredAccountSummary) => void;
  onDelete?: (summary: StoredAccountSummary) => void;
}

function buildKey(summary: StoredAccountSummary): string {
  return `${summary.appleId.trim().toLowerCase()}::${summary.teamId.trim().toUpperCase()}`;
}

function formatUpdatedAt(iso: string): string {
  return Number.isNaN(Date.parse(iso)) ? iso : new Date(iso).toLocaleString();
}

export function SavedAccountsList({ accounts, activeKey, cachedKeys, onSwitch, onDelete }: SavedAccountsListProps) {
  if (accounts.length === 0) {
    return (
      <div className="flex flex-col items-center py-8 text-center">
        <p className="text-[14px] text-muted">No accounts yet.</p>
        <p className="mt-1 text-[12.5px] text-subtle">Click "Add Account" to sign in.</p>
      </div>
    );
  }

  return (
    <div>
      {accounts.map((item) => {
        const key = buildKey(item);
        const isActive = key === activeKey;
        const hasCachedSession = cachedKeys.has(key);
        return (
          <div key={key} className="acct-row" data-active={isActive ? 'true' : 'false'}>
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <p className="truncate text-[13.5px] font-medium text-ink">{item.appleId}</p>
                <p className="mt-0.5 text-[11.5px] text-muted">
                  {item.teamName} · {item.teamId} · {formatUpdatedAt(item.updatedAtIso)}
                  {hasCachedSession ? ' · session cached' : ''}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                {!isActive && (
                  <Button size="sm" variant="ghost" onClick={() => onSwitch(item)}>
                    {hasCachedSession ? 'Switch' : 'Re-Login'}
                  </Button>
                )}
                {isActive && <span className="px-2 text-[11.5px] font-medium text-[var(--color-success)]">Active</span>}
                {onDelete && (
                  <button
                    type="button"
                    onClick={() => onDelete(item)}
                    className="flex h-7 w-7 items-center justify-center rounded-md text-subtle transition-colors hover:bg-[var(--color-danger-soft)] hover:text-[var(--color-danger)]"
                    title="Remove account"
                  >
                    <svg
                      className="h-3.5 w-3.5"
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
            </div>
          </div>
        );
      })}
    </div>
  );
}
