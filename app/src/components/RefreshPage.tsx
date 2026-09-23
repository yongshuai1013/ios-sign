import { useMemo, useState } from 'react';
import { Button } from './ui/Button';
import { DevicePicker } from './DevicePicker';
import type { InstalledAppInfo } from '../flows/refresh';
import type { CachedIpaMeta } from '../lib/ipa-cache';

/** Free Apple ID provisioning profiles last 7 days. */
const PROFILE_VALID_MS = 7 * 24 * 60 * 60 * 1000;

export interface RefreshRow {
  app: InstalledAppInfo;
  cached: CachedIpaMeta | null;
}

interface RefreshPageProps {
  knownUdids: string[];
  connectedUdid: string | null;
  selectedUdid: string;
  onSelectedUdidChange: (value: string) => void;

  onPair: () => void;
  pairBusy: boolean;
  pairDisabled: boolean;

  rows: RefreshRow[] | null;
  scanBusy: boolean;
  onScan: () => void;
  scanDisabled: boolean;

  refreshingBundleId: string | null;
  onRefresh: (bundleId: string) => void;
  onUploadIpa: (bundleId: string, displayName: string, file: File) => void;

  refreshResult: {
    bundleId: string;
    displayName: string;
    success: boolean;
    error?: string;
  } | null;
  onDismissResult: () => void;

  log: string[];
}

function expiryText(cachedAt: number): string {
  const expiresAt = cachedAt + PROFILE_VALID_MS;
  const left = expiresAt - Date.now();
  if (left <= 0) return 'expired';
  const days = Math.floor(left / (24 * 60 * 60 * 1000));
  const hours = Math.floor((left % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
  if (days > 0) return `${days}d ${hours}h left`;
  return `${hours}h left`;
}

export function RefreshPage({
  knownUdids,
  connectedUdid,
  selectedUdid,
  onSelectedUdidChange,
  onPair,
  pairBusy,
  pairDisabled,
  rows,
  scanBusy,
  onScan,
  scanDisabled,
  refreshingBundleId,
  onRefresh,
  onUploadIpa,
  refreshResult,
  onDismissResult,
  log,
}: RefreshPageProps) {
  const [search, setSearch] = useState('');
  const [confirmRow, setConfirmRow] = useState<RefreshRow | null>(null);
  const [uploadRow, setUploadRow] = useState<RefreshRow | null>(null);

  const filteredRows = useMemo(() => {
    if (!rows) return null;
    const q = search.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      ({ app }) =>
        app.displayName.toLowerCase().includes(q) || app.bundleId.toLowerCase().includes(q),
    );
  }, [rows, search]);

  const downloadLog = () => {
    const blob = new Blob([log.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sideimpactor-refresh-log-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Refresh Apps</h2>
        <p className="mt-1 text-sm text-muted">
          Re-sign apps you installed through this website with a fresh 7-day provisioning profile
          and overwrite-install them. User data is kept. Requires the USB cable and the original
          IPA cached from signing.
        </p>
      </div>

      <DevicePicker
        knownUdids={knownUdids}
        connectedUdid={connectedUdid}
        selectedUdid={selectedUdid}
        onSelectedChange={onSelectedUdidChange}
        onPair={onPair}
        pairing={pairBusy}
        pairDisabled={pairDisabled}
      />

      <div>
        <Button onClick={onScan} disabled={scanDisabled} busy={scanBusy}>
          {scanBusy ? 'Scanning…' : 'Scan Installed Apps'}
        </Button>
      </div>

      {rows !== null && rows.length === 0 && (
        <p className="text-sm text-muted">No user apps found on the device.</p>
      )}

      {rows !== null && rows.length > 0 && (
        <div>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search apps…"
            className="mb-3 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-accent"
          />
          {filteredRows !== null && filteredRows.length === 0 && (
            <p className="text-sm text-muted">No apps match “{search.trim()}”.</p>
          )}
        </div>
      )}

      {filteredRows !== null && filteredRows.length > 0 && (
        <ul className="divide-y divide-border rounded-lg border border-border">
          {filteredRows.map(({ app, cached }) => {
            const isRefreshing = refreshingBundleId === app.bundleId;
            return (
              <li key={app.bundleId} className="flex items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[15px] font-medium text-ink">{app.displayName}</div>
                  <div className="truncate text-xs text-muted">{app.bundleId}</div>
                  <div className="mt-0.5 text-xs text-muted">
                    {cached ? (
                      <span>profile {expiryText(cached.cachedAt)}</span>
                    ) : (
                      <span className="text-amber-600">no cached IPA</span>
                    )}
                  </div>
                </div>
                {cached ? (
                  <Button
                    onClick={() => setConfirmRow({ app, cached })}
                    disabled={refreshingBundleId !== null}
                    busy={isRefreshing}
                  >
                    {isRefreshing ? 'Refreshing…' : 'Refresh'}
                  </Button>
                ) : (
                  <Button
                    variant="ghost"
                    onClick={() => setUploadRow({ app, cached })}
                    disabled={refreshingBundleId !== null}
                  >
                    Upload IPA
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {log.length > 0 && (
        <div>
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-sm font-semibold">Log</h3>
            <Button variant="ghost" onClick={downloadLog}>
              Download log
            </Button>
          </div>
          <pre className="max-h-64 overflow-y-auto rounded-lg border border-border bg-muted/40 p-3 text-xs leading-relaxed">
            {log.join('\n')}
          </pre>
        </div>
      )}

      {confirmRow && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setConfirmRow(null)}
        >
          <div
            className="w-full max-w-sm rounded-xl border border-border bg-surface p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-base font-semibold text-ink">Refresh this app?</h3>
            <p className="mt-2 text-sm text-muted">
              <span className="font-medium text-ink">{confirmRow.app.displayName}</span>
              <br />
              <span className="text-xs">{confirmRow.app.bundleId}</span>
            </p>
            <p className="mt-2 text-sm text-muted">
              It will be re-signed with a fresh 7-day profile and reinstalled over the current
              copy. Your app data is kept.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setConfirmRow(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  onRefresh(confirmRow.app.bundleId);
                  setConfirmRow(null);
                }}
              >
                Refresh
              </Button>
            </div>
          </div>
        </div>
      )}

      {uploadRow && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setUploadRow(null)}
        >
          <div
            className="w-full max-w-sm rounded-xl border border-border bg-surface p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-base font-semibold text-ink">Upload IPA</h3>
            <p className="mt-2 text-sm text-muted">
              <span className="font-medium text-ink">{uploadRow.app.displayName}</span>
              <br />
              <span className="text-xs">{uploadRow.app.bundleId}</span>
            </p>
            <p className="mt-2 text-sm text-muted">
              Select the original .ipa file for this app. It will be cached in the browser so
              future refreshes work with one tap.
            </p>
            <input
              type="file"
              accept=".ipa,application/octet-stream"
              className="mt-3 w-full text-sm text-ink"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  onUploadIpa(uploadRow.app.bundleId, uploadRow.app.displayName, file);
                  setUploadRow(null);
                }
              }}
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setUploadRow(null)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}

      {refreshResult && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={onDismissResult}
        >
          <div
            className="w-full max-w-sm rounded-xl border border-border bg-surface p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-base font-semibold text-ink">
              {refreshResult.success ? 'Refresh complete' : 'Refresh failed'}
            </h3>
            <p className="mt-2 text-sm text-muted">
              <span className="font-medium text-ink">{refreshResult.displayName}</span>
              <br />
              <span className="text-xs">{refreshResult.bundleId}</span>
            </p>
            {refreshResult.success ? (
              <p className="mt-2 text-sm text-muted">
                The app was re-signed with a fresh 7-day profile and reinstalled. Your data is
                kept.
              </p>
            ) : (
              <p className="mt-2 text-sm text-red-600">
                {refreshResult.error ?? 'Unknown error'}
              </p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="primary" onClick={onDismissResult}>
                OK
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
