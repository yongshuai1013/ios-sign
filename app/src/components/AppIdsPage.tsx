import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button } from './ui/Button';
import { getApi, toAltTeam, toSession } from '../apple-signing';
import { restorePersistedAccountContexts } from '../lib/account-session';
import { accountKey } from '../lib/ids';
import type { AppID } from 'altsign.js';

/**
 * App ID 管理頁（#/appids）：列出該團隊的所有 App ID，可刪除不用的。
 * 免費 Apple ID 每 7 天最多建 10 個 App ID，刪掉不用的能騰出名額。
 * 刪除是不可逆操作，必須先彈確認框。
 */
export function AppIdsPage() {
  const accounts = useMemo(() => [...restorePersistedAccountContexts().values()], []);
  const [selectedKey, setSelectedKey] = useState(() =>
    accounts.length > 0 ? accountKey(accounts[0].appleId, accounts[0].team.identifier) : '',
  );
  const [appIds, setAppIds] = useState<AppID[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmTarget, setConfirmTarget] = useState<AppID | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadAppIds = useCallback(async () => {
    const ctx = accounts.find((a) => accountKey(a.appleId, a.team.identifier) === selectedKey);
    if (!ctx) {
      setAppIds(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const api = getApi();
      const list = await api.fetchAppIDs(toSession(ctx), toAltTeam(ctx));
      setAppIds(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setAppIds(null);
    } finally {
      setLoading(false);
    }
  }, [accounts, selectedKey]);

  useEffect(() => {
    loadAppIds();
  }, [loadAppIds]);

  async function handleDelete(appId: AppID) {
    const ctx = accounts.find((a) => accountKey(a.appleId, a.team.identifier) === selectedKey);
    if (!ctx) return;
    setDeletingId(appId.identifier);
    setError(null);
    try {
      const api = getApi();
      const res = await api.deleteAppId(toSession(ctx), toAltTeam(ctx), appId);
      const code = String(res.resultCode);
      if (code !== '0' && res.resultCode !== 0) {
        throw new Error(`刪除失敗 (resultCode=${code})${res.userString ? `: ${res.userString}` : ''}`);
      }
      setAppIds((prev) => (prev ? prev.filter((a) => a.identifier !== appId.identifier) : prev));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingId(null);
      setConfirmTarget(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">App IDs</h2>
        <p className="mt-1 text-sm text-muted">
          免費 Apple ID 每 7 天最多建立 10 個 App ID。刪掉不用的可以騰出名額。
          刪除是不可逆的，請確認該 App ID 不再需要。
        </p>
      </div>

      {accounts.length > 1 && (
        <label className="block text-sm">
          <span className="text-muted">Account</span>
          <select
            className="mt-1 block w-full rounded-lg border border-border bg-surface px-3 py-2"
            value={selectedKey}
            onChange={(e) => setSelectedKey(e.target.value)}
          >
            {accounts.map((a) => {
              const key = accountKey(a.appleId, a.team.identifier);
              return (
                <option key={key} value={key}>
                  {a.appleId} / {a.team.identifier}
                </option>
              );
            })}
          </select>
        </label>
      )}

      {accounts.length === 0 ? (
        <p className="text-sm text-muted">
          尚未登入。請先到 <a href="#/login" className="underline">Account</a> 頁面登入 Apple ID。
        </p>
      ) : (
        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={loadAppIds} disabled={loading}>
            {loading ? '載入中…' : '重新整理'}
          </Button>
          {appIds && (
            <span className="text-sm text-muted">
              共 {appIds.length} 個 App ID
            </span>
          )}
        </div>
      )}

      {error && (
        <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </p>
      )}

      {appIds && appIds.length > 0 && (
        <ul className="divide-y divide-border rounded-xl border border-border">
          {appIds.map((appId) => (
            <li key={appId.identifier} className="flex items-center justify-between gap-3 px-4 py-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-ink">{appId.name}</div>
                <div className="truncate text-xs text-muted">{appId.bundleIdentifier}</div>
                <div className="truncate text-xs text-muted opacity-70">{appId.identifier}</div>
              </div>
              <Button
                variant="ghost"
                onClick={() => setConfirmTarget(appId)}
                disabled={deletingId !== null}
                className="shrink-0 text-red-400"
              >
                {deletingId === appId.identifier ? '刪除中…' : '刪除'}
              </Button>
            </li>
          ))}
        </ul>
      )}

      {appIds && appIds.length === 0 && !loading && (
        <p className="text-sm text-muted">這個團隊還沒有 App ID。</p>
      )}

      {confirmTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setConfirmTarget(null)}
        >
          <div
            className="w-full max-w-sm rounded-xl border border-border bg-surface p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-base font-semibold text-ink">刪除這個 App ID？</h3>
            <p className="mt-2 text-sm text-muted">
              <span className="font-medium text-ink">{confirmTarget.name}</span>
              <br />
              <span className="text-xs">{confirmTarget.bundleIdentifier}</span>
            </p>
            <p className="mt-2 text-sm text-red-400">
              刪除後無法復原，用這個 App ID 簽名的 App 之後也無法續簽。
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setConfirmTarget(null)}>
                取消
              </Button>
              <Button
                variant="primary"
                onClick={() => handleDelete(confirmTarget)}
                disabled={deletingId !== null}
              >
                確認刪除
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
