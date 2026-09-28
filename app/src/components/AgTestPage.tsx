import { useMemo, useState } from 'react';
import { Button } from './ui/Button';
import { getApi, toAltTeam, toSession } from '../apple-signing';
import { restorePersistedAccountContexts } from '../lib/account-session';
import { accountKey } from '../lib/ids';
import type { AppID } from 'altsign.js';

/**
 * Hidden test page (#/ag-test): verifies whether the 4100 from updateAppId was
 * caused by our request format (re-sending all features) rather than free-team
 * ineligibility. Sends ONLY APG3427HIY, mirroring isideload's ensure_group_feature.
 *
 * Flow: create throwaway App ID -> updateAppId (single flag) -> report ->
 * delete throwaway App ID. No App Group is created.
 */
export function AgTestPage() {
  const accounts = useMemo(() => [...restorePersistedAccountContexts().values()], []);
  const [selectedKey, setSelectedKey] = useState(() =>
    accounts.length > 0 ? accountKey(accounts[0].appleId, accounts[0].team.identifier) : '',
  );
  const [lines, setLines] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [verdict, setVerdict] = useState<string | null>(null);

  const addLine = (line: string) => setLines((prev) => [...prev, line]);

  async function runTest() {
    const ctx = accounts.find((a) => accountKey(a.appleId, a.team.identifier) === selectedKey);
    if (!ctx) return;
    setLines([]);
    setVerdict(null);
    setBusy(true);
    let appId: AppID | null = null;
    try {
      const api = getApi(addLine);
      const session = toSession(ctx);
      const team = toAltTeam(ctx);
      const bundleId = `com.sideimpactor.agtest${Date.now().toString(36)}`;

      addLine(`1/3 建立測試用 App ID: ${bundleId}`);
      appId = await api.addAppID(session, team, 'AGTest', bundleId);
      addLine(`    已建立，Apple 內部 ID: ${appId.identifier}`);

      addLine(`2/3 送出 updateAppId（只帶 APG3427HIY: true）…`);
      const res = await api.updateAppIdSingleFlag(session, team, appId);
      addLine(`    resultCode=${String(res.resultCode)}${res.userString ? ` (${res.userString})` : ''}`);
      const flagOn = res.appId?.features?.APG3427HIY === true;
      addLine(`    回傳的 App ID 上 APG3427HIY 生效: ${flagOn}`);

      const code = String(res.resultCode);
      if (code === '4100') {
        setVerdict('4100 重現：免費號確實開不了 App Groups 能力，假說不成立。');
      } else if ((code === '0' || res.resultCode === 0) && flagOn) {
        setVerdict('成功：當初的 4100 是請求寫法問題，不是免費號原罪，假說成立。');
      } else {
        setVerdict(`結果未定（resultCode=${code}），看上方 log。`);
      }
    } catch (e) {
      addLine(`錯誤: ${e instanceof Error ? e.message : String(e)}`);
      setVerdict('測試過程出錯，看上方 log。');
    } finally {
      if (appId) {
        try {
          addLine(`3/3 清理：刪除測試用 App ID…`);
          const del = await getApi(addLine).deleteAppId(toSession(ctx), toAltTeam(ctx), appId);
          addLine(`    刪除結果 resultCode=${String(del.resultCode)}${del.userString ? ` (${del.userString})` : ''}`);
        } catch (e) {
          addLine(`    刪除失敗: ${e instanceof Error ? e.message : String(e)}（請手動到 Apple Developer 網站刪除 ${appId.bundleIdentifier}）`);
        }
      }
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">App Group 4100 驗證</h2>
        <p className="mt-1 text-sm text-muted">
          驗證當初 updateAppId 回 4100 是請求寫法問題還是免費號真的沒資格。流程：建一個一次性測試 App
          ID，只送單個開關打 updateAppId，看結果，測完立刻刪除。不會建立 App Group。
        </p>
      </div>

      {accounts.length === 0 ? (
        <p className="text-sm text-muted">沒有已登入的帳號，請先到 Sign 頁登入 Apple ID。</p>
      ) : (
        <>
          <div>
            <label className="block text-sm font-medium">測試用帳號</label>
            <select
              className="mt-1 w-full rounded border border-border bg-bg px-3 py-2 text-sm"
              value={selectedKey}
              onChange={(e) => setSelectedKey(e.target.value)}
              disabled={busy}
            >
              {accounts.map((a) => {
                const key = accountKey(a.appleId, a.team.identifier);
                return (
                  <option key={key} value={key}>
                    {a.appleId}（{a.team.name}）
                  </option>
                );
              })}
            </select>
          </div>

          <div className="flex gap-3">
            <Button onClick={runTest} disabled={busy} busy={busy} busyLabel="測試中…">
              開始測試
            </Button>
          </div>
        </>
      )}

      {verdict && (
        <div className="rounded border border-border bg-surface px-4 py-3 text-sm font-medium">{verdict}</div>
      )}

      {lines.length > 0 && (
        <div className="rounded border border-border bg-surface px-4 py-3">
          <pre className="whitespace-pre-wrap text-xs leading-relaxed">{lines.join('\n')}</pre>
        </div>
      )}
    </div>
  );
}
