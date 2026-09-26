import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from './ui/Button';
import { Field } from './ui/Field';
import {
  FastbootClient,
  extractUnlockData,
  type FastbootCallbacks,
} from '../lib/fastboot';

const MOTOROLA_UNLOCK_URL = 'https://en-us.support.motorola.com/app/standalone/bootloader/unlock-your-device-b';

type Step = 1 | 2 | 3 | 4;

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function MotoUnlockPage() {
  const [step, setStep] = useState<Step>(1);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [unlockData, setUnlockData] = useState('');
  const [unlockCode, setUnlockCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const clientRef = useRef<FastbootClient | null>(null);
  const logRef = useRef<HTMLPreElement | null>(null);

  const addLog = useCallback((message: string) => {
    setLines((prev) => [...prev.slice(-199), message]);
  }, []);

  const getClient = useCallback((): FastbootClient => {
    if (!clientRef.current) {
      const callbacks: FastbootCallbacks = { log: addLog };
      clientRef.current = new FastbootClient(callbacks);
    }
    return clientRef.current;
  }, [addLog]);

  useEffect(() => {
    // Auto-scroll the log to the bottom on new lines.
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [lines]);

  useEffect(() => {
    return () => {
      // Best-effort cleanup when leaving the page.
      void clientRef.current?.close().catch(() => undefined);
    };
  }, []);

  const handleConnect = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      const client = getClient();
      await client.connect();
      // Connectivity check: probe a few getvar names. Motorola bootloaders
      // don't implement `getvar:version`, so any protocol-level answer
      // counts as connected.
      const { value, answered } = await client.probeConnectivity();
      if (value) {
        addLog(`fastboot: 連通性檢查通過（${value}）`);
      } else if (answered) {
        addLog('fastboot: 設備有回應但不支援版本查詢，視為已連接，繼續後續步驟');
      }
      setConnected(true);
      setStep(2);
    } catch (error) {
      addLog(`連接失敗：${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, getClient, addLog]);

  const handleGetUnlockData = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    setCopied(false);
    try {
      const client = getClient();
      const raw = await client.oem('get_unlock_data');
      const cleaned = extractUnlockData(raw.split('\n'));
      if (!cleaned) {
        addLog('讀取失敗：設備沒有回傳解鎖數據（可能是該機型不支援解鎖）');
        return;
      }
      setUnlockData(cleaned);
      addLog(`fastboot: 解鎖數據已讀取（${cleaned.length} 字元）`);
      setStep(3);
    } catch (error) {
      addLog(`讀取失敗：${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, getClient, addLog]);

  const handleCopy = useCallback(async () => {
    if (!unlockData) return;
    try {
      await navigator.clipboard.writeText(unlockData);
      setCopied(true);
      addLog('已複製解鎖數據到剪貼簿');
    } catch (error) {
      addLog(`複製失敗：${formatError(error)}，請手動選取複製`);
    }
  }, [unlockData, addLog]);

  const handleUnlock = useCallback(async () => {
    if (busy) return;
    const code = unlockCode.trim();
    if (!code) {
      addLog('請先輸入摩托羅拉郵件裡收到的解鎖碼');
      return;
    }
    if (!window.confirm(`確定要用這個解鎖碼解鎖嗎？\n${code}\n\n解鎖會清除手機上所有資料！`)) {
      return;
    }
    setBusy(true);
    try {
      const client = getClient();
      addLog('正在發送解鎖指令…請在手機螢幕上用音量鍵選擇 UNLOCK THE BOOTLOADER，電源鍵確認');
      await client.oemUnlock(code);
      addLog('fastboot: 解鎖指令已接受');
      setStep(4);
    } catch (error) {
      addLog(`解鎖失敗：${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, unlockCode, getClient, addLog]);

  const handleReboot = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      const client = getClient();
      await client.reboot();
      addLog('已發送重啟指令。開機時出現警告文字即表示解鎖完成（首次開機較慢）。');
    } catch (error) {
      addLog(`重啟失敗：${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, getClient, addLog]);

  const handleDisconnect = useCallback(() => {
    void getClient().close().catch(() => undefined);
    setConnected(false);
    setStep(1);
    addLog('fastboot: 已斷開連接');
  }, [getClient, addLog]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Moto Unlock</h2>
        <p className="mt-1 text-sm text-muted">
          用 WebUSB 對摩托羅拉手機發 fastboot 指令，完成 Bootloader 解鎖。
          需要另一台支援 WebUSB 的 Android 手機（Chrome）當主機，透過 OTG 連接已進入 fastboot 模式的摩托羅拉手機。
        </p>
      </div>

      {/* Step 1: connect */}
      <section className="rounded-xl border border-border p-4">
        <h3 className="text-sm font-semibold">
          <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-ink text-[11px] text-white">1</span>
          連接設備
        </h3>
        <p className="mt-2 text-sm text-muted">
          先在摩托羅拉手機上按住<span className="font-medium text-ink">音量下＋電源鍵</span>進入 fastboot 模式（螢幕顯示 fastboot 字樣），
          再用 OTG 線接到這台手機，然後點連接。
        </p>
        <div className="mt-3 flex gap-3">
          {!connected ? (
            <Button variant="primary" onClick={handleConnect} busy={busy} busyLabel="連接中…">
              連接設備
            </Button>
          ) : (
            <Button variant="ghost" onClick={handleDisconnect}>
              斷開連接
            </Button>
          )}
        </div>
        {connected && (
          <p className="mt-2 text-sm text-muted">已連接{step > 1 ? '，連通性檢查通過' : ''}。</p>
        )}
      </section>

      {/* Step 2: get unlock data */}
      <section className={`rounded-xl border border-border p-4 ${step < 2 ? 'opacity-50' : ''}`}>
        <h3 className="text-sm font-semibold">
          <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-ink text-[11px] text-white">2</span>
          讀取解鎖數據
        </h3>
        <div className="mt-3">
          <Button onClick={handleGetUnlockData} disabled={step < 2} busy={busy} busyLabel="讀取中…">
            讀取解鎖數據
          </Button>
        </div>
        {unlockData && (
          <div className="mt-3 space-y-2">
            <pre className="max-h-32 overflow-y-auto rounded-lg border border-border bg-muted/40 p-3 text-xs leading-relaxed break-all whitespace-pre-wrap">
              {unlockData}
            </pre>
            <div className="flex gap-3">
              <Button variant="primary" size="sm" onClick={handleCopy}>
                {copied ? '已複製' : '一鍵複製'}
              </Button>
              <a
                className="btn btn-sm btn-ghost no-underline"
                href={MOTOROLA_UNLOCK_URL}
                target="_blank"
                rel="noreferrer"
              >
                前往摩托羅拉官網申請
              </a>
            </div>
            <p className="text-sm text-muted">
              把上面複製的解鎖數據貼到摩托羅拉官網（需登入摩托羅拉帳號），查詢可解鎖性並同意協議，
              解鎖碼會寄到你的郵箱。拿到解鎖碼後繼續下一步。
            </p>
          </div>
        )}
      </section>

      {/* Step 3: unlock */}
      <section className={`rounded-xl border border-border p-4 ${step < 3 ? 'opacity-50' : ''}`}>
        <h3 className="text-sm font-semibold">
          <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-ink text-[11px] text-white">3</span>
          輸入解鎖碼並解鎖
        </h3>
        <p className="mt-2 text-sm text-muted">
          解鎖會清除手機上所有資料，請先備份。發送指令後，在手機螢幕上用音量鍵選擇
          <span className="font-medium text-ink"> UNLOCK THE BOOTLOADER </span>，電源鍵確認。
        </p>
        <div className="mt-3">
          <Field
            label="解鎖碼（來自摩托羅拉郵件）"
            value={unlockCode}
            disabled={step < 3}
            onChange={(e) => setUnlockCode(e.target.value)}
            placeholder="例如：XXXXXXXXXXXXXXX"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="mt-3">
          <Button variant="primary" onClick={handleUnlock} disabled={step < 3} busy={busy} busyLabel="解鎖中…">
            發送解鎖指令
          </Button>
        </div>
      </section>

      {/* Step 4: reboot */}
      <section className={`rounded-xl border border-border p-4 ${step < 4 ? 'opacity-50' : ''}`}>
        <h3 className="text-sm font-semibold">
          <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-ink text-[11px] text-white">4</span>
          重啟手機
        </h3>
        <div className="mt-3">
          <Button onClick={handleReboot} disabled={step < 4} busy={busy} busyLabel="重啟中…">
            重啟
          </Button>
        </div>
      </section>

      {/* Log */}
      {lines.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold">Log</h3>
          <pre
            ref={logRef}
            className="max-h-64 overflow-y-auto rounded-lg border border-border bg-muted/40 p-3 text-xs leading-relaxed"
          >
            {lines.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}
