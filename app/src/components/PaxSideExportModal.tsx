import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { Button } from './ui/Button';
import { getStoredAccountSession, encodeAnisetteData } from '../lib/account-session';
import { getAnisetteData } from '../anisette-service';
import type { StoredAccountSummary } from '../lib/account-session';

interface PaxSideExportModalProps {
  account: StoredAccountSummary;
  onClose: () => void;
}

/**
 * Export the Apple session (dsid + authToken) as a QR code for the PaxSide app to scan.
 * The QR payload is a JSON: { v: 1, appleId, dsid, authToken }.
 * No password is included. The QR is displayed on the user's own screen for immediate scanning.
 */
export function PaxSideExportModal({ account, onClose }: PaxSideExportModalProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [qrText, setQrText] = useState<string>('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const run = async () => {
      const payload = getStoredAccountSession(account.appleId, account.teamId);
      if (!payload) {
        setError('No cached session for this account. Please re-login first.');
        return;
      }
      // 生成全新的 anisette（OTP 單次使用，登入時的不再有效）
      let anisetteData = payload.anisetteData;
      try {
        const fresh = await getAnisetteData();
        anisetteData = encodeAnisetteData(fresh);
      } catch (e) {
        // 用舊的繼續，PaxSide 會報錯提示
        console.warn('Fresh anisette failed, using cached:', e);
      }
      const qrData = JSON.stringify({
        v: 3,
        appleId: payload.appleId,
        dsid: payload.dsid,
        authToken: payload.authToken,
        anisette: anisetteData,
        teamId: payload.teamId,
        teamName: payload.teamName,
      });
      setQrText(qrData);
      if (canvasRef.current) {
        QRCode.toCanvas(canvasRef.current, qrData, { width: 280, margin: 2 }, (err) => {
          if (err) setError(`QR generation failed: ${err.message}`);
        });
      }
    };
    run();
  }, [account]);

  const copyText = async () => {
    try {
      await navigator.clipboard.writeText(qrText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError('Copy failed. Please select the text manually.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="w-full max-w-sm rounded-2xl bg-[var(--color-surface)] p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold text-ink">Export to PaxSide</h2>
        <p className="mt-1 text-[13px] text-muted">
          Scan this QR code with the PaxSide app to log in as {account.appleId}. The code contains your
          Apple session token (no password). Do not share it.
        </p>
        <div className="mt-4 flex justify-center">
          {error ? (
            <p className="text-[13px] text-[var(--color-danger)]">{error}</p>
          ) : (
            <canvas ref={canvasRef} className="rounded-lg bg-white p-2" />
          )}
        </div>
        {qrText && !error && (
          <div className="mt-4">
            <p className="mb-1 text-[12px] text-muted">或複製以下文字，在 PaxSide 選擇「貼上 Session 登入」：</p>
            <textarea
              readOnly
              value={qrText}
              rows={3}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] p-2 font-mono text-[11px] text-ink"
              onClick={(e) => (e.target as HTMLTextAreaElement).select()}
            />
            <Button size="sm" variant="ghost" onClick={copyText} className="mt-1">
              {copied ? '已複製 ✓' : '複製'}
            </Button>
          </div>
        )}
        <div className="mt-4 flex justify-end">
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}
