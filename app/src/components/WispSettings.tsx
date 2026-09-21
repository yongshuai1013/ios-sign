import { useState } from 'react';
import { Button } from './ui/Button';
import { Field } from './ui/Field';
import { resetAnisetteCache } from '../anisette-service';
import {
  defaultWispUrl,
  getWispUrl,
  isWispEnabled,
  setWispEnabled,
  setWispUrl,
} from '../lib/network';

/**
 * WISP proxy settings. Browsers cannot reach Apple endpoints directly
 * (CORS), so Apple API traffic is tunneled through libcurl-WASM over a
 * WISP WebSocket proxy. The proxy URL is configurable here.
 */
export function WispSettings() {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState(getWispUrl);
  const [enabled, setEnabled] = useState(isWispEnabled);
  const [saved, setSaved] = useState(false);
  const [anisetteReset, setAnisetteReset] = useState(false);

  const handleSave = () => {
    setWispUrl(url.trim() || defaultWispUrl());
    setWispEnabled(enabled);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    setUrl(defaultWispUrl());
    setWispUrl(defaultWispUrl());
    setEnabled(true);
    setWispEnabled(true);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="rounded-2xl border border-border bg-elevated">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-5 py-4 text-left"
      >
        <div>
          <p className="text-[14px] font-semibold text-ink">Network proxy (WISP)</p>
          <p className="mt-0.5 text-[12px] text-muted">
            {enabled ? `Tunneling Apple API traffic via ${getWispUrl()}` : 'Direct fetch (WISP disabled)'}
          </p>
        </div>
        <span className="text-muted">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-border px-5 py-4">
          <label className="flex items-center gap-3 text-[13px] text-ink">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 accent-[#2563eb]"
            />
            Route Apple API traffic through WISP (recommended)
          </label>
          <Field
            label="WISP WebSocket URL"
            placeholder={defaultWispUrl()}
            value={url}
            disabled={!enabled}
            onChange={(e) => setUrl(e.target.value)}
          />
          <p className="text-[11.5px] leading-relaxed text-muted">
            The browser cannot open raw TLS sockets to Apple, so requests are proxied through a
            WISP server over WebSocket. Self-host one (any WISP implementation) or keep the
            default. Changing the URL re-initializes the libcurl transport on next login.
          </p>
          <div className="flex items-center gap-3">
            <Button variant="primary" onClick={handleSave}>
              Save
            </Button>
            <Button variant="ghost" onClick={handleReset}>
              Reset to default
            </Button>
            {saved && <span className="text-[12px] text-success">Saved</span>}
          </div>
          <div className="border-t border-border pt-4">
            <p className="text-[13px] font-medium text-ink">Anisette device identity</p>
            <p className="mt-1 text-[11.5px] leading-relaxed text-muted">
              If login keeps failing, the cached device identity may be stale. Resetting forces a
              fresh provisioning with Apple on the next login.
            </p>
            <div className="mt-2 flex items-center gap-3">
              <Button
                variant="ghost"
                onClick={() => {
                  resetAnisetteCache();
                  setAnisetteReset(true);
                  window.setTimeout(() => setAnisetteReset(false), 2000);
                }}
              >
                Reset anisette
              </Button>
              {anisetteReset && <span className="text-[12px] text-success">Reset</span>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
