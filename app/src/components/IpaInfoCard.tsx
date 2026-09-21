import { useEffect, useState } from 'react';
import { unzipSync } from 'fflate';
import { parsePlist, plistString, type PlistValue } from '../lib/plist';

export interface IpaInfo {
  bundleId: string;
  bundleName: string;
  bundleVersion: string;
  appDirName: string;
}

/** Reads `Payload/*.app/Info.plist` out of an IPA (XML or binary plist). */
export async function readIpaInfo(file: File): Promise<IpaInfo> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(bytes);
  } catch {
    throw new Error('not a valid zip archive (.ipa)');
  }
  const names = Object.keys(entries);
  const appDir = names.find((n) => /^Payload\/[^/]+\.app\/$/.test(n));
  const infoName = names.find((n) => /^Payload\/[^/]+\.app\/Info\.plist$/i.test(n));
  if (!infoName) {
    throw new Error('IPA has no Payload/*.app/Info.plist');
  }
  const info = parsePlist(entries[infoName]) as { [key: string]: PlistValue };
  const bundleId = plistString(info, 'CFBundleIdentifier');
  if (!bundleId) throw new Error('Info.plist has no CFBundleIdentifier');
  return {
    bundleId,
    bundleName:
      plistString(info, 'CFBundleDisplayName') ?? plistString(info, 'CFBundleName') ?? bundleId,
    bundleVersion: plistString(info, 'CFBundleShortVersionString') ?? '1.0',
    appDirName: appDir ?? 'Payload/*.app',
  };
}

/** Shows bundle metadata of the currently selected IPA. */
export function IpaInfoCard({ file }: { file: File }) {
  const [info, setInfo] = useState<IpaInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setInfo(null);
    setError(null);
    void readIpaInfo(file)
      .then((parsed) => {
        if (!cancelled) setInfo(parsed);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [file]);

  if (error) {
    return (
      <p className="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-[12.5px] text-danger">
        Could not read IPA info: {error}
      </p>
    );
  }

  if (!info) {
    return <p className="text-[12.5px] text-muted">Reading app info…</p>;
  }

  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 rounded-xl border border-border bg-elevated px-4 py-3 text-[13px]">
      <dt className="text-muted">App</dt>
      <dd className="truncate font-medium text-ink">{info.bundleName}</dd>
      <dt className="text-muted">Bundle ID</dt>
      <dd className="truncate font-mono text-[12px] text-ink">{info.bundleId}</dd>
      <dt className="text-muted">Version</dt>
      <dd className="text-ink">{info.bundleVersion}</dd>
    </dl>
  );
}
