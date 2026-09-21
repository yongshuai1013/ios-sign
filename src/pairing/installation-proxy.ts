/**
 * installation_proxy client — TypeScript port of the Rust `idevice` crate's
 * `services/installation_proxy.rs` (install flow).
 *
 * Wire format (mirrors `Idevice::send_plist` / `read_plist`, same as lockdown.ts):
 *   u32 big-endian length + XML plist body.
 *
 * The constructor takes an already-connected {@link ByteTransport} — the caller
 * is responsible for running lockdownd `StartService("com.apple.mobile.installation_proxy")`
 * first and handing over the new connection's transport.
 */

import plist from 'plist';
import { AfcClient } from './afc.js';

/** Byte-oriented transport, mirroring the shape defined in usbmuxd.ts. */
export interface ByteTransport {
  write(data: Uint8Array): Promise<void>;
  readExact(n: number): Promise<Uint8Array>;
  close(): void;
}

/** Per-message timeout while waiting for installation_proxy replies. */
export const INSTALL_MESSAGE_TIMEOUT_MS = 120_000;

/** Upper bound on installation_proxy reply messages per operation. */
export const MAX_INSTALL_MESSAGES = 4096;

/** Error raised when installation_proxy reports a failure. */
export class InstallationProxyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InstallationProxyError';
  }
}

/**
 * One installation progress event from the device.
 *
 * Mirrors the plist fields of each installation_proxy status reply:
 * `Status` (e.g. `"CreatingStagingDirectory"`, `"Complete"`), the optional
 * `PercentComplete` number, and the optional `Error` / `ErrorDescription`
 * failure details. A reply carrying an `Error` never yields an event — the
 * generator throws {@link InstallationProxyError} instead.
 */
export interface InstallProgressEvent {
  status: string;
  percentComplete?: number;
  error?: string;
  errorDescription?: string;
}

/**
 * Options sent as `ClientOptions` with the `Install` command.
 *
 * Defaults to `{ PackageType: 'Developer' }` (the SideImpactor/webmuxd
 * behaviour). Pass `ApplicationType` when the caller wants to scope the
 * installation (e.g. `"Any"` / `"User"`), mirroring the Lookup command.
 */
export interface InstallOptions {
  PackageType?: string;
  ApplicationType?: string;
}

/**
 * Client for the `com.apple.mobile.installation_proxy` service.
 *
 * Mirrors the Rust `InstallationProxyClient::install_with_callback`: sends the
 * Install command, then loops over plist replies until `Status == "Complete"`.
 */
export class InstallationProxyClient {
  constructor(private readonly transport: ByteTransport) {}

  private async sendPlist(message: plist.PlistObject): Promise<void> {
    const body = new TextEncoder().encode(plist.build(message));
    const frame = new Uint8Array(4 + body.length);
    new DataView(frame.buffer).setUint32(0, body.length, false);
    frame.set(body, 4);
    await this.transport.write(frame);
  }

  private async readPlist(): Promise<Record<string, unknown>> {
    const header = await this.transport.readExact(4);
    const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(
      0,
      false,
    );
    const body = await this.transport.readExact(length);
    return plist.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
  }

  private async readPlistWithTimeout(timeoutMs: number): Promise<Record<string, unknown>> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        this.readPlist(),
        new Promise<Record<string, unknown>>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`installation_proxy: no reply within ${timeoutMs}ms`)),
            timeoutMs,
          );
        }),
      ]);
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }
  }

  /**
   * Installs an application package already staged in the AFC jail,
   * yielding one {@link InstallProgressEvent} per status reply.
   *
   * @param packagePath path to the .ipa inside the AFC jail, relative to the
   *   jail root (e.g. `PublicStaging/app.ipa` — a leading slash is stripped).
   * @param options installation `ClientOptions`; `PackageType` defaults to
   *   `"Developer"`.
   *
   * The generator ends after yielding the `Status == "Complete"` event, and
   * throws {@link InstallationProxyError} when the device reports `Error`.
   */
  async *installEvents(
    packagePath: string,
    options: InstallOptions = {},
  ): AsyncGenerator<InstallProgressEvent> {
    const normalized = packagePath.trim().replace(/^\/+/, '');
    if (normalized.length === 0) {
      throw new InstallationProxyError('installation_proxy: package path is empty');
    }
    await this.sendPlist({
      Command: 'Install',
      PackagePath: normalized,
      ClientOptions: { PackageType: 'Developer', ...options },
    });

    for (let i = 0; i < MAX_INSTALL_MESSAGES; i++) {
      const res = await this.readPlistWithTimeout(INSTALL_MESSAGE_TIMEOUT_MS);

      const status = typeof res['Status'] === 'string' ? res['Status'] : '';
      const percentComplete =
        typeof res['PercentComplete'] === 'number' ? res['PercentComplete'] : undefined;
      const error =
        res['Error'] !== undefined && res['Error'] !== null ? String(res['Error']) : undefined;
      const errorDescription =
        res['ErrorDescription'] !== undefined && res['ErrorDescription'] !== null
          ? String(res['ErrorDescription'])
          : undefined;

      if (error) {
        throw new InstallationProxyError(
          `installation_proxy: ${error}${errorDescription ? ` (${errorDescription})` : ''}`,
        );
      }

      yield { status, percentComplete, error, errorDescription };

      if (status === 'Complete') {
        return;
      }
    }
    throw new InstallationProxyError(
      `installation_proxy: exceeded ${MAX_INSTALL_MESSAGES} reply messages`,
    );
  }

  /**
   * Installs an application package already staged in the AFC jail.
   *
   * @param packagePath path to the .ipa inside the AFC jail, relative to the
   *   jail root (e.g. `PublicStaging/app.ipa` — no leading slash).
   * @param onProgress called for each status reply with the `Status` string
   *   and the optional `PercentComplete` number.
   * @param options installation `ClientOptions` passed through to the device.
   */
  async install(
    packagePath: string,
    onProgress?: (status: string, percentComplete?: number) => void,
    options: InstallOptions = {},
  ): Promise<void> {
    for await (const event of this.installEvents(packagePath, options)) {
      onProgress?.(event.status, event.percentComplete);
    }
  }
}

/**
 * Sanitizes an IPA file name for the device staging directory.
 *
 * Exact port of SideImpactor's `sanitizeIpaFileName` (webmuxd): trims the
 * name, falls back to `webmuxd-upload.ipa` when empty, replaces every run of
 * characters outside `[\\w.\\-]` with `_`, and appends `.ipa` unless the name
 * already ends with it (case-insensitive).
 */
export function sanitizeIpaFileName(fileName: string): string {
  const trimmed = fileName.trim();
  const fallback = 'webmuxd-upload.ipa';
  const base = trimmed.length > 0 ? trimmed : fallback;
  const safe = base.replace(/[^\w.\-]+/g, '_');
  return safe.toLowerCase().endsWith('.ipa') ? safe : `${safe}.ipa`;
}

/**
 * Full IPA install pipeline, mirroring SideImpactor's `installIpaViaInstProxy`:
 * stages the IPA into `/PublicStaging` over AFC, then installs it via
 * installation_proxy.
 *
 * @param afc client for the already-connected `com.apple.afc` service.
 * @param instProxy client for the already-connected
 *   `com.apple.mobile.installation_proxy` service.
 * @param ipaData signed IPA bytes.
 * @param fileName original file name; sanitized with {@link sanitizeIpaFileName}.
 * @param onLog optional log sink.
 */
export async function installIpa(
  afc: AfcClient,
  instProxy: InstallationProxyClient,
  ipaData: Uint8Array,
  fileName: string,
  onLog?: (msg: string) => void,
): Promise<void> {
  const safeName = sanitizeIpaFileName(fileName);
  const stagingDir = '/PublicStaging';
  const devicePath = `${stagingDir}/${safeName}`;
  // NB: PackagePath is relative to the AFC jail root — no leading slash.
  const packagePath = `PublicStaging/${safeName}`;

  onLog?.(`install: staging ${safeName} (${ipaData.byteLength} bytes)...`);
  await afc.makeDirectory(stagingDir);
  await afc.uploadFile(devicePath, ipaData, (sent, total) => {
    onLog?.(`install: uploaded ${sent}/${total} bytes`);
  });
  onLog?.(`install: staged IPA at ${devicePath}.`);

  await instProxy.install(packagePath, (status, percentComplete) => {
    const percentText = percentComplete !== undefined ? `, ${percentComplete}%` : '';
    onLog?.(`install: ${status}${percentText}`);
  });
  onLog?.('install: complete.');
}
