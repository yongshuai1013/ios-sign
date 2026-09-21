/**
 * Apple ID login flow.
 *
 * Ensures anisette provisioning data exists (WASM + Apple provisioning,
 * cached in localStorage), then authenticates with the developer portal
 * via `loginAppleDeveloperAccount` (SRP + trusted-device 2FA bridged to
 * the UI) and refreshes the context.
 */
import type { AnisetteData } from '../anisette-service';
import type { AppleDeveloperContext, TwoFactorContext } from '../apple-signing';

export interface EnsureAnisetteResult {
  anisetteData: AnisetteData;
  provisioned: boolean;
}

export async function ensureAnisetteData(
  existing: AnisetteData | null,
  log: (msg: string) => void,
): Promise<EnsureAnisetteResult> {
  if (existing) {
    return { anisetteData: existing, provisioned: true };
  }
  const anisetteService = await import('../anisette-service');
  log('login: initializing anisette...');
  await anisetteService.initAnisette(log);
  const anisetteData = await anisetteService.getAnisetteData(log);
  return { anisetteData, provisioned: true };
}

export async function checkAnisetteProvisioned(): Promise<boolean> {
  const anisetteService = await import('../anisette-service');
  return anisetteService.checkAnisetteProvisioned();
}

export interface LoginRequest {
  appleId: string;
  password: string;
  anisetteData: AnisetteData;
  log: (msg: string) => void;
  onTwoFactorRequired: (ctx: TwoFactorContext) => void;
}

export async function loginAccount(req: LoginRequest): Promise<AppleDeveloperContext> {
  const appleSigning = await import('../apple-signing');
  req.log('login: authenticating Apple account...');
  const context = await appleSigning.loginAppleDeveloperAccount({
    anisetteData: req.anisetteData,
    credentials: { appleId: req.appleId, password: req.password },
    onLog: req.log,
    onTwoFactorRequired: req.onTwoFactorRequired,
  });
  return appleSigning.refreshAppleDeveloperContext(context, req.log);
}
