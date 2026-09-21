/**
 * IPA signing flow.
 *
 * Refreshes the stored developer context (teams / certificates / devices),
 * then signs via `signIpaWithAppleContext` (altsign.js + zsign-WASM).
 */
import type { AnisetteData } from '../anisette-service';
import type { AppleDeveloperContext } from '../apple-signing';

export interface SignIpaRequest {
  ipaFile: File;
  context: AppleDeveloperContext;
  anisetteData: AnisetteData;
  deviceUdid: string;
  deviceName?: string;
  log: (msg: string) => void;
}

export interface SignIpaResult {
  signedFile: File;
  context: AppleDeveloperContext;
}

export async function signIpaFlow(req: SignIpaRequest): Promise<SignIpaResult> {
  const appleSigning = await import('../apple-signing');

  const contextWithAnisette: AppleDeveloperContext = {
    ...req.context,
    session: {
      ...req.context.session,
      anisetteData: req.anisetteData,
    },
  };

  const refreshed = await appleSigning.refreshAppleDeveloperContext(contextWithAnisette, req.log);

  req.log('sign: preparing ipa...');
  const result = await appleSigning.signIpaWithAppleContext({
    ipaFile: req.ipaFile,
    context: refreshed,
    deviceUdid: req.deviceUdid,
    deviceName: req.deviceName,
    onLog: req.log,
  });
  req.log(`sign: done -> ${result.signedFile.name}`);

  return { signedFile: result.signedFile, context: refreshed };
}
