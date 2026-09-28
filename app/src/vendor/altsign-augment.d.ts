/**
 * Type augmentation for our vendored altsign.js (vite aliases 'altsign.js' to
 * src/vendor/altsign.js at build time). The npm package's own .d.ts doesn't
 * know about the App Group methods and test helpers we added.
 */
import type { AppGroup, AppID, AppleAPISession, Team } from 'altsign.js';

declare module 'altsign.js' {
  interface AppleAPI {
    addAppGroup(
      session: AppleAPISession,
      team: Team,
      name: string,
      groupIdentifier: string,
    ): Promise<AppGroup>;
    assignAppGroupToAppId(
      session: AppleAPISession,
      team: Team,
      appId: AppID,
      appGroup: AppGroup,
    ): Promise<void>;
    updateAppIdSingleFlag(
      session: AppleAPISession,
      team: Team,
      appId: AppID,
    ): Promise<{
      resultCode: unknown;
      userString: string | null;
      appId: AppID | null;
    }>;
    deleteAppId(
      session: AppleAPISession,
      team: Team,
      appId: AppID,
    ): Promise<{
      resultCode: unknown;
      userString: string | null;
    }>;
  }
}
