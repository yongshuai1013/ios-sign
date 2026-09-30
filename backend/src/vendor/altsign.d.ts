export class Fetch {
  static default(): Fetch;
  get(url: string, headers?: Record<string, string>): Promise<Response>;
  post(url: string, body: any, headers?: Record<string, string>): Promise<Response>;
}
export class AppleAuth {
  constructor(fetch: Fetch);
  authenticate(
    appleID: string,
    password: string,
    anisetteData: any,
    verificationHandler?: (submitCode: (code: string) => Promise<boolean>, info: any) => Promise<void>,
    options?: any
  ): Promise<{ account: any; session: { dsid: string; authToken: string; anisetteData: any } }>;
}
export function parsePlist(text: string): any;
export function bytesToBase64(bytes: Uint8Array): string;
export function base64ToBytes(b64: string): Uint8Array;
export class AppleAPI {
  constructor(fetch: Fetch);
}
