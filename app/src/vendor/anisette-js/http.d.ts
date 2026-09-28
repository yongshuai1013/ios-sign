export interface HttpClient {
    get(url: string, headers: Record<string, string>): Promise<Uint8Array>;
    post(url: string, body: string, headers: Record<string, string>): Promise<Uint8Array>;
}
export declare class FetchHttpClient implements HttpClient {
    get(url: string, headers: Record<string, string>): Promise<Uint8Array>;
    post(url: string, body: string, headers: Record<string, string>): Promise<Uint8Array>;
}
//# sourceMappingURL=http.d.ts.map