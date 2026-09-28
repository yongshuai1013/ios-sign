// HTTP client abstraction — allows swapping fetch vs Node.js http in tests
export class FetchHttpClient {
    async get(url, headers) {
        const response = await fetch(url, { method: "GET", headers });
        if (!response.ok) {
            throw new Error(`HTTP GET ${url} failed: ${response.status} ${response.statusText}`);
        }
        return new Uint8Array(await response.arrayBuffer());
    }
    async post(url, body, headers) {
        const response = await fetch(url, { method: "POST", body, headers });
        if (!response.ok) {
            throw new Error(`HTTP POST ${url} failed: ${response.status} ${response.statusText}`);
        }
        return new Uint8Array(await response.arrayBuffer());
    }
}
//# sourceMappingURL=http.js.map