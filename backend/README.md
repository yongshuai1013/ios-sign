# sideimpactor-backend（Cloudflare Worker WISP 代理）

前端的 libcurl WASM 無法直接對 Apple 伺服器發起 TLS 連線，因此所有
Apple API 流量都經由此 Worker 上的 **WISP v1**（WebSocket 承載的 TCP 隧道）
代理出去。原始碼複刻自 SideImpactor 的 `backend/src/index.ts`。

## 端點

| 路由 | 說明 |
| --- | --- |
| `GET /healthz` | 健康檢查，回傳 `ok` |
| `GET /` | 服務資訊 JSON（`service: "sideimpactor-backend"`） |
| `WS /wisp/` | WISP v1 會話。需要 WebSocket 升級；非 `/wisp/` 的 `/wisp*` 路徑回 404 |
| 其他 | 由 `ASSETS` 提供前端靜態檔（SPA fallback） |

## 安全策略（`src/wisp-policy.ts`）

- **Apple 主機 allowlist**（僅 443/tcp）：
  - `auth.itunes.apple.com`
  - `buy.itunes.apple.com`
  - `init.itunes.apple.com`
  - `p<數字>-buy.itunes.apple.com`
  - `gsa.apple.com`
  - `developerservices2.apple.com`
- UDP 禁用、只允許 TCP/443。
- 拒絕直接 IP 連線（`allow_direct_ip` / `allow_private_ips` / `allow_loopback_ips` 皆關閉），防 SSRF。
- 這些規則以純函式寫在 `wisp-policy.ts`，有完整單元測試；同時也設定在
  `wisp.options` 上，由 wisp-js 在每次開流時強制執行（雙保險）。

## 可選存取權杖

設定其中一個 Worker secret 即可要求 `?token=` 驗證：

```bash
cd backend
bunx wrangler secret put ACCESS_TOKEN_HASH    # 推薦：token 的 SHA-256 hex
# 或
bunx wrangler secret put ACCESS_PASSWORD      # 明文密碼，Worker 計算 SHA-256 後比對
```

兩者都未設定時 `/wisp/` 為公開端點（與原始碼行為一致）。

比對使用常數時間比較（`timingSafeEqual`），避免時序側信道。

## 前端對接

前端 `app/src/anisette-libcurl-init.ts` 的 `initLibcurl()` 會：

```ts
const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
const wsUrl = `${wsProto}//${location.host}/wisp/`;
loadedLibcurl.set_websocket(wsUrl);
await loadedLibcurl.load_wasm();
```

因為 Worker 同時用 `assets` 提供前端靜態檔（`wrangler.jsonc` 的 `assets.directory`
指向 `../app/dist`），前端與 `/wisp/` 同源，瀏覽器頁面載入後直接連上
`wss://<worker-host>/wisp/`。

若 Worker 有設定存取權杖，前端需要把 token 附加到 URL：

```ts
const wsUrl = `${wsProto}//${location.host}/wisp/?token=${encodeURIComponent(token)}`;
```

## 開發與部署

```bash
cd backend
bun install
bun test            # 單元測試（wisp-policy）
bun run build       # tsc --noEmit 型別檢查
bun run dev         # wrangler dev，預設 http://127.0.0.1:8787
bun run deploy      # wrangler deploy
```

## 實作說明

- WISP 協定處理來自 `@mercuryworkshop/wisp-js` 的 `ServerConnection`。
- 出站 TCP 使用 `cloudflare:sockets` 的 `connect()`（`secureTransport: "off"`：
  TLS 由 WISP 客戶端自行與 Apple 端點協商，Worker 只做 TCP 轉發）。
- `CfTcpSocket` 把 socket 的 `ReadableStream` 泵入一個單消費者 async queue，
  供 wisp-js 的 `recv()` 使用；`WsAdapter` 把 Cloudflare 伺服端 WebSocket
  轉成 wisp-js 期望的 ws 介面（property handler + `OPEN`/`readyState`）。

## 已知限制（誠實標註）

- UDP 流被禁用（與原始碼一致）。
- 不支援舊式 wsproxy 路徑（例如 `/wisp/example.com:443`），只接受 `/wisp/`。
- 不包含 Asspp 後端的 `/api/*` HTTP API。
- `ping_interval: 30`（秒）與原始碼相同。
