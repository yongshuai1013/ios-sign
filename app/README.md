# SideImpactor Web (app/)

純前端 SPA：Apple ID 登入 → IPA 簽名 → USB 配對 → 安裝。複刻自
[SideImpactor](https://github.com/lbr77/SideImpactor) 的核心流程，
並整合 [idevice_pair](https://github.com/jkcoxson/idevice_pair) 風格的
配對檔案功能。以 TypeScript + React 19 + Vite + Tailwind CSS 實作。

核心配對/傳輸協定位於 `../src/pairing/`（本 repo 的 TypeScript 實作），
前端透過 `@pairing` alias 引用。

## 路由（Hash）

| Hash | 頁面 |
|---|---|
| `#/login` | Apple ID 帳號管理、WISP 設定 |
| `#/pairing` | USB / Remote 配對、配對檔匯入匯出 |
| `#/sign` | IPA 簽名與安裝 |

## 安裝 / 開發 / 建置

```bash
cd app
bun install        # 或 npm install
bun run dev        # Vite dev server (http://localhost:5173)
bunx tsc --noEmit  # 型別檢查
bun run test       # vitest 單元測試
bun run build      # 生產建置 → dist/
```

> 需求：Node 18+ / Bun 1+。瀏覽器需支援 WebUSB（Chrome / Edge，
> HTTPS 或 localhost）。

## 架構

| 模組 | 說明 |
|---|---|
| `src/anisette-service.ts` | `@lbr77/anisette-js` WASM provisioning；`adi.pb` + `device.json` 快取於 localStorage |
| `src/apple-signing.ts` | `altsign.js`：SRP 登入、Team/Certificate/Device/App ID/Provisioning Profile、`signIPA` (zsign-WASM) |
| `src/lib/network.ts` | libcurl-WASM + WISP WebSocket 傳輸層，失敗時 fallback 原生 fetch |
| `src/lib/plist.ts` | 自寫 plist 解析器（XML + binary `bplist00`），讀 IPA 的 `Payload/*.app/Info.plist` |
| `src/lib/router.ts` | Hash 路由 helper |
| `src/lib/filenames.ts` | 下載檔名消毒 |
| `src/flows/` | login / sign / pair / install / remote-pair 流程 |
| `src/components/` | 頁面與 UI（LoginModal、TwoFactorModal、DropZone、IpaInfoCard、WispSettings…） |

## WISP

瀏覽器打不到 Apple API（CORS / 無 raw socket），所有 Apple 流量經
libcurl-WASM → WISP WebSocket proxy 轉發。預設：

```
wss://sideload.nvme0n1p.dev/wisp/
```

可在登入頁「Network proxy (WISP)」折疊區修改 URL 或停用（停用後改用
原生 fetch，通常會被 CORS 擋下）。設定存於 localStorage
(`webmuxd:wisp-*`)，下次登入時重新初始化傳輸層。也可以自架任何 WISP
實作。

## WebUSB

USB 配對與安裝走 WebUSB（`src/transport/webusb-mux.ts` + 根目錄
`src/pairing/` 協定模組）。配對成功後產生 `{UDID}.plist`（相容
idevice_pair / libimobiledevice），可匯出、下載、重新匯入；
Remote（Wi-Fi）配對走 SRP 產生 `pairingFile.plist`。

## Anisette

`public/assets/anisette_rs.wasm`（+ `public/assets/anisette_rs.js` glue）
與 `public/anisette/*.so` 由建置時放入 `public/` 提供。
首次啟動時向 Apple provisioning，結果（`adi.pb`、`device.json`）
base64 存於 localStorage，之後直接恢復；快取過期時自動清除並重新
provision。anisette 的 provisioning HTTP 同樣走 `lib/network.ts` 的傳輸層。

## 帳號

- 最多儲存 12 組帳號摘要（`persistAccountSummary` 會截斷）。
- 憑證私鑰以 `appleId::teamId` 為 key 快取於 localStorage；憑證達到
  Apple 上限（錯誤 7460）時自動撤銷最舊一張後重試。
- 簽名輸出檔名為 `<原名>-signed.ipa`，經檔名消毒。

## 安全限制（必讀）

- **憑證風險**：Apple ID / 密碼只在瀏覽器記憶體中使用，直接送往
  Apple。**請確認你信任部署此頁面的伺服器**——被入侵的伺服器可以攔截
  你的憑證（LoginModal 內有同樣的警告）。
- **localStorage**：Session（dsid / auth token）、anisette 快取、憑證私鑰
  目前暫存於 localStorage。正式環境應改為後端 Session + httpOnly cookie，
  不要把私鑰放在前端儲存。
- **2FA**：只支援受信任裝置推播的 6 位碼。altsign.js 沒有 SMS 電話列表 /
  SMS 驗證 API，簡訊備援會顯示明確的「不支援」錯誤而非靜默失敗。
- **安裝**：`src/flows/install.ts` 目前仍是誠實的 stub——需要
  lockdownd `StartSession` 後的 mTLS 升級（`WebUsbMuxClient.upgradeToTls()`）
  尚未實作。配對流程可用，安裝流程會明確報錯而非假裝成功。

## 測試

```bash
bun run test
```

- `src/lib/plist.test.ts`：XML + 手工構造的 binary plist 解析
- `src/lib/filenames.test.ts`：下載檔名消毒
- `src/lib/router.test.ts`：hash 路由解析 / 回寫
