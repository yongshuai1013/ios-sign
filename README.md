# SideImpactor

SideImpactor（https://github.com/lbr77/SideImpactor）的 TypeScript 完整實作，
整合 idevice_pair（https://github.com/jkcoxson/idevice_pair）的配對檔案功能。
原本是 React/Vite 前端，本專案保持相同語言與架構。

## 目錄結構

| 路徑 | 內容 |
|---|---|
| `src/pairing/` | 配對協定核心：TLV8、OPACK、SRP-3072、X.509 CA、usbmuxd/lockdownd、AFC、installation_proxy、WebUSB MUX、Remote Pairing |
| `src/pairing/index.ts` | 上述模組的統一匯出入口 |
| `test/` | 核心模組單元測試（`bun test`） |
| `app/` | Vite + React 19 前端：登入（`#/login`）、簽名（`#/sign`）、配對（`#/pairing`） |
| `backend/` | Cloudflare Worker：WISP v1 代理（讓瀏覽器經 WebSocket 連到區網內的 iOS 裝置） |

## 執行方式

```bash
# 核心庫：型別檢查 + 測試
cd ~/workspace/sideimpactor
bun install
bun run build      # tsc --noEmit
bun test

# 前端
cd app
bun install
bun run build      # tsc + vite build -> dist/
bun run dev        # 開發伺服器

# WISP 後端（部署到 Cloudflare Workers）
cd backend
bun install
bun run build
npx wrangler deploy
```

Remote 配對需要先部署後端，並在前端 `.env` 設定 `VITE_WISP_URL`。

## 配對檔案格式

### Lockdown 配對檔（USB，`{UDID}.plist`）
XML plist，與 libimobiledevice / idevice_pair 相容。主要欄位：
`DeviceCertificate`、`HostCertificate`、`HostPrivateKey`、`RootCertificate`、
`RootPrivateKey`、`SystemBUID`、`HostID`、可選 `EscrowBag`。相關程式碼：
`src/pairing/pairing-file.ts` 的 `PairingFile`、`parseLockdownPairRecord`。

### Remote 配對檔（`pairingFile.plist`）
XML plist，主要欄位：`public_key`、`private_key`（Ed25519）、`identifier`、
可選 `alt_irk`。相關程式碼：`src/pairing/pairing-file.ts` 的 `RpPairingFile`。

## 安全注意事項

- **私鑰明文儲存**：配對檔（HostPrivateKey、Remote 配對檔的 private_key）、
  Apple 登入 session、簽名憑證私鑰目前以 base64 存放在瀏覽器 localStorage。
  任何能讀到瀏覽器資料的人都能拿到這些私鑰，請勿在共用電腦使用。
- **WISP 代理**：`backend/` 未設定 `ACCESS_TOKEN_HASH` / `ACCESS_PASSWORD` 時，
  任何人都可以用你的 Worker 連到任意 Apple 主機（預設僅允許 443/TCP），
  部署時請務必設定存取密碼。

## 已知缺口

以下功能會丟出明確錯誤，不會假裝成功：

- **TLS 升級已實作但未經真機驗證**：`upgradeToTls()` 現在使用
  專案自帶的純 TypeScript TLS 1.2（ECDHE-RSA-AES-CBC-SHA，mTLS，SNI
  `lockdownd`）完成 `StartSession` 後的加密，AFC 上傳與
  installation_proxy 安裝路徑已接線（`installFlow`）。
  但整條「配對 → StartSession → TLS → 安裝」路徑**未用真實 iPhone
  做端到端驗證**。
- **SMS 2FA**：altsign.js 只支援信任裝置流程，SMS 會明確報錯。
- 無真機 / 無真實 Apple ID 憑證：Apple 登入、2FA、配對、IPA 簽名安裝
  僅通過型別檢查、API 簽名核對與單元測試，**未做端到端真實驗證**。
