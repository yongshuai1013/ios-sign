# anisette WASM 自建記錄（2026-09-29）

目標：不依賴 `@lbr77/anisette-js` 的預編譯包，從公開源碼自行構建
Emscripten WASM，並在 sideimpactor 中驗證可用。

## 構建環境
- 工作目錄：`~/workspace/anisette-rebuild/`（**不進 git**，內含 Apple 私有二進制）
- Rust nightly 1.101.0 + `wasm32-unknown-emscripten` target
- Emscripten SDK 6.0.10（emsdk，`latest`）
- Unicorn：`lbr77/unicorn` 的 `tci-emscripten` 分支（commit `76da9c39`），
  用 `script/rebuild-unicorn.sh` 產出 4 個靜態庫（`unicorn/build/`）
- anisette-js：`lbr77/anisette-js`（當日 main），`bash script/build-glue.sh --release`
- 構建過程**無需修改** Rust 源碼（僅一個 Emscripten deprecation 警告）
- 環境坑：本機 `tar` 解包 emsdk 的 node tarball 時還原 uid 1000 屬主失敗
  （root 但無 chown 權限），用 `bin/tar` wrapper 加 `--no-same-owner` 繞過

## 產物
- `dist/anisette_rs.js`（web，3.8MB，SINGLE_FILE）
- `dist/anisette_rs.node.js`（node，3.8MB，SINGLE_FILE）
- 匯出函式與 lbr77 官方版本一致（`_malloc`/`_free`/`_anisette_*` 全套）

## 測試（`test-provisioning.mjs`，Node 24）
| 步驟 | 自建版 | lbr77 官方預編譯版（對照） |
|---|---|---|
| WASM 載入 | ✅ | ✅ |
| `init_from_blobs`（Apple Music APK 提取的 .so） | rc=0 ✅（mprotect/madvise stub 警告） | rc=0 ✅（警告序列逐字相同） |
| `is_machine_provisioned`（新裝置） | 0 ✅ | 0 ✅ |
| 真實 provisioning（Apple GSA） | ❌ 本機 egress 被 GSA 在 HTTP 層擋 | ❌ 同一步失敗（證非構建問題） |

結論：WASM 本體與官方版行為等價；provisioning 只需在能連 Apple 的
環境重跑 `test-provisioning.mjs`。

## 最終驗證（2026-09-29，真機）
自建 WASM 已接入 sideimpactor（`app/public/assets/anisette_rs.js`），
部署後真機測試：**Apple ID 登入成功**，完整鏈路
（WASM 載入 → provisioning → OTP → 登入）全過。

## 注意事項
- `.so` 來源：Apple Music Android APK（Apple 官方 CDN
  `apps.mzstatic.com`），側載圈公認做法；屬 Apple 私有二進制，
  **僅本地使用、不進 git、不散佈**。
- `lbr77/anisette-js` repo 無 LICENSE 文件、`package.json` 無 license 欄位；
  公開散佈衍生構建前需先處理授權問題。
- 構建時曾誤判 `/apple-proxy/` 回 404 為線上代理故障；後查證為誤報——
  代理路由正常，404 是 Apple 對裸 GET `/grandslam/GsService2/lookup`
  的回應（代理原樣轉發上游狀態碼）。特此更正。
