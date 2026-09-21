import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { WebUsbMuxClient } from './transport/webusb-mux';
import type { AnisetteData } from './anisette-service';
import type { AppleDeveloperContext, TwoFactorContext } from './apple-signing';

import { Header, type AppPage } from './components/Header';
import { LoginPage } from './components/LoginPage';
import { LoginModal } from './components/LoginModal';
import { SignPage } from './components/SignPage';
import { PairingPage } from './components/PairingPage';
import { TrustModal, type TrustModalState } from './components/TrustModal';
import { TwoFactorModal } from './components/TwoFactorModal';
import { ProgressCard } from './components/ProgressCard';

import { ensureClientSelected, isPairingDialogPendingError, pairDeviceFlow, type PairedDeviceInfo } from './flows/pair';
import { checkAnisetteProvisioned, ensureAnisetteData, loginAccount } from './flows/login';
import { signIpaFlow } from './flows/sign';
import { installFlow } from './flows/install';

import {
  APPLE_ACCOUNT_LIST_STORAGE_KEY,
  APPLE_ACCOUNT_SUMMARY_STORAGE_KEY,
  APPLE_ID_STORAGE_KEY,
  SELECTED_DEVICE_UDID_STORAGE_KEY,
  loadText,
  saveText,
  writeJson,
} from './lib/storage';
import { accountKey, buildPreparedSourceKey, formatError } from './lib/ids';
import { listKnownDeviceUdids } from './lib/pair-record';
import {
  loadStoredAccountList,
  loadStoredAccountSummary,
  persistAccountSession,
  persistAccountSummary,
  removeStoredAccountSession,
  restorePersistedAccountContexts,
  setStoredAccountSummary,
  type StoredAccountSummary,
} from './lib/account-session';
import {
  isKnownPageHash,
  pageToHash,
  resolvePageFromHash,
  LOGIN_PAGE_HASH,
  SIGN_PAGE_HASH,
  PAIRING_PAGE_HASH,
} from './lib/router';
import { parseProgressFromLog } from './lib/log-parser';
import { useLog } from './lib/use-log';

const TRUST_MODAL_CLOSED: TrustModalState = 'closed';

type BusyState = {
  pair: boolean;
  loginSign: boolean;
  sign: boolean;
  install: boolean;
};

type PairFlowResult =
  | { kind: 'paired'; info: PairedDeviceInfo }
  | { kind: 'pending' }
  | { kind: 'failed' };

const idleBusy: BusyState = { pair: false, loginSign: false, sign: false, install: false };

export function App() {
  const { lines: logLines, addLog: rawAddLog } = useLog();

  // Form (for login modal)
  const [appleId, setAppleId] = useState<string>(() => loadText(APPLE_ID_STORAGE_KEY) ?? '');
  const [password, setPassword] = useState<string>('');

  // Navigation
  const [currentPage, setCurrentPage] = useState<AppPage>(() => resolvePageFromHash(window.location.hash));

  // Auth / session
  const [loginContext, setLoginContext] = useState<AppleDeveloperContext | null>(null);
  const [savedAccounts, setSavedAccounts] = useState<StoredAccountSummary[]>(() => loadStoredAccountList());
  const accountContextMapRef = useRef<Map<string, AppleDeveloperContext>>(new Map());
  const [accountCacheVersion, setAccountCacheVersion] = useState(0);

  // Login modal
  const [loginModalOpen, setLoginModalOpen] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  // Device
  const [pairedDeviceInfo, setPairedDeviceInfo] = useState<PairedDeviceInfo | null>(null);
  const [selectedTargetUdid, setSelectedTargetUdid] = useState<string>(
    () => loadText(SELECTED_DEVICE_UDID_STORAGE_KEY) ?? '',
  );
  const [pairRecordsVersion, setPairRecordsVersion] = useState<number>(0);
  const directClientRef = useRef<WebUsbMuxClient | null>(null);

  // File + signing
  const [selectedIpaFile, setSelectedIpaFile] = useState<File | null>(null);
  const [prepared, setPrepared] = useState<{ file: File; sourceKey: string } | null>(null);

  // Anisette
  const [anisetteData, setAnisetteData] = useState<AnisetteData | null>(null);
  const [anisetteProvisioned, setAnisetteProvisioned] = useState<boolean>(false);

  // Busy + progress
  const [busy, setBusy] = useState<BusyState>(idleBusy);
  const busyRef = useRef<BusyState>(idleBusy);
  busyRef.current = busy;
  const [progress, setProgress] = useState<{ percent: number; status: string }>({
    percent: 0,
    status: 'idle',
  });
  const lastInstallPercentRef = useRef<number>(0);

  // Modals
  const [trustState, setTrustState] = useState<TrustModalState>(TRUST_MODAL_CLOSED);
  const [twoFactor, setTwoFactor] = useState<{
    open: boolean;
    ctx: TwoFactorContext | null;
    error: string | null;
  }>({ open: false, ctx: null, error: null });
  const twoFactorCancelledRef = useRef(false);

  // ---- derived ----
  const isWebUsbSupported = useMemo(() => {
    try {
      return typeof navigator !== 'undefined' && 'usb' in navigator;
    } catch {
      return false;
    }
  }, []);

  const knownUdids = useMemo(
    () => listKnownDeviceUdids(pairedDeviceInfo?.udid ?? null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pairRecordsVersion, pairedDeviceInfo],
  );

  void anisetteProvisioned;

  const activeAccountKey = loginContext ? accountKey(loginContext.appleId, loginContext.team.identifier) : null;
  const cachedAccountKeys = useMemo(() => new Set(accountContextMapRef.current.keys()), [accountCacheVersion]);
  const trustOpen = trustState !== TRUST_MODAL_CLOSED;

  // ---- log + progress plumbing ----
  const addLog = useCallback(
    (message: string) => {
      rawAddLog(message);
      const update = parseProgressFromLog(message, lastInstallPercentRef.current);
      if (!update) return;

      if (update.source === 'install') {
        lastInstallPercentRef.current = update.percent;
      }

      if (busyRef.current.sign && update.source === 'sign') {
        setProgress({ percent: update.percent, status: `signing: ${update.status}` });
      } else if (busyRef.current.install && update.source === 'install') {
        setProgress({ percent: update.percent, status: `installing: ${update.status}` });
      }
    },
    [rawAddLog],
  );

  // ---- navigation ----
  const navigateToPage = useCallback((page: AppPage) => {
    setCurrentPage(page);
    const nextHash = pageToHash(page);
    if (window.location.hash !== nextHash) {
      window.location.hash = nextHash;
    }
  }, []);

  useEffect(() => {
    const hash = window.location.hash;
    if (hash !== LOGIN_PAGE_HASH && hash !== SIGN_PAGE_HASH && hash !== PAIRING_PAGE_HASH) {
      window.location.hash = LOGIN_PAGE_HASH;
    }
    const onHashChange = () => {
      setCurrentPage(resolvePageFromHash(window.location.hash));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // ---- on mount: restore account contexts + active login ----
  useEffect(() => {
    const restored = restorePersistedAccountContexts();
    accountContextMapRef.current = restored;
    setAccountCacheVersion((v) => v + 1);
    const summary = loadStoredAccountSummary();
    if (summary) {
      const active = restored.get(accountKey(summary.appleId, summary.teamId));
      if (active) {
        setLoginContext(active);
        setAppleId(active.appleId);
        addLog(`login: restored session ${active.appleId} / ${active.team.identifier}`);
      }
    }
    addLog('ready');
    void (async () => {
      try {
        const provisioned = await checkAnisetteProvisioned();
        setAnisetteProvisioned(provisioned);
      } catch (error) {
        addLog(`anisette status check failed: ${formatError(error)}`);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- body scroll lock on modal open ----
  useEffect(() => {
    const anyOpen = trustOpen || twoFactor.open || loginModalOpen;
    document.body.classList.toggle('modal-open', anyOpen);
    return () => {
      document.body.classList.remove('modal-open');
    };
  }, [trustOpen, twoFactor.open, loginModalOpen]);

  // ---- close WebUSB on unload ----
  useEffect(() => {
    const handler = () => {
      directClientRef.current?.close();
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, []);

  // ---- persist appleId ----
  const handleAppleIdBlur = useCallback(() => {
    saveText(APPLE_ID_STORAGE_KEY, appleId.trim());
  }, [appleId]);

  // ---- reset signed package when inputs change ----
  const clearPrepared = useCallback(() => setPrepared(null), []);

  const handleFileChange = useCallback(
    (file: File | null) => {
      setSelectedIpaFile(file);
      clearPrepared();
      if (file) {
        addLog(`ipa selected: ${file.name}`);
      } else {
        addLog('ipa selection cleared');
      }
    },
    [addLog, clearPrepared],
  );

  const handleSelectedUdidChange = useCallback(
    (value: string) => {
      setSelectedTargetUdid(value);
      saveText(SELECTED_DEVICE_UDID_STORAGE_KEY, value);
      clearPrepared();
      if (value) {
        addLog(`target udid selected: ${value}`);
      } else {
        addLog('target udid cleared');
      }
    },
    [addLog, clearPrepared],
  );

  // ---- auto-reset invalid selected UDID ----
  useEffect(() => {
    if (selectedTargetUdid.length > 0 && !knownUdids.includes(selectedTargetUdid)) {
      setSelectedTargetUdid('');
      saveText(SELECTED_DEVICE_UDID_STORAGE_KEY, '');
    }
  }, [knownUdids, selectedTargetUdid]);

  // ---- shared "a device was paired" bookkeeping (used by Sign page + Pairing page) ----
  const handlePairedDevice = useCallback(
    (info: PairedDeviceInfo) => {
      setPairedDeviceInfo(info);
      setSelectedTargetUdid(info.udid);
      saveText(SELECTED_DEVICE_UDID_STORAGE_KEY, info.udid);
      setPairRecordsVersion((v) => v + 1);
    },
    [],
  );

  // ---- pair flow (Sign page "Connect Device" button) ----
  const runPairFlow = useCallback(async (options: {
    showSuccess: boolean;
    startLogMessage: string;
  }): Promise<PairFlowResult> => {
    if (busyRef.current.pair) return { kind: 'failed' };
    setBusy((prev) => ({ ...prev, pair: true }));
    setTrustState('pairing');
    addLog(options.startLogMessage);
    try {
      const info = await pairDeviceFlow({
        log: addLog,
        clientRef: directClientRef,
        onStateChange: () => {},
        onTrustPending: () => {
          setTrustState('pending');
          addLog('pair: waiting for trust confirmation on device');
        },
      });
      handlePairedDevice(info);
      setTrustState(options.showSuccess ? 'paired' : TRUST_MODAL_CLOSED);
      return { kind: 'paired', info };
    } catch (error) {
      if (isPairingDialogPendingError(error)) {
        return { kind: 'pending' };
      }
      setTrustState(TRUST_MODAL_CLOSED);
      addLog(`pair failed: ${formatError(error)}`);
      return { kind: 'failed' };
    } finally {
      setBusy((prev) => ({ ...prev, pair: false }));
    }
  }, [addLog, handlePairedDevice]);

  const handlePair = useCallback(() => {
    void runPairFlow({
      showSuccess: true,
      startLogMessage: 'pair: please continue on your device',
    });
  }, [runPairFlow]);

  const handleTrustRetry = useCallback(() => {
    void runPairFlow({
      showSuccess: true,
      startLogMessage: 'pair: retrying after trust confirmation',
    });
  }, [runPairFlow]);

  // ---- login flow ----
  const handleLogin = useCallback(async () => {
    if (busyRef.current.loginSign) return;
    const trimmedAppleId = appleId.trim();
    if (!trimmedAppleId || !password) {
      addLog('login failed: please input email and password');
      return;
    }

    setBusy((prev) => ({ ...prev, loginSign: true }));
    setProgress({ percent: 0, status: 'starting' });
    twoFactorCancelledRef.current = false;
    setLoginError(null);
    let twoFactorOpened = false;
    let twoFactorErrorShown = false;
    try {
      saveText(APPLE_ID_STORAGE_KEY, trimmedAppleId);
      addLog('login: initializing anisette...');

      const { anisetteData: nextAnisette } = await ensureAnisetteData(null, addLog);
      setAnisetteData(nextAnisette);
      setAnisetteProvisioned(true);
      addLog('login: anisette ready, authenticating...');

      const context = await loginAccount({
        appleId: trimmedAppleId,
        password,
        anisetteData: nextAnisette,
        log: addLog,
        onTwoFactorRequired: (ctx) => {
          twoFactorOpened = true;
          setTwoFactor({ open: true, ctx, error: null });
          addLog('login: 2FA required, opening verification dialog');
        },
      });

      setTwoFactor({ open: false, ctx: null, error: null });
      setLoginError(null);
      addLog(`login: authenticated as ${context.appleId} / ${context.team.identifier}`);
      const key = accountKey(context.appleId, context.team.identifier);
      accountContextMapRef.current.set(key, context);
      setAccountCacheVersion((v) => v + 1);
      persistAccountSummary(context);
      persistAccountSession(context, nextAnisette);
      addLog('login: session persisted');

      setSavedAccounts(loadStoredAccountList());
      setLoginContext(context);
      setPassword('');
      setLoginModalOpen(false);
      clearPrepared();
      addLog('login: done, navigating to sign page');
      navigateToPage('sign');
    } catch (error) {
      console.error('[login] caught error:', error);
      const msg = formatError(error);
      addLog(`login failed: ${msg}`);
      // Keep the progress overlay visible on failure so the user can read the log.
      setProgress({ percent: 0, status: 'failed' });
      if (twoFactorOpened && !twoFactorCancelledRef.current) {
        setTwoFactor((prev) => ({ ...prev, error: msg }));
        twoFactorErrorShown = true;
      } else if (!twoFactorOpened) {
        setLoginError(msg);
      }
    } finally {
      if (!twoFactorErrorShown) {
        setTwoFactor({ open: false, ctx: null, error: null });
      }
      setBusy((prev) => ({ ...prev, loginSign: false }));
    }
  }, [addLog, appleId, clearPrepared, navigateToPage, password]);

  const handleTwoFactorCancel = useCallback(() => {
    const ctx = twoFactor.ctx;
    twoFactorCancelledRef.current = true;
    setTwoFactor({ open: false, ctx: null, error: null });
    if (ctx) {
      addLog('login: 2FA canceled');
      ctx.submitDeviceCode('__CANCELLED__');
    }
  }, [addLog, twoFactor.ctx]);

  const handleTwoFactorRetry = useCallback(() => {
    setTwoFactor({ open: false, ctx: null, error: null });
    void handleLogin();
  }, [handleLogin]);

  // ---- sign flow ----
  const handleSign = useCallback(async () => {
    if (busyRef.current.sign) return;
    if (!selectedIpaFile || !loginContext) return;
    const targetUdid = selectedTargetUdid.trim();
    if (targetUdid.length === 0) return;

    setBusy((prev) => ({ ...prev, sign: true }));
    setProgress({ percent: 0, status: 'starting' });
    lastInstallPercentRef.current = 0;

    try {
      const { anisetteData: nextAnisette } = await ensureAnisetteData(anisetteData, addLog);
      setAnisetteData(nextAnisette);
      setAnisetteProvisioned(true);

      let result;
      result = await signIpaFlow({
        ipaFile: selectedIpaFile,
        context: loginContext,
        anisetteData: nextAnisette,
        deviceUdid: targetUdid,
        deviceName: pairedDeviceInfo?.udid === targetUdid ? pairedDeviceInfo.name ?? undefined : undefined,
        log: addLog,
      });

      const key = accountKey(result.context.appleId, result.context.team.identifier);
      accountContextMapRef.current.set(key, result.context);
      persistAccountSummary(result.context);
      persistAccountSession(result.context, nextAnisette);
      setSavedAccounts(loadStoredAccountList());
      setLoginContext(result.context);
      setPrepared({
        file: result.signedFile,
        sourceKey: buildPreparedSourceKey(selectedIpaFile, targetUdid),
      });
      setProgress({ percent: 100, status: 'complete' });
    } catch (error) {
      addLog(`sign failed: ${formatError(error)}`);
      setProgress({ percent: 0, status: 'failed' });
    } finally {
      setBusy((prev) => ({ ...prev, sign: false }));
    }
  }, [addLog, anisetteData, loginContext, pairedDeviceInfo, selectedIpaFile, selectedTargetUdid]);

  // ---- install flow ----
  const handleInstall = useCallback(async () => {
    if (busyRef.current.install) return;
    if (!selectedIpaFile) return;
    const targetUdid = selectedTargetUdid.trim();
    if (targetUdid.length === 0) return;

    setBusy((prev) => ({ ...prev, install: true }));
    setProgress({ percent: 0, status: 'starting' });
    lastInstallPercentRef.current = 0;

    try {
      const client = await ensureClientSelected({
        log: addLog,
        clientRef: directClientRef,
        onStateChange: () => {},
        onTrustPending: () => setTrustState('pending'),
      });
      let currentDeviceUdid = pairedDeviceInfo?.udid ?? null;
      if (!client.isSessionStarted) {
        const pairResult = await runPairFlow({
          showSuccess: false,
          startLogMessage: 'install: device trust required, continue on your device',
        });
        if (pairResult.kind === 'pending') {
          addLog('install paused: finish trusting the device, then install again');
          setProgress({ percent: 0, status: 'idle' });
          return;
        }
        if (pairResult.kind === 'failed') {
          setProgress({ percent: 0, status: 'failed' });
          return;
        }
        currentDeviceUdid = pairResult.info.udid;
      }
      if (currentDeviceUdid !== targetUdid) {
        throw new Error('connected device udid does not match selected target');
      }

      const currentSourceKey = buildPreparedSourceKey(selectedIpaFile, targetUdid);
      if (!prepared || prepared.sourceKey !== currentSourceKey) {
        throw new Error('please sign ipa first, then install');
      }

      await installFlow({ client, targetUdid, signedFile: prepared.file, log: addLog });
      setProgress({ percent: 100, status: 'complete' });
    } catch (error) {
      addLog(`install failed: ${formatError(error)}`);
      setProgress({ percent: 0, status: 'failed' });
    } finally {
      setBusy((prev) => ({ ...prev, install: false }));
    }
  }, [addLog, pairedDeviceInfo, prepared, runPairFlow, selectedIpaFile, selectedTargetUdid]);

  // ---- switch account ----
  const handleSwitchAccount = useCallback(
    (summary: StoredAccountSummary) => {
      const key = accountKey(summary.appleId, summary.teamId);
      const cached = accountContextMapRef.current.get(key);

      setAppleId(summary.appleId);
      saveText(APPLE_ID_STORAGE_KEY, summary.appleId);
      setStoredAccountSummary(summary);
      setSavedAccounts(loadStoredAccountList());
      clearPrepared();

      if (cached) {
        setLoginContext(cached);
        addLog(`account switched: ${summary.appleId} / ${summary.teamId}`);
        navigateToPage('sign');
        return;
      }

      setLoginContext(null);
      setLoginModalOpen(true);
      addLog(`account selected: ${summary.appleId} / ${summary.teamId}, please sign in again`);
    },
    [addLog, clearPrepared, navigateToPage],
  );

  // ---- delete account ----
  const handleDeleteAccount = useCallback(
    (summary: StoredAccountSummary) => {
      const key = accountKey(summary.appleId, summary.teamId);

      removeStoredAccountSession(summary.appleId, summary.teamId);
      accountContextMapRef.current.delete(key);
      setAccountCacheVersion((v) => v + 1);

      const list = loadStoredAccountList().filter(
        (item) => !(item.appleId === summary.appleId && item.teamId === summary.teamId),
      );
      writeJson(APPLE_ACCOUNT_LIST_STORAGE_KEY, list);

      const activeSummary = loadStoredAccountSummary();
      if (activeSummary && activeSummary.appleId === summary.appleId && activeSummary.teamId === summary.teamId) {
        if (list.length > 0) {
          setStoredAccountSummary(list[0]);
        } else {
          writeJson(APPLE_ACCOUNT_SUMMARY_STORAGE_KEY, null);
        }
      }

      if (activeAccountKey === key) {
        setLoginContext(null);
      }

      setSavedAccounts(list);
      clearPrepared();
      addLog(`account removed: ${summary.appleId} / ${summary.teamId}`);
    },
    [activeAccountKey, addLog, clearPrepared],
  );

  // ---- dismiss progress ----
  const handleDismissProgress = useCallback(() => {
    setProgress({ percent: 0, status: 'idle' });
  }, []);

  // ---- derived disabled flags ----
  const progressBusy = busy.sign || busy.install || busy.loginSign;
  const loginCanSubmit = !busy.loginSign && !twoFactor.open && appleId.trim().length > 0 && password.length > 0;

  const currentSourceKey =
    selectedIpaFile && selectedTargetUdid ? buildPreparedSourceKey(selectedIpaFile, selectedTargetUdid) : null;
  const hasValidSignedPackage = !!prepared && !!currentSourceKey && prepared.sourceKey === currentSourceKey;

  const pairDisabled = busy.pair || busy.sign || busy.install || !isWebUsbSupported;
  const signDisabled =
    busy.pair ||
    busy.loginSign ||
    busy.sign ||
    busy.install ||
    !selectedIpaFile ||
    !loginContext ||
    selectedTargetUdid.length === 0;
  const installDisabled =
    busy.pair ||
    busy.loginSign ||
    busy.sign ||
    busy.install ||
    !pairedDeviceInfo ||
    pairedDeviceInfo.udid !== selectedTargetUdid ||
    !hasValidSignedPackage;

  return (
    <main className="min-h-screen bg-bg">
      <Header currentPage={currentPage} onNavigate={navigateToPage} />

      <section className="mx-auto max-w-190 px-5 py-10 sm:px-7">
        {currentPage === 'login' ? (
          <LoginPage
            loggedIn={!!loginContext}
            savedAccounts={savedAccounts}
            activeAccountKey={activeAccountKey}
            cachedAccountKeys={cachedAccountKeys}
            onSwitchAccount={handleSwitchAccount}
            onDeleteAccount={handleDeleteAccount}
            onAddAccount={() => {
              setPassword('');
              setLoginModalOpen(true);
            }}
            onGoToSignPage={() => navigateToPage('sign')}
          />
        ) : currentPage === 'pairing' ? (
          <PairingPage log={addLog} clientRef={directClientRef} onPairedDevice={handlePairedDevice} />
        ) : (
          <SignPage
            file={selectedIpaFile}
            onFileChange={handleFileChange}
            accounts={savedAccounts}
            activeAccountKey={activeAccountKey}
            onAccountChange={(key) => {
              const summary = savedAccounts.find((a) => accountKey(a.appleId, a.teamId) === key);
              if (summary) handleSwitchAccount(summary);
            }}
            knownUdids={knownUdids}
            connectedUdid={pairedDeviceInfo?.udid ?? null}
            selectedUdid={selectedTargetUdid}
            onSelectedUdidChange={handleSelectedUdidChange}
            onPair={handlePair}
            pairBusy={busy.pair}
            pairDisabled={pairDisabled}
            onSign={handleSign}
            signBusy={busy.sign}
            signDisabled={signDisabled}
            onInstall={handleInstall}
            installBusy={busy.install}
            installDisabled={installDisabled}
          />
        )}
      </section>

      <LoginModal
        open={loginModalOpen}
        onClose={() => { setLoginModalOpen(false); setLoginError(null); }}
        appleId={appleId}
        password={password}
        busyLoginSign={busy.loginSign}
        canSubmit={loginCanSubmit}
        error={loginError}
        onAppleIdChange={(v) => { setAppleId(v); setLoginError(null); }}
        onAppleIdBlur={handleAppleIdBlur}
        onPasswordChange={(v) => { setPassword(v); setLoginError(null); }}
        onSubmit={handleLogin}
      />

      <ProgressCard
        percent={progress.percent}
        status={progress.status}
        busy={progressBusy && !twoFactor.open}
        logLines={logLines}
        onDismiss={handleDismissProgress}
      />

      <TrustModal
        state={trustState}
        onClose={() => setTrustState(TRUST_MODAL_CLOSED)}
        onRetry={handleTrustRetry}
      />
      <TwoFactorModal
        open={twoFactor.open}
        ctx={twoFactor.ctx}
        onCancel={handleTwoFactorCancel}
        serverError={twoFactor.error}
        onRetry={handleTwoFactorRetry}
      />
    </main>
  );
}
