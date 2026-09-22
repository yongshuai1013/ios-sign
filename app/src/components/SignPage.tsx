import { Button } from './ui/Button';
import { DropZone } from './DropZone';
import { DevicePicker } from './DevicePicker';
import { IpaInfoCard } from './IpaInfoCard';
import type { StoredAccountSummary } from '../lib/account-session';

interface SignPageProps {
  file: File | null;
  onFileChange: (file: File | null) => void;

  accounts: StoredAccountSummary[];
  activeAccountKey: string | null;
  onAccountChange: (key: string) => void;

  knownUdids: string[];
  connectedUdid: string | null;
  selectedUdid: string;
  onSelectedUdidChange: (value: string) => void;

  onPair: () => void;
  pairBusy: boolean;
  pairDisabled: boolean;

  onSign: () => void;
  signBusy: boolean;
  signDisabled: boolean;

  onRevokeCert: () => void;

  onInstall: () => void;
  installBusy: boolean;
  installDisabled: boolean;
}

function accountKey(s: StoredAccountSummary): string {
  return `${s.appleId.trim().toLowerCase()}::${s.teamId.trim().toUpperCase()}`;
}

export function SignPage({
  file,
  onFileChange,
  accounts,
  activeAccountKey,
  onAccountChange,
  knownUdids,
  connectedUdid,
  selectedUdid,
  onSelectedUdidChange,
  onPair,
  pairBusy,
  pairDisabled,
  onSign,
  signBusy,
  signDisabled,
  onRevokeCert,
  onInstall,
  installBusy,
  installDisabled,
}: SignPageProps) {
  return (
    <section className="space-y-6 anim-in">
      <div>
        <h1 className="text-[clamp(1.75rem,3.5vw,2.1rem)] font-semibold tracking-tight text-ink">Sign &amp; Install</h1>
        <p className="mt-2 text-[14.5px] text-muted">Drop an .ipa, then sign and install onto your paired device.</p>
      </div>

      <DropZone file={file} onFileChange={onFileChange} />

      {file && <IpaInfoCard file={file} />}

      <div>
        <label htmlFor="account-select" className="mb-1.5 block text-[12.5px] font-medium text-muted">
          Signing Account
        </label>
        <select
          id="account-select"
          className="field-input field-select"
          value={activeAccountKey ?? ''}
          onChange={(e) => onAccountChange(e.target.value)}
        >
          <option value="">{accounts.length > 0 ? 'Select account' : 'No account'}</option>
          {accounts.map((acct) => {
            const key = accountKey(acct);
            return (
              <option key={key} value={key}>
                {acct.appleId} / {acct.teamId}
              </option>
            );
          })}
        </select>
      </div>

      <DevicePicker
        knownUdids={knownUdids}
        connectedUdid={connectedUdid}
        selectedUdid={selectedUdid}
        onSelectedChange={onSelectedUdidChange}
        onPair={onPair}
        pairing={pairBusy}
        pairDisabled={pairDisabled}
      />

      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button
          variant="ghost"
          busy={signBusy}
          busyLabel="Signing…"
          disabled={signDisabled}
          onClick={onSign}
          className="min-w-[120px]"
        >
          Sign IPA
        </Button>
        <Button
          variant="ghost"
          disabled={signBusy || signDisabled}
          onClick={onRevokeCert}
          className="min-w-[140px]"
          title="撤銷舊憑證，下次簽名建新的"
        >
          Revoke Cert
        </Button>
        <Button
          variant="primary"
          busy={installBusy}
          busyLabel="Installing…"
          disabled={installDisabled}
          onClick={onInstall}
          className="min-w-[160px]"
        >
          Install Signed IPA
        </Button>
      </div>
    </section>
  );
}
