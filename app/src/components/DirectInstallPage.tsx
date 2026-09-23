import { Button } from './ui/Button';
import { DropZone } from './DropZone';
import { DevicePicker } from './DevicePicker';
import { IpaInfoCard } from './IpaInfoCard';

interface DirectInstallPageProps {
  file: File | null;
  onFileChange: (file: File | null) => void;

  knownUdids: string[];
  connectedUdid: string | null;
  selectedUdid: string;
  onSelectedUdidChange: (value: string) => void;

  onPair: () => void;
  pairBusy: boolean;
  pairDisabled: boolean;

  onInstall: () => void;
  installBusy: boolean;
  installDisabled: boolean;
}

export function DirectInstallPage({
  file,
  onFileChange,
  knownUdids,
  connectedUdid,
  selectedUdid,
  onSelectedUdidChange,
  onPair,
  pairBusy,
  pairDisabled,
  onInstall,
  installBusy,
  installDisabled,
}: DirectInstallPageProps) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Direct Install</h2>
        <p className="mt-1 text-sm text-muted">
          Install a pre-signed IPA (e.g. enterprise-signed from third-party tools) directly to your
          device. No Apple ID or signing required.
        </p>
        <p className="mt-1 text-sm text-muted">
          Note: the app must be signed with a valid (non-revoked) certificate, otherwise it will
          crash on launch after installation.
        </p>
      </div>

      <DropZone file={file} onFileChange={onFileChange} />

      {file && <IpaInfoCard file={file} />}

      <DevicePicker
        knownUdids={knownUdids}
        connectedUdid={connectedUdid}
        selectedUdid={selectedUdid}
        onSelectedChange={onSelectedUdidChange}
        onPair={onPair}
        pairing={pairBusy}
        pairDisabled={pairDisabled}
      />

      <div className="flex gap-3">
        <Button onClick={onInstall} disabled={installDisabled} busy={installBusy}>
          Install
        </Button>
      </div>
    </div>
  );
}
