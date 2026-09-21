import { Button } from './ui/Button';

interface DevicePickerProps {
  knownUdids: string[];
  connectedUdid: string | null;
  selectedUdid: string;
  onSelectedChange: (udid: string) => void;
  onPair: () => void;
  pairing: boolean;
  pairDisabled: boolean;
}

export function DevicePicker({
  knownUdids,
  connectedUdid,
  selectedUdid,
  onSelectedChange,
  onPair,
  pairing,
  pairDisabled,
}: DevicePickerProps) {
  return (
    <div>
      <label htmlFor="device-udid-select" className="mb-1.5 block text-[12.5px] font-medium text-muted">
        Target Device
      </label>
      <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
        <select
          id="device-udid-select"
          className="field-input field-select"
          value={selectedUdid}
          onChange={(e) => onSelectedChange(e.target.value)}
        >
          <option value="">{knownUdids.length > 0 ? 'Select paired device' : 'No paired device'}</option>
          {knownUdids.map((udid) => (
            <option key={udid} value={udid}>
              {udid}
            </option>
          ))}
        </select>
        <Button variant="ghost" busy={pairing} busyLabel="Connecting…" disabled={pairDisabled} onClick={onPair}>
          Connect Device
        </Button>
      </div>
      {connectedUdid && (
        <p className="mt-1.5 font-mono text-[11px] text-subtle">
          Connected: <code className="text-muted">{connectedUdid}</code>
        </p>
      )}
    </div>
  );
}
