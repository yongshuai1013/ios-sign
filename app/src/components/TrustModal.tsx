import { Button } from './ui/Button';
import { Modal } from './ui/Modal';

export type TrustModalState = 'closed' | 'pairing' | 'pending' | 'paired';

interface TrustModalProps {
  state: TrustModalState;
  onClose: () => void;
  onRetry: () => void;
}

export function TrustModal({ state, onClose, onRetry }: TrustModalProps) {
  if (state === 'closed') return null;

  return (
    <Modal
      open
      onClose={onClose}
      labelledBy="trust-title"
      closeOnBackdrop={false}
      closeOnEscape={state !== 'pairing'}
    >
      <div className="flex flex-col items-center text-center">
        <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-surface" aria-hidden="true">
          <svg
            className="h-7 w-7 text-ink"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="6" y="2.5" width="12" height="19" rx="2.5" />
            <path d="M11 18.5h2" />
            <path d="M9 7.5l2.2 2.2L15 5.9" />
          </svg>
        </div>

        {state === 'pairing' ? (
          <>
            <h2 id="trust-title" className="text-[16px] font-semibold tracking-tight text-ink">
              Continue on Your Device
            </h2>
            <p className="mt-2 text-[13px] leading-[1.6] text-muted">
              If prompted, unlock your iPhone or iPad and tap <strong className="font-semibold text-ink">Trust</strong>.
              Enter your passcode if asked.
            </p>
            <p className="mt-1.5 text-[12px] leading-[1.5] text-subtle">
              Developer Mode must be enabled on your device. Go to Settings → Privacy & Security → Developer Mode.
            </p>
            <div className="mt-5 flex items-center gap-2 text-[12.5px] text-muted">
              <span className="spinner" aria-hidden="true" />
              <span>Waiting for device…</span>
            </div>
          </>
        ) : state === 'pending' ? (
          <>
            <h2 id="trust-title" className="text-[16px] font-semibold tracking-tight text-ink">
              Trust This Device
            </h2>
            <p className="mt-2 text-[13px] leading-[1.6] text-muted">
              Approve the trust prompt on your iPhone or iPad, then return here to finish pairing.
            </p>
            <p className="mt-1.5 text-[12px] leading-[1.5] text-subtle">
              Tap <strong className="font-semibold text-ink">Trust</strong> and enter your passcode if asked.
            </p>
            <div className="mt-5 grid w-full gap-2 sm:grid-cols-2">
              <Button variant="ghost" onClick={onClose} className="w-full">
                Close
              </Button>
              <Button variant="primary" onClick={onRetry} className="w-full">
                I Trusted This Device
              </Button>
            </div>
          </>
        ) : (
          <>
            <h2 id="trust-title" className="text-[16px] font-semibold tracking-tight text-ink">
              Device Paired
            </h2>
            <p className="mt-2 text-[13px] leading-[1.6] text-muted">Your device is connected and ready for signing.</p>
            <Button variant="primary" onClick={onClose} className="mt-5 w-full">
              Continue
            </Button>
          </>
        )}
      </div>
    </Modal>
  );
}
