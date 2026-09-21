import { Button } from './ui/Button';
import { SavedAccountsList } from './SavedAccountsList';
import { WispSettings } from './WispSettings';
import type { StoredAccountSummary } from '../lib/account-session';

interface LoginPageProps {
  loggedIn: boolean;
  savedAccounts: StoredAccountSummary[];
  activeAccountKey: string | null;
  cachedAccountKeys: Set<string>;
  onSwitchAccount: (summary: StoredAccountSummary) => void;
  onDeleteAccount: (summary: StoredAccountSummary) => void;
  onAddAccount: () => void;
  onGoToSignPage: () => void;
}

export function LoginPage({
  loggedIn,
  savedAccounts,
  activeAccountKey,
  cachedAccountKeys,
  onSwitchAccount,
  onDeleteAccount,
  onAddAccount,
  onGoToSignPage,
}: LoginPageProps) {
  return (
    <section className="space-y-6 anim-in">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-[clamp(1.75rem,3.5vw,2.1rem)] font-semibold tracking-tight text-ink">Accounts</h1>
          <p className="mt-1 text-[14px] text-muted">Add your Apple Developer account here to sign and install apps.</p>
        </div>
        <Button variant="primary" onClick={onAddAccount} className="shrink-0">
          Add Account
        </Button>
      </div>

      <SavedAccountsList
        accounts={savedAccounts}
        activeKey={activeAccountKey}
        cachedKeys={cachedAccountKeys}
        onSwitch={onSwitchAccount}
        onDelete={onDeleteAccount}
      />

      <WispSettings />

      {loggedIn && (
        <div className="flex justify-end">
          <Button variant="ghost" onClick={onGoToSignPage}>
            Sign &amp; Install →
          </Button>
        </div>
      )}
    </section>
  );
}
