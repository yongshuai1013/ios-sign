import type { AppPage } from '../lib/router';

export type { AppPage };

interface HeaderProps {
  currentPage: AppPage;
  onNavigate: (page: AppPage) => void;
}

export function Header({ currentPage, onNavigate }: HeaderProps) {
  return (
    <header className="border-b border-border">
      <div className="mx-auto flex max-w-[760px] items-center justify-between px-5 py-4 sm:px-7">
        <a
          href="#/login"
          onClick={(e) => {
            e.preventDefault();
            onNavigate('login');
          }}
          className="flex items-center gap-2 text-[15px] font-semibold tracking-tight text-ink no-underline"
        >
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-ink text-[10px] font-bold text-white">
            S
          </span>
          Side Impactor
        </a>
        <nav className="seg" aria-label="Page">
          <button
            type="button"
            className="seg-btn"
            data-active={currentPage === 'login'}
            onClick={() => onNavigate('login')}
          >
            Account
          </button>
          <button
            type="button"
            className="seg-btn"
            data-active={currentPage === 'pairing'}
            onClick={() => onNavigate('pairing')}
          >
            Pairing
          </button>
          <button
            type="button"
            className="seg-btn"
            data-active={currentPage === 'sign'}
            onClick={() => onNavigate('sign')}
          >
            Sign &amp; Install
          </button>
          <button
            type="button"
            className="seg-btn"
            data-active={currentPage === 'direct-install'}
            onClick={() => onNavigate('direct-install')}
          >
            Direct Install
          </button>
          <button
            type="button"
            className="seg-btn"
            data-active={currentPage === 'refresh'}
            onClick={() => onNavigate('refresh')}
          >
            Refresh
          </button>
        </nav>
      </div>
    </header>
  );
}
