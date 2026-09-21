import type { ButtonHTMLAttributes, ReactNode } from 'react';

type Variant = 'primary' | 'ghost' | 'accent';

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type'> {
  variant?: Variant;
  busy?: boolean;
  busyLabel?: string;
  size?: 'default' | 'sm';
  children: ReactNode;
}

const variantClass: Record<Variant, string> = {
  primary: 'btn-primary',
  ghost: 'btn-ghost',
  accent: 'btn-accent',
};

export function Button({
  variant = 'ghost',
  busy = false,
  busyLabel,
  size = 'default',
  className,
  disabled,
  children,
  ...rest
}: ButtonProps) {
  const classes = ['btn', variantClass[variant]];
  if (size === 'sm') classes.push('btn-sm');
  if (className) classes.push(className);

  return (
    <button type="button" disabled={busy || disabled} className={classes.join(' ')} {...rest}>
      {busy ? (
        <>
          <span className="spinner" aria-hidden="true" />
          <span>{busyLabel ?? 'Working…'}</span>
        </>
      ) : (
        children
      )}
    </button>
  );
}
