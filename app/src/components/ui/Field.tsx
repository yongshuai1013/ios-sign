import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from 'react';

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'className'> {
  label: string;
  hint?: ReactNode;
  error?: ReactNode;
  inputClassName?: string;
}

export const Field = forwardRef<HTMLInputElement, FieldProps>(function Field(
  { label, hint, error, inputClassName, id, ...rest },
  ref,
) {
  const reactId = useId();
  const fieldId = id ?? reactId;
  const hintId = hint || error ? `${fieldId}-hint` : undefined;

  return (
    <div>
      <label htmlFor={fieldId} className="mb-1.5 block text-[12.5px] font-medium text-muted">
        {label}
      </label>
      <input
        ref={ref}
        id={fieldId}
        className={['field-input', inputClassName].filter(Boolean).join(' ')}
        aria-describedby={hintId}
        aria-invalid={error ? true : undefined}
        {...rest}
      />
      {error ? (
        <p id={hintId} className="mt-1.5 text-[12px] text-[var(--color-danger)]">
          {error}
        </p>
      ) : hint ? (
        <p id={hintId} className="mt-1.5 text-[12px] text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
});
