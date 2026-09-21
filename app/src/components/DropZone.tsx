import { useState, type ChangeEvent, type DragEvent, type MouseEvent } from 'react';
import { formatFileSize } from '../lib/ids';

interface DropZoneProps {
  file: File | null;
  onFileChange: (file: File | null) => void;
  accept?: string;
}

export function DropZone({ file, onFileChange, accept = '.ipa,application/octet-stream' }: DropZoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);

  const handleDragOver = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragOver(false);
    const dropped = event.dataTransfer?.files?.[0] ?? null;
    if (dropped) onFileChange(dropped);
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files?.[0] ?? null;
    onFileChange(selected);
  };

  const handleClear = (event: MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    onFileChange(null);
  };

  return (
    <div>
      <label
        className={`drop-zone${isDragOver ? ' dragover' : ''}`}
        onDragEnter={handleDragOver}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <svg
          className="mx-auto mb-2 h-7 w-7 text-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M14 3v4a1 1 0 0 0 1 1h4" />
          <path d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2z" />
          <path d="M12 11v6m-3-3 3 3 3-3" />
        </svg>

        {file ? (
          <>
            <span className="block truncate text-[14px] font-medium text-ink">{file.name}</span>
            <span className="mt-1 block text-[12px] text-muted">
              {formatFileSize(file.size)}
              <button
                type="button"
                onClick={handleClear}
                className="ml-2 text-[var(--color-accent)] underline-offset-2 hover:underline"
              >
                Clear
              </button>
            </span>
          </>
        ) : (
          <>
            <span className="block text-[14px] font-medium text-ink">No file selected</span>
            <span className="mt-1 block text-[12px] text-muted">Click or drag .ipa here</span>
          </>
        )}

        <input type="file" accept={accept} className="hidden" onChange={handleInputChange} value="" />
      </label>
    </div>
  );
}
