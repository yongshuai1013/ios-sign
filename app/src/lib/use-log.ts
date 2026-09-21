import { useCallback, useRef, useState } from 'react';

const MAX_LINES = 200;

export interface UseLogResult {
  lines: string[];
  addLog: (message: string) => void;
  clearLog: () => void;
}

export function useLog(): UseLogResult {
  const [lines, setLines] = useState<string[]>([]);
  const bufferRef = useRef<string[]>([]);

  const addLog = useCallback((message: string) => {
    const now = new Date();
    const time = `${now.toLocaleTimeString()}.${String(now.getMilliseconds()).padStart(3, '0')}`;
    const line = `[${time}] ${message}`;
    console.log(`%c[sideload]%c ${message}`, 'color:#2563eb;font-weight:600', 'color:inherit');
    bufferRef.current = [...bufferRef.current, line].slice(-MAX_LINES);
    setLines(bufferRef.current);
  }, []);

  const clearLog = useCallback(() => {
    bufferRef.current = [];
    setLines([]);
  }, []);

  return { lines, addLog, clearLog };
}
