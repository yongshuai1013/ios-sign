export type ProgressSource = 'sign' | 'install';

export interface ProgressUpdate {
  percent: number;
  status: string;
  source: ProgressSource;
}

export function parseInstallProgress(message: string, lastPercent: number): ProgressUpdate | null {
  const statusMatch = message.match(/InstProxy status:\s*([^,]+)(?:,|$)/i);
  if (!statusMatch) return null;
  const status = statusMatch[1].trim();
  const percentMatch = message.match(/Percent=(\d{1,3})%/i);
  if (percentMatch) {
    return { source: 'install', percent: Number(percentMatch[1]), status };
  }
  if (status.toLowerCase() === 'complete') {
    return { source: 'install', percent: 100, status };
  }
  return { source: 'install', percent: lastPercent, status };
}

export function parseSigningProgress(message: string): ProgressUpdate | null {
  const lower = message.toLowerCase();
  if (lower.includes('sign: preparing ipa')) {
    return { source: 'sign', percent: 8, status: 'preparing ipa' };
  }
  if (lower.includes('signing stage: refreshing team')) {
    return { source: 'sign', percent: 14, status: 'refreshing team' };
  }
  if (lower.includes('signing stage: refreshed team')) {
    return { source: 'sign', percent: 22, status: 'team ready' };
  }
  if (lower.includes('signing stage: using team')) {
    return { source: 'sign', percent: 28, status: 'using team' };
  }
  if (lower.includes('signing stage: creating development certificate')) {
    return { source: 'sign', percent: 36, status: 'creating certificate' };
  }
  if (lower.includes('signing stage: using cached certificate')) {
    return { source: 'sign', percent: 40, status: 'using certificate' };
  }
  if (lower.includes('signing stage: certificate ready')) {
    return { source: 'sign', percent: 48, status: 'certificate ready' };
  }
  if (lower.includes('signing stage: registering device')) {
    return { source: 'sign', percent: 56, status: 'registering device' };
  }
  if (
    lower.includes('signing stage: device already registered') ||
    lower.includes('signing stage: device registered') ||
    lower.includes('signing stage: device confirmed')
  ) {
    return { source: 'sign', percent: 62, status: 'device ready' };
  }
  if (lower.includes('signing stage: creating app id') || lower.includes('signing stage: reuse app id')) {
    return { source: 'sign', percent: 72, status: 'app id ready' };
  }
  if (lower.includes('signing stage: fetching provisioning profile')) {
    return { source: 'sign', percent: 82, status: 'fetching profile' };
  }
  if (lower.includes('signing stage: resigning ipa')) {
    return { source: 'sign', percent: 90, status: 'resigning ipa' };
  }
  if (lower.includes('signing stage: complete') || lower.includes('sign: done ->')) {
    return { source: 'sign', percent: 100, status: 'complete' };
  }
  return null;
}

export function parseProgressFromLog(message: string, lastInstallPercent: number): ProgressUpdate | null {
  return parseInstallProgress(message, lastInstallPercent) ?? parseSigningProgress(message);
}
