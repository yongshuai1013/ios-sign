import { describe, expect, it } from 'vitest';
import {
  extractUnlockData,
  FastbootClient,
  parseFastbootPacket,
  type FastbootResponse,
} from './fastboot';

function packet(status: string, payload: string): Uint8Array {
  const bytes = new Uint8Array(64);
  const head = new TextEncoder().encode(status);
  bytes.set(head.subarray(0, 4));
  bytes.set(new TextEncoder().encode(payload), 4);
  return bytes;
}

describe('parseFastbootPacket', () => {
  it('parses OKAY with payload', () => {
    const { status, payload } = parseFastbootPacket(packet('OKAY', '0.4'));
    expect(status).toBe('OKAY');
    expect(payload).toBe('0.4');
  });

  it('parses INFO packets', () => {
    const { status, payload } = parseFastbootPacket(
      packet('INFO', '(bootloader) 0A40040192024205'),
    );
    expect(status).toBe('INFO');
    expect(payload).toBe('(bootloader) 0A40040192024205');
  });

  it('parses FAIL with empty payload', () => {
    const { status, payload } = parseFastbootPacket(packet('FAIL', ''));
    expect(status).toBe('FAIL');
    expect(payload).toBe('');
  });

  it('rejects truncated packets', () => {
    expect(() => parseFastbootPacket(new Uint8Array(3))).toThrow();
  });
});

describe('extractUnlockData', () => {
  it('joins INFO lines and strips bootloader markers', () => {
    const infos = [
      '(bootloader) 0A40040192024205#4C44',
      '(bootloader) 3556473232#30342E',
    ];
    expect(extractUnlockData(infos)).toBe('0A40040192024205#4C443556473232#30342E');
  });

  it('returns empty string for empty input', () => {
    expect(extractUnlockData([])).toBe('');
  });

  it('strips the Unlockdata: label newer bootloaders prepend', () => {
    const infos = [
      '(bootloader) Unlockdata: 3A25668213015453#5A593332',
      '(bootloader) 44563850464B00585',
    ];
    expect(extractUnlockData(infos)).toBe(
      '3A25668213015453#5A59333244563850464B00585',
    );
  });
});

/** Stub client that fakes runCommand answers for probeConnectivity tests. */
class StubClient extends FastbootClient {
  constructor(private readonly behavior: (command: string) => string | Error) {
    super({ log: () => undefined });
  }

  override async runCommand(command: string): Promise<FastbootResponse> {
    const result = this.behavior(command);
    if (result instanceof Error) throw result;
    return { status: 'OKAY', payload: result, infos: [] };
  }
}

describe('probeConnectivity', () => {
  const fail = () => new Error('fastboot: command failed: (no message)');

  it('returns the first supported variable', async () => {
    const client = new StubClient((cmd) => {
      if (cmd === 'getvar:version') throw fail();
      if (cmd === 'getvar:product') return 'denver';
      throw fail();
    });
    await expect(client.probeConnectivity()).resolves.toEqual({
      value: 'product=denver',
      answered: true,
    });
  });

  it('still counts as connected when the device answers but supports none of the variables', async () => {
    const client = new StubClient(() => fail());
    await expect(client.probeConnectivity()).resolves.toEqual({
      value: null,
      answered: true,
    });
  });

  it('rethrows on timeout (device not answering at all)', async () => {
    const client = new StubClient(
      () => new Error('fastboot: timed out after 30s waiting for device response'),
    );
    await expect(client.probeConnectivity()).rejects.toThrow(/timed out/);
  });
});
