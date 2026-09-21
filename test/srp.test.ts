import { describe, expect, test } from 'bun:test';
import {
  SrpClient,
  SRP_N_HEX,
  SRP_GROUP_N,
  SRP_GROUP_G,
  srpK,
  srpU,
  srpX,
  SrpPairSetupClient,
} from '../src/pairing/srp';

// Fixed test vectors, generated with Python per the idevice-srp 0.6.0 algorithm:
//   a        = bytes 0x01..0x20 (32 bytes)
//   username = "Pair-Setup", password = "000000"
//   salt     = bytes 0x64..0x73 (16 bytes)
//   b_pub    = (k*v + g^b) mod N, b = bytes 0x21..0x40 (simulated server)

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

const A = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
const USERNAME = 'Pair-Setup';
const PASSWORD = '000000';
const SALT = hexToBytes('6465666768696a6b6c6d6e6f70717273');
const B_PUB = hexToBytes(
  '249420e5b677fcade48d93a431a6c40c4e65f8337379bb0a38704c7731e5555f' +
    '8b286f16f730c367c52920c2d930f8fb68522922e3c1482e0916d773b412c8152c' +
    'bf1e4fa2eb53f6312a8d5caf25b05ac5cf79682a4364d15be97eec2a9458fb846' +
    '3e278f239e0548faeda7338a16eee84d83f82362478253c69a9cf8cdd985b1d2e' +
    '96927ed507a0638598307a98eead1292e0b8df061e7119a549775111cfe26c9e19' +
    'd3e3d1d0d9e734fbf5106540aff295d19d5e2ffb7fc1f5e2ef2aac2c807e269092' +
    '912a1584d73def1b18098810af349f825622031f6c5e5489e6b8ba030705341ea0' +
    'dce6bfff7870e40dd800ce264f0a634d2027cb73e66f5e59127c51346e0872871' +
    '565e4c996587be17a1c0e06704ceb29cb9053e3c0e5ed8cc5111ee4cd4cc1a3dcc' +
    '148767c4ede285e708a5753c387c6423471196367c69a034912fe1f4edc623b96a' +
    '2566bd161b52ec9baa0249d8250a05fb1a4b5c2dfaafdca73104b417730a2c5c00' +
    '9a48a0453d3f4ff803b298b37c8daff6a0de4719d38e43a',
);

const EXPECTED_A_PUB =
  'bc0e7cf5dc3babf67dcedbb3b140aacc6cac43f4336b43bbd5de48d6ea7c8eda' +
  '66924e354255225bccad9debe21182e6bb050f3ff3e6cfbb62c229379968c70ca' +
  '436ad649a0b051373184215eef046f6f1f2256838f958581f6c7b2b85fa4afe32' +
  '6a0e8a951d4489305331aff88a136fd8d108bcc95fceb7e557c889c828bd23fb0' +
  '702f053e1ca6470fb3c76bce4843fc005c7ea675740f8550212656cfc8919d9db' +
  '805a434a68229e0d9dfe43fc16dc680a5ce74b77cf374353b05759bc1da3a9dab' +
  'de30a4209381c87ca83d9483abdf66b86f9b1cbda9ad82c62712b87ce6fb7069' +
  'b8fc8df344261821a06d0dc5106af76d4245f3f7737a94dbc484b415555dc4018' +
  '42d3011204553ba9f611b02bc38de26eba1a76bf8350205a62c436ba1c3c7c69d' +
  '59318bd107fd1c1f5d846b3142e85a5d49e522655e020ed1bfe1e186cf923bf32' +
  '8f0b9b4c6a8aa3266ed9125bb98d63827110713be7803122ee4603c54ea31863c' +
  'e4b10aff31f9073cf63b94733b4f066e72d4ec35687047d5d0db160';

const EXPECTED_KEY =
  'c2b0cd83281ef1e11c3d9ad3f5943d93ee9faca8980938fcad01e716bbe16f2b36' +
  'b87b9d512b865ccbc181831ea90425728282aa6aeef024b7f70489bf86a6cd';

const EXPECTED_M1 =
  'ef3e44bd858c8044ca61aa6d2497e075bee9f0ec84f480a7ec471f8b58f6f5327' +
  'bc97f23742995e0e9be1f8f86908c5a764513fa7dbb1354666e56bfd3c53a92';

const EXPECTED_M2 =
  'e4b0a3ebd45eb02241056c8052ca9ae2c03647eef5c260359c119cfc35ea4b2a0' +
  'eae411af41cb57a9fc86672a06882b5cff1001cb49855725cfb0172cb3b34f5';

describe('SrpClient (SRP-6a, SHA-512, G_3072)', () => {
  const client = new SrpClient();

  test('SRP_N_HEX is the 384-byte RFC 5054 3072-bit prime', () => {
    expect(SRP_N_HEX.length).toBe(768);
    expect(SRP_N_HEX.startsWith('ffffffffffffffffc90fdaa22168c234c4')).toBe(true);
  });

  test('computePublicEphemeral returns the expected 384-byte A', () => {
    const aPub = client.computePublicEphemeral(A);
    expect(bytesToHex(aPub)).toBe(EXPECTED_A_PUB);
    expect(aPub.length).toBe(384);
  });

  test('processReply derives the expected session key and M1', () => {
    const verifier = client.processReply(A, USERNAME, PASSWORD, SALT, B_PUB);
    expect(bytesToHex(verifier.key())).toBe(EXPECTED_KEY);
    expect(verifier.key().length).toBe(64);
    expect(bytesToHex(verifier.proof())).toBe(EXPECTED_M1);
    expect(verifier.proof().length).toBe(64);
  });

  test('verifyServer accepts the correct M2', () => {
    const verifier = client.processReply(A, USERNAME, PASSWORD, SALT, B_PUB);
    expect(verifier.verifyServer(hexToBytes(EXPECTED_M2))).toBe(true);
  });

  test('verifyServer rejects a tampered M2', () => {
    const verifier = client.processReply(A, USERNAME, PASSWORD, SALT, B_PUB);
    const tampered = hexToBytes(EXPECTED_M2);
    tampered[0] ^= 0xff;
    tampered[tampered.length - 1] ^= 0x01;
    expect(verifier.verifyServer(tampered)).toBe(false);
    expect(verifier.verifyServer(new Uint8Array(0))).toBe(false);
    expect(verifier.verifyServer(new Uint8Array(64))).toBe(false);
  });

  test('processReply rejects a malicious B (B mod N == 0)', () => {
    // B = 0
    expect(() => client.processReply(A, USERNAME, PASSWORD, SALT, new Uint8Array(384))).toThrow();
    // B = N
    expect(() =>
      client.processReply(A, USERNAME, PASSWORD, SALT, hexToBytes(SRP_N_HEX)),
    ).toThrow();
  });

  test('isGsaEmptyHash hashes an empty username into the identity hash', () => {
    const normal = client.processReply(A, USERNAME, PASSWORD, SALT, B_PUB);
    const gsa = client.processReply(A, USERNAME, PASSWORD, SALT, B_PUB, true);
    // Different identity hash -> different x -> different session key.
    expect(bytesToHex(gsa.key())).not.toBe(bytesToHex(normal.key()));
    expect(gsa.key().length).toBe(64);
    expect(bytesToHex(gsa.proof()).length).toBe(128);
  });

  test('username/password also accepted as Uint8Array', () => {
    const enc = new TextEncoder();
    const verifier = client.processReply(A, enc.encode(USERNAME), enc.encode(PASSWORD), SALT, B_PUB);
    expect(bytesToHex(verifier.key())).toBe(EXPECTED_KEY);
    expect(bytesToHex(verifier.proof())).toBe(EXPECTED_M1);
  });
});
describe('SrpPairSetupClient + srp* building blocks', () => {
  // Independent vectors from a Python reference implementation of the
  // idevice-srp 0.6.0 algorithm (hashlib.sha512, pow with 3 args):
  //   a        = bytes 0x01..0x20 (32 bytes)
  //   username = "Pair-Setup", password = "123456"
  //   salt     = bytes 0x65..0x84 (32 bytes)
  //   b        = bytes 0x21..0x40 (simulated server private)
  const A2 = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
  const USER2 = 'Pair-Setup';
  const PASS2 = new TextEncoder().encode('123456');
  const SALT2 = hexToBytes(
    '65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384',
  );
  const B2 = hexToBytes(
    '64c09b4f536c92082104d691d003514fe3b39b1ea649050f192bf54aa1782be8a' +
      '2972a33545ef260104c9a1460a4700c1a84581c21b33d6470ebd8d24a3eb53553' +
      'c3e637aff7f3580a8a9204fd0e40af64bc70313fad9527b9a015a62ea315e8d65' +
      'bce52e9036cc00933845edbc6780b85916efb25b73f56e1a6d8fca5d9f7c006b' +
      '3a6fa320ea36c953d656c8e588b7c8c5af325c25beaff9bacf66ffd52a74cfdd7' +
      '229fdd0178437cc73705f142e7d972b82d27fd55b00c3c84c0bbe664fc09120dc' +
      '78e95474538e7631b0df9c9ffc611f9fe0148f7f86cc4ebad38ea389dd4a1b7f5' +
      'fe89b9f1385e535b2841c2cb0e72cdde4aee35bd4a7efed9b4754faa0fd44e82d' +
      'af6781b098a4c973215db0ad3c3d20aa39ec54e1fadf8a9baa3a13e7dbbee8b96' +
      '1acf1aab32eaace1813776420538006daffbc824539d093160d71b7d237df1586' +
      'f70787f16e4ea1de7f1a249aeb17de8805bc25a87e6b332ef458e8d0976fd8502' +
      'e294ab033068ba1b274d4bf8e29eb89b52a246a9c3b1cb5568ba12',
  );
  const EXPECTED_A2 =
    'bc0e7cf5dc3babf67dcedbb3b140aacc6cac43f4336b43bbd5de48d6ea7c8eda' +
    '66924e354255225bccad9debe21182e6bb050f3ff3e6cfbb62c229379968c70ca' +
    '436ad649a0b051373184215eef046f6f1f2256838f958581f6c7b2b85fa4afe32' +
    '6a0e8a951d4489305331aff88a136fd8d108bcc95fceb7e557c889c828bd23fb0' +
    '702f053e1ca6470fb3c76bce4843fc005c7ea675740f8550212656cfc8919d9db' +
    '805a434a68229e0d9dfe43fc16dc680a5ce74b77cf374353b05759bc1da3a9dab' +
    'de30a4209381c87ca83d9483abdf66b86f9b1cbda9ad82c62712b87ce6fb7069' +
    'b8fc8df344261821a06d0dc5106af76d4245f3f7737a94dbc484b415555dc4018' +
    '42d3011204553ba9f611b02bc38de26eba1a76bf8350205a62c436ba1c3c7c69d' +
    '59318bd107fd1c1f5d846b3142e85a5d49e522655e020ed1bfe1e186cf923bf32' +
    '8f0b9b4c6a8aa3266ed9125bb98d63827110713be7803122ee4603c54ea31863c' +
    'e4b10aff31f9073cf63b94733b4f066e72d4ec35687047d5d0db160';
  const EXPECTED_K2 =
    '040ffdb28c5d8fb690f8f27eb826f808c4918bd990e3159905570c6ae209a28a1' +
    '5a26e031afe330a4f9bcbd923b938cf7a1471a197cab4390ccec26e74736eb4';
  const EXPECTED_M1_2 =
    '8c2f65862472c84c899833e4b3ad0c99133927d182c77465f05bbe12cf93122a2' +
    '4a2cb542bdce1823f0da2cc25c9b63d2781059cf335f14d240c4122768268b6';
  const EXPECTED_M2_2 =
    '9796f7c01d6684d6c8b58a0320357ddd55a8c5bd7197e9f3c19f856f4a834301d' +
    '0e45b777927f89f9aa6b1f7e0afb891bb4b1a2eb1b5ff301992c60b61d51e07';
  const EXPECTED_X2 =
    '8d9fb8db4e07702f813b3a83aed474c69d83b276611e4d4d39797d5798d04a37' +
    'c8dc3dc84d775221b6e86f0ad2218176b2cc3e282cdf497100f2dd2796fca953';

  test('SRP_GROUP_N / SRP_GROUP_G constants', () => {
    expect(SRP_GROUP_G).toBe(5n);
    expect(SRP_GROUP_N.toString(2).length).toBe(3072);
    expect(SRP_GROUP_N.toString(16)).toBe(SRP_N_HEX);
  });

  test('srpX matches the reference x', () => {
    expect(srpX(SALT2, USER2, PASS2).toString(16)).toBe(EXPECTED_X2);
  });

  test('srpK / srpU return positive bigints', () => {
    expect(srpK() > 0n).toBe(true);
    expect(srpU(hexToBytes(EXPECTED_A2), B2) > 0n).toBe(true);
  });

  test('SrpPairSetupClient full handshake against reference vectors', () => {
    const client = new SrpPairSetupClient(USER2, PASS2, SALT2);
    const A = client.generateAFromSecret(A2);
    expect(bytesToHex(A)).toBe(EXPECTED_A2);
    const { M1, sessionKey } = client.computeM1(B2);
    expect(bytesToHex(M1)).toBe(EXPECTED_M1_2);
    expect(bytesToHex(sessionKey)).toBe(EXPECTED_K2);
    expect(client.verifyM2(hexToBytes(EXPECTED_M2_2), M1)).toBe(true);
  });

  test('SrpPairSetupClient rejects tampered M2 or M1', () => {
    const client = new SrpPairSetupClient(USER2, PASS2, SALT2);
    client.generateAFromSecret(A2);
    const { M1 } = client.computeM1(B2);
    const badM2 = hexToBytes(EXPECTED_M2_2);
    badM2[0] ^= 0x01;
    expect(client.verifyM2(badM2, M1)).toBe(false);
    const badM1 = M1.slice();
    badM1[7] ^= 0x80;
    expect(client.verifyM2(hexToBytes(EXPECTED_M2_2), badM1)).toBe(false);
  });

  test('SrpPairSetupClient enforces call order', () => {
    const client = new SrpPairSetupClient(USER2, PASS2, SALT2);
    expect(() => client.computeM1(B2)).toThrow();
    expect(() => client.verifyM2(new Uint8Array(64), new Uint8Array(64))).toThrow();
    client.generateAFromSecret(A2);
    expect(() => client.verifyM2(new Uint8Array(64), new Uint8Array(64))).toThrow();
  });

  test('generateA produces 384-byte A from random 256-bit a', () => {
    const client = new SrpPairSetupClient(USER2, PASS2, SALT2);
    const A = client.generateA();
    expect(A.length).toBeLessThanOrEqual(384);
    expect(A.length).toBeGreaterThan(300);
  });
});
