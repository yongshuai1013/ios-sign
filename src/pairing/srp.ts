/**
 * SRP-6a client — TypeScript port of the Rust crate `idevice-srp` 0.6.0
 * (`src/client.rs`, `src/utils.rs`, `src/groups.rs`).
 *
 * - Digest is fixed to SHA-512.
 * - Group is fixed to G_3072 (g = 5, the RFC 5054 3072-bit prime).
 *
 * Big integers are native `bigint`; all byte conversions are big-endian and
 * strip leading zero bytes, mirroring Rust `BigUint::to_bytes_be()`.
 */

import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

/** The G_3072 prime N as hex (RFC 5054 3072-bit prime), exported for debugging. */
export const SRP_N_HEX =
  'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff';

const N = hexToBigInt(SRP_N_HEX);
const G = 5n;
/** Byte length of N (384 for the 3072-bit prime); used for PAD(). */
const N_BYTE_LEN = bigIntToBytes(N).length;

// ---------------------------------------------------------------------------
// Byte / bigint helpers (big-endian, leading zeros stripped like
// Rust `BigUint::to_bytes_be()`)
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hexToBigInt(hex: string): bigint {
  return BigInt('0x' + hex);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

/** Big-endian bytes with leading zero bytes stripped. */
function bigIntToBytes(n: bigint): Uint8Array {
  if (n === 0n) {
    return new Uint8Array(0);
  }
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  return hexToBytes(hex);
}

/** Left-pad with zero bytes to `len` (the PAD() of the SRP utils). */
function padLeft(bytes: Uint8Array, len: number): Uint8Array {
  if (bytes.length > len) {
    throw new Error('srp: value too large to pad');
  }
  const out = new Uint8Array(len);
  out.set(bytes, len - bytes.length);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Square-and-multiply modular exponentiation (fast enough for 3072-bit). */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) {
    return 0n;
  }
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

/** Constant-time equality check for the M2 server proof. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

// ---------------------------------------------------------------------------
// SRP internals (mirrors `utils.rs`)
// ---------------------------------------------------------------------------

/** u = H(A | B), A and B with leading zeros stripped. */
function computeU(aPubBytes: Uint8Array, bPubBytes: Uint8Array): bigint {
  return bytesToBigInt(sha512(concat(aPubBytes, bPubBytes)));
}

/** k = H(N | PAD(g)) — N as 384 bytes, g left-padded to 384 bytes. */
function computeK(): bigint {
  const nBytes = padLeft(bigIntToBytes(N), N_BYTE_LEN);
  const gPad = padLeft(bigIntToBytes(G), N_BYTE_LEN);
  return bytesToBigInt(sha512(concat(nBytes, gPad)));
}

/** identityHash = H(username | ":" | password). */
function computeIdentityHash(username: Uint8Array, password: Uint8Array): Uint8Array {
  return sha512(concat(username, new Uint8Array([0x3a]), password));
}

/** x = H(salt | identityHash). */
function computeX(identityHash: Uint8Array, salt: Uint8Array): bigint {
  return bytesToBigInt(sha512(concat(salt, identityHash)));
}

/**
 * Premaster secret S = (B - k*g^x) ^ (a + u*x) mod N.
 * base = (N + B - (k * g^x mod N)) mod N, mirroring the Rust safeguard that
 * adds N before subtracting so the base stays non-negative.
 */
function computePremasterSecret(
  bPub: bigint,
  k: bigint,
  x: bigint,
  a: bigint,
  u: bigint,
): bigint {
  const kgx = (k * modPow(G, x, N)) % N;
  const base = (((N + bPub - kgx) % N) + N) % N;
  const exp = u * x + a;
  return modPow(base, exp, N);
}

/**
 * M1 = H( (H(N) XOR H(g)) | H(username) | salt | PAD(A) | PAD(B) | key ).
 * H(N) is over the 384-byte N; H(g) is over g's shortest bytes (0x05).
 */
function computeM1(
  aPubBytes: Uint8Array,
  bPubBytes: Uint8Array,
  key: Uint8Array,
  username: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const aPad = padLeft(aPubBytes, N_BYTE_LEN);
  const bPad = padLeft(bPubBytes, N_BYTE_LEN);

  const nHash = sha512(padLeft(bigIntToBytes(N), N_BYTE_LEN));
  const gHash = sha512(bigIntToBytes(G));

  const hnxorg = new Uint8Array(nHash.length);
  for (let i = 0; i < hnxorg.length; i++) {
    hnxorg[i] = nHash[i] ^ gHash[i];
  }

  return sha512(concat(hnxorg, sha512(username), salt, aPad, bPad, key));
}

/** M2 = H(A | M1 | key), A with leading zeros stripped. */
function computeM2(aPubBytes: Uint8Array, m1: Uint8Array, key: Uint8Array): Uint8Array {
  return sha512(concat(aPubBytes, m1, key));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * SRP client state after the handshake with the server.
 *
 * NOTE: unlike the Rust `idevice-srp` `verify_server` (which returns
 * `Err(SrpAuthError::BadRecordMac)` on a mismatching server proof),
 * `verifyServer()` here returns `false` on mismatch so it is easier to use
 * from TypeScript. A `false` result must be treated as authentication
 * failure.
 */
export interface SrpVerifier {
  /** M1 client proof, to send to the server. */
  proof(): Uint8Array;
  /** Constant-time check of the server's M2 proof. */
  verifyServer(serverProof: Uint8Array): boolean;
  /** The shared session key (SHA-512 of the premaster secret). */
  key(): Uint8Array;
}

class SrpClientVerifier implements SrpVerifier {
  private readonly m1: Uint8Array;
  private readonly m2: Uint8Array;
  private readonly sessionKey: Uint8Array;

  constructor(m1: Uint8Array, m2: Uint8Array, key: Uint8Array) {
    this.m1 = m1;
    this.m2 = m2;
    this.sessionKey = key;
  }

  proof(): Uint8Array {
    return this.m1.slice();
  }

  verifyServer(serverProof: Uint8Array): boolean {
    return constantTimeEqual(this.m2, serverProof);
  }

  key(): Uint8Array {
    return this.sessionKey.slice();
  }
}

/** SRP-6a client state before the handshake (SHA-512, G_3072). */
export class SrpClient {
  constructor() {
    // Group and digest are fixed; nothing to configure.
  }

  /**
   * Public ephemeral value A = g^a mod N.
   * Returned with leading zero bytes stripped.
   */
  computePublicEphemeral(a: Uint8Array): Uint8Array {
    return bigIntToBytes(modPow(G, bytesToBigInt(a), N));
  }

  /**
   * Process the server reply (`salt`, `b_pub`) and derive the session key
   * plus the M1/M2 proofs.
   *
   * When `isGsaEmptyHash` is true the identity hash is computed with an
   * empty username (GSA-style flow); the M1 username hash still uses the
   * real username, mirroring the Rust implementation.
   *
   * @throws if `b_pub` looks malicious (`B mod N == 0`).
   */
  processReply(
    a: Uint8Array,
    username: Uint8Array | string,
    password: Uint8Array | string,
    salt: Uint8Array,
    bPub: Uint8Array,
    isGsaEmptyHash = false,
  ): SrpVerifier {
    const aBig = bytesToBigInt(a);
    const aPubBytes = bigIntToBytes(modPow(G, aBig, N));

    const bPubBig = bytesToBigInt(bPub);
    // Safeguard against malicious B (Rust: SrpAuthError::IllegalParameter("b_pub"))
    if (bPubBig % N === 0n) {
      throw new Error('srp: illegal parameter b_pub (B mod N == 0)');
    }
    const bPubStripped = bigIntToBytes(bPubBig);

    const usernameBytes = toBytes(username);
    const passwordBytes = toBytes(password);

    const u = computeU(aPubBytes, bPubStripped);
    const k = computeK();
    const identityHash = computeIdentityHash(
      isGsaEmptyHash ? new Uint8Array(0) : usernameBytes,
      passwordBytes,
    );
    const x = computeX(identityHash, salt);

    const s = computePremasterSecret(bPubBig, k, x, aBig, u);
    const key = sha512(bigIntToBytes(s));

    const m1 = computeM1(aPubBytes, bPubStripped, key, usernameBytes, salt);
    const m2 = computeM2(aPubBytes, m1, key);

    return new SrpClientVerifier(m1, m2, key);
  }
}

// ---------------------------------------------------------------------------
// Convenience API: group constants, SRP building blocks, and a stateful
// pair-setup client shaped for the RPPairing "Pair-Setup" handshake.
// ---------------------------------------------------------------------------

/** The G_3072 prime N as a bigint (RFC 5054 3072-bit prime). */
export const SRP_GROUP_N: bigint = N;

/** The G_3072 generator g = 5. */
export const SRP_GROUP_G: bigint = G;

/** k = H(N || PAD(g)), with g left-padded to the 384-byte N length. */
export function srpK(): bigint {
  return computeK();
}

/** u = H(A || B) over the raw ephemeral bytes. */
export function srpU(A: Uint8Array, B: Uint8Array): bigint {
  return computeU(A, B);
}

/**
 * x = H(salt || H(username || ":" || password)).
 * Matches idevice-srp's compute_identity_hash + compute_x.
 */
export function srpX(salt: Uint8Array, username: string, password: Uint8Array): bigint {
  const identityHash = computeIdentityHash(toBytes(username), password);
  return computeX(identityHash, salt);
}

export interface SrpPairSetupProof {
  /** M1 client proof (64 bytes, SHA-512). */
  M1: Uint8Array;
  /** K session key = SHA-512(S) (64 bytes). */
  sessionKey: Uint8Array;
}

/**
 * Stateful SRP client for the Remote Pairing "Pair-Setup" handshake
 * (username "Pair-Setup", 6-digit PIN as password).
 *
 * Thin wrapper over {@link SrpClient} that keeps the username/password/salt
 * and the client private ephemeral between the two handshake steps:
 * `generateA()` -> send A -> `computeM1(B)` -> `verifyM2(M2, M1)`.
 */
export class SrpPairSetupClient {
  private readonly inner = new SrpClient();
  private readonly username: string;
  private readonly password: Uint8Array;
  private readonly salt: Uint8Array;
  private a: Uint8Array | null = null;
  private verifier: SrpVerifier | null = null;

  constructor(username: string, password: Uint8Array, salt: Uint8Array) {
    this.username = username;
    this.password = password;
    this.salt = salt;
  }

  /**
   * Generate the private ephemeral `a` (32 random bytes, like idevice) and
   * return A = g^a mod N (raw big-endian bytes, leading zeros stripped).
   */
  generateA(): Uint8Array {
    this.a = randomBytes(32);
    this.verifier = null;
    return this.inner.computePublicEphemeral(this.a);
  }

  /** Deterministic variant of generateA for tests. */
  generateAFromSecret(a: Uint8Array): Uint8Array {
    this.a = a.slice();
    this.verifier = null;
    return this.inner.computePublicEphemeral(this.a);
  }

  /**
   * Process the server reply B: S = (B - k*g^x)^(a + u*x) mod N, K = H(S),
   * and the client proof M1. Throws on a malicious B (B mod N == 0).
   */
  computeM1(B: Uint8Array): SrpPairSetupProof {
    if (!this.a) {
      throw new Error('srp: generateA() must be called before computeM1()');
    }
    this.verifier = this.inner.processReply(
      this.a,
      this.username,
      this.password,
      this.salt,
      B,
    );
    return { M1: this.verifier.proof(), sessionKey: this.verifier.key() };
  }

  /**
   * Verify the server proof M2 = H(A || M1 || K) with a constant-time
   * comparison. `M1` must be the proof returned by computeM1; a mismatching
   * M1 is rejected as well.
   */
  verifyM2(M2: Uint8Array, M1: Uint8Array): boolean {
    if (!this.verifier) {
      throw new Error('srp: computeM1() must be called before verifyM2()');
    }
    if (!constantTimeEqual(M1, this.verifier.proof())) {
      return false;
    }
    return this.verifier.verifyServer(M2);
  }
}
