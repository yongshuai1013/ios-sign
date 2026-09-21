/**
 * Ambient declarations for `bun:test`.
 *
 * The project does not install `bun-types`, so TypeScript cannot resolve the
 * `bun:test` module on its own. This file declares it ambiently (script-style
 * .d.ts, no top-level import/export — so `declare module` here is a module
 * declaration, not an augmentation, and does not trigger TS2664).
 *
 * `bun test` itself does not type-check; this only exists so `tsc --noEmit`
 * can verify the test files.
 */
declare module 'bun:test' {
  export function describe(name: string, fn: () => void): void;
  export namespace describe {
    function skip(name: string, fn: () => void): void;
    function skipIf(condition: boolean, name: string, fn: () => void): void;
  }
  export function test(name: string, fn: () => void | Promise<void>, timeoutMs?: number): void;
  export namespace test {
    function skip(name: string, fn: () => void | Promise<void>): void;
    function skipIf(condition: boolean, name: string, fn: () => void | Promise<void>, timeoutMs?: number): void;
  }
  export function beforeEach(fn: () => void | Promise<void>): void;
  export function afterEach(fn: () => void | Promise<void>): void;
  /** Matches bun's toThrow matcher: message/regex or an error constructor. */
  export type ThrowMatcher = RegExp | string | (new (...args: never[]) => Error);
  /** Async variants of every matcher, as returned by expect().resolves/rejects. */
  export interface AsyncMatchers {
    toBe(expected: unknown): Promise<void>;
    toEqual(expected: unknown): Promise<void>;
    toBeNull(): Promise<void>;
    toBeUndefined(): Promise<void>;
    toBeTruthy(): Promise<void>;
    toBeFalsy(): Promise<void>;
    toBeInstanceOf(expected: unknown): Promise<void>;
    toContain(item: unknown): Promise<void>;
    toMatch(matcher: RegExp | string): Promise<void>;
    toMatchObject(expected: unknown): Promise<void>;
    toThrow(matcher?: ThrowMatcher): Promise<void>;
    toBeGreaterThan(n: number): Promise<void>;
    toBeGreaterThanOrEqual(n: number): Promise<void>;
    toBeLessThan(n: number): Promise<void>;
    toBeLessThanOrEqual(n: number): Promise<void>;
    not: AsyncMatchers;
  }
  export interface Matchers {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toBeNull(): void;
    toBeUndefined(): void;
    toBeTruthy(): void;
    toBeFalsy(): void;
    toBeInstanceOf(expected: unknown): void;
    toContain(item: unknown): void;
    toMatch(matcher: RegExp | string): void;
    toMatchObject(expected: unknown): void;
    toThrow(matcher?: ThrowMatcher): void;
    toBeGreaterThan(n: number): void;
    toBeGreaterThanOrEqual(n: number): void;
    toBeLessThan(n: number): void;
    toBeLessThanOrEqual(n: number): void;
    not: Matchers;
    resolves: AsyncMatchers;
    rejects: AsyncMatchers;
  }
  export function expect(actual: unknown): Matchers;
}
