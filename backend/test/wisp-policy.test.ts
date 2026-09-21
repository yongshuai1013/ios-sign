import { describe, expect, test } from "bun:test";
import {
  isAllowedHost,
  isValidToken,
  isWispPath,
  isWispRoute,
  sha256Hex,
  timingSafeEqual,
} from "../src/wisp-policy";

describe("isAllowedHost", () => {
  const allowed = [
    "auth.itunes.apple.com",
    "buy.itunes.apple.com",
    "init.itunes.apple.com",
    "p1-buy.itunes.apple.com",
    "p42-buy.itunes.apple.com",
    "p12345-buy.itunes.apple.com",
    "gsa.apple.com",
    "developerservices2.apple.com",
  ];

  for (const host of allowed) {
    test(`allows ${host}:443`, () => {
      expect(isAllowedHost(host, 443)).toBe(true);
    });
  }

  test("normalizes case and trailing dot", () => {
    expect(isAllowedHost("GSA.Apple.COM.", 443)).toBe(true);
    expect(isAllowedHost("  auth.itunes.apple.com  ", 443)).toBe(true);
  });

  test("rejects non-443 ports", () => {
    expect(isAllowedHost("gsa.apple.com", 80)).toBe(false);
    expect(isAllowedHost("gsa.apple.com", 8443)).toBe(false);
    expect(isAllowedHost("gsa.apple.com", 0)).toBe(false);
  });

  test("rejects hosts outside the allowlist", () => {
    expect(isAllowedHost("apple.com", 443)).toBe(false);
    expect(isAllowedHost("itunes.apple.com", 443)).toBe(false);
    expect(isAllowedHost("evil-auth.itunes.apple.com", 443)).toBe(false);
    expect(isAllowedHost("auth.itunes.apple.com.evil.com", 443)).toBe(false);
    expect(isAllowedHost("p-buy.itunes.apple.com", 443)).toBe(false);
    expect(isAllowedHost("pa-buy.itunes.apple.com", 443)).toBe(false);
    expect(isAllowedHost("p1x-buy.itunes.apple.com", 443)).toBe(false);
    expect(isAllowedHost("developerservices3.apple.com", 443)).toBe(false);
  });

  test("rejects IP literals (SSRF)", () => {
    expect(isAllowedHost("127.0.0.1", 443)).toBe(false);
    expect(isAllowedHost("17.253.144.10", 443)).toBe(false);
    expect(isAllowedHost("10.0.0.1", 443)).toBe(false);
    expect(isAllowedHost("::1", 443)).toBe(false);
    expect(isAllowedHost("2001:db8::1", 443)).toBe(false);
  });

  test("rejects empty host", () => {
    expect(isAllowedHost("", 443)).toBe(false);
    expect(isAllowedHost("   ", 443)).toBe(false);
  });
});

describe("timingSafeEqual", () => {
  test("equal strings", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("", "")).toBe(true);
  });
  test("different content", () => {
    expect(timingSafeEqual("abc", "abd")).toBe(false);
  });
  test("different length", () => {
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
    expect(timingSafeEqual("", "x")).toBe(false);
  });
  test("unicode", () => {
    expect(timingSafeEqual("密碼🔑", "密碼🔑")).toBe(true);
    expect(timingSafeEqual("密碼🔑", "密碼🔒")).toBe(false);
  });
});

describe("isValidToken", () => {
  test("accepts the configured hash directly", async () => {
    const hash = await sha256Hex("super-secret");
    // With ACCESS_PASSWORD set, the client supplies the SHA-256 hex of it.
    expect(await isValidToken(hash, { ACCESS_PASSWORD: "super-secret" })).toBe(true);
    expect(await isValidToken(hash, { ACCESS_TOKEN_HASH: hash })).toBe(true);
  });

  test("rejects wrong tokens", async () => {
    const hash = await sha256Hex("super-secret");
    expect(await isValidToken("wrong", { ACCESS_TOKEN_HASH: hash })).toBe(false);
    expect(await isValidToken("", { ACCESS_TOKEN_HASH: hash })).toBe(false);
    expect(await isValidToken(null, { ACCESS_TOKEN_HASH: hash })).toBe(false);
  });

  test("hash config takes precedence over password", async () => {
    const hash = await sha256Hex("from-hash");
    const env = { ACCESS_TOKEN_HASH: hash, ACCESS_PASSWORD: "from-password" };
    expect(await isValidToken(hash, env)).toBe(true);
    expect(
      await isValidToken(await sha256Hex("from-password"), env),
    ).toBe(false);
  });

  test("strips trailing slashes from the supplied token", async () => {
    const hash = await sha256Hex("abc");
    expect(await isValidToken(`${hash}///`, { ACCESS_TOKEN_HASH: hash })).toBe(true);
  });

  test("public when nothing is configured", async () => {
    expect(await isValidToken(null, {})).toBe(true);
    expect(await isValidToken("anything", {})).toBe(true);
    expect(
      await isValidToken(null, { ACCESS_TOKEN_HASH: "  ", ACCESS_PASSWORD: "" }),
    ).toBe(true);
  });

  test("constant-time: correct-length wrong token is rejected", async () => {
    const hash = await sha256Hex("correct horse");
    const wrong = "x".repeat(hash.length);
    expect(hash.length).toBe(wrong.length);
    expect(await isValidToken(wrong, { ACCESS_TOKEN_HASH: hash })).toBe(false);
  });
});

describe("wisp path checks", () => {
  test("isWispRoute", () => {
    expect(isWispRoute("/wisp/")).toBe(true);
    expect(isWispRoute("/wisp")).toBe(true);
    // "/wispx" still enters the WISP branch (startsWith "/wisp") and is
    // then rejected by isWispPath with a 404 instead of hitting ASSETS.
    expect(isWispRoute("/wispx")).toBe(true);
    expect(isWispRoute("/")).toBe(false);
    expect(isWispRoute("/healthz")).toBe(false);
  });

  test("isWispPath requires exactly /wisp/", () => {
    expect(isWispPath("/wisp/")).toBe(true);
    expect(isWispPath("/wisp")).toBe(false);
    expect(isWispPath("/wisp/extra")).toBe(false);
    expect(isWispPath("/wisp/extra/")).toBe(false);
    expect(isWispPath("/")).toBe(false);
    expect(isWispPath("/healthz")).toBe(false);
    expect(isWispPath("/wispx/")).toBe(false);
  });
});
