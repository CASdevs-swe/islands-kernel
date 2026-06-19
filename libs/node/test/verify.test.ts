import { describe, it, expect } from "vitest";
import { generateKeyPair, SignJWT, exportJWK } from "jose";
import { verifyIslandJwt } from "../src/verify";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const jwk = await exportJWK(publicKey);
  jwk.kid = "kid-1"; jwk.alg = "EdDSA"; jwk.use = "sig";
  const jwks = { keys: [jwk] };
  const token = await new SignJWT({ org: "org_1" })
    .setProtectedHeader({ alg: "EdDSA", kid: "kid-1" })
    .setIssuer("https://id.x").setSubject("prn_1")
    .setAudience("https://mcp.x").setIssuedAt(1000).setExpirationTime(1300)
    .sign(privateKey);
  return { jwks, token };
}

describe("verifyIslandJwt", () => {
  it("verifies a valid EdDSA token offline", async () => {
    const { jwks, token } = await setup();
    const claims = await verifyIslandJwt(token, {
      jwks, audience: "https://mcp.x", issuer: "https://id.x", now: 1100,
    });
    expect(claims.sub).toBe("prn_1");
    expect(claims.org).toBe("org_1");
  });

  it("rejects a wrong audience", async () => {
    const { jwks, token } = await setup();
    await expect(verifyIslandJwt(token, {
      jwks, audience: "https://other", now: 1100,
    })).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const { jwks, token } = await setup();
    await expect(verifyIslandJwt(token, {
      jwks, audience: "https://mcp.x", now: 9999,
    })).rejects.toThrow();
  });
});

// Cross-language proof: the Python test (tests/test_cross_language.py) mints
// a token from a throwaway fixed seed and writes tests/fixtures/cross_lang/token.json.
// This test reads that same fixture and verifies the token in Node — same bytes,
// both runtimes. Run pytest tests/ first to generate the fixture.
it("verifies the cross-language golden token from the Python issuer", async () => {
  const path = resolve(__dirname, "../../../tests/fixtures/cross_lang/token.json");
  const fx = JSON.parse(readFileSync(path, "utf8"));
  const claims = await verifyIslandJwt(fx.token, {
    jwks: fx.jwks, audience: fx.audience, issuer: fx.issuer, now: fx.now,
  });
  expect(claims.sub).toBe("prn_1");
  expect(claims.org).toBe("org_1");
});
