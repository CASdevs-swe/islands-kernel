import { jwtVerify, importJWK, type JSONWebKeySet, type JWTPayload } from "jose";

export interface VerifyOpts {
  jwks: JSONWebKeySet;
  audience: string;
  issuer?: string;
  now?: number; // seconds; defaults to current time
}

export async function verifyIslandJwt(token: string, opts: VerifyOpts): Promise<JWTPayload> {
  const getKey = async (header: { kid?: string; alg?: string }) => {
    const jwk = opts.jwks.keys.find((k) => (k as any).kid === header.kid);
    if (!jwk) throw new Error(`no JWK for kid=${header.kid}`);
    return importJWK(jwk, "EdDSA");
  };
  const { payload } = await jwtVerify(token, getKey, {
    audience: opts.audience,
    issuer: opts.issuer,
    algorithms: ["EdDSA"],
    currentDate: opts.now !== undefined ? new Date(opts.now * 1000) : undefined,
  });
  return payload;
}

export async function fetchJwks(
  url: string,
  fetchImpl: typeof fetch = fetch,
): Promise<JSONWebKeySet> {
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
  return (await res.json()) as JSONWebKeySet;
}
