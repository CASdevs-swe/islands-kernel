export interface VaultAccess {
  accessToken: string;
  scope: string;
  expiresAt: number;
}

export interface AccessArgs {
  org: string;
  provider: string;
  account: string;
  baseUrl: string;
  principal?: string;
  island?: string;
  fetchImpl?: typeof fetch;
}

export async function getAccess(args: AccessArgs): Promise<VaultAccess> {
  const f = args.fetchImpl ?? fetch;
  const cid = encodeURIComponent(`${args.org}/${args.provider}/${args.account}`);
  const res = await f(`${args.baseUrl.replace(/\/$/, "")}/connections/${cid}/access-token`, {
    method: "POST",
    headers: {
      "X-Principal": args.principal ?? "stub",
      "X-Island": args.island ?? "unknown",
    },
  });
  if (!res.ok) throw new Error(`vault access-token failed: ${res.status}`);
  return (await res.json()) as VaultAccess;
}

export async function getAccessToken(args: AccessArgs): Promise<string> {
  return (await getAccess(args)).accessToken;
}
