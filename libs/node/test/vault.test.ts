import { describe, it, expect } from "vitest";
import { getAccessToken } from "../src/index";

describe("getAccessToken", () => {
  it("posts to access-token and returns the token, never the refresh", async () => {
    let calledUrl = "";
    const fakeFetch = async (url: string, opts: any) => {
      calledUrl = url;
      expect(opts.headers["X-Principal"]).toBe("owner");
      return { ok: true, json: async () => ({ accessToken: "ACCESS", scope: "bk", expiresAt: 1 }) } as any;
    };
    const tok = await getAccessToken({
      org: "caput-venti", provider: "fortnox", account: "559401-5157",
      baseUrl: "http://localhost:8000", principal: "owner", island: "bk", fetchImpl: fakeFetch as any,
    });
    expect(tok).toBe("ACCESS");
    expect(calledUrl).toContain("/connections/caput-venti%2Ffortnox%2F559401-5157/access-token");
  });
});
