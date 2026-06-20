import { describe, it, expect } from "vitest";
import { publish, subscribe } from "../src/bus";

function fakeFetch(capture: any) {
  return async (url: string, init: any) => {
    capture.url = url;
    capture.init = init;
    capture.body = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ id: "evt_1", deduped: false }) } as any;
  };
}

describe("bus lib", () => {
  it("publish posts the envelope with a bearer and returns the result", async () => {
    const cap: any = {};
    const res = await publish({
      baseUrl: "http://bus.local", bearer: "JWT", type: "bookkeeping.voucher.posted",
      data: { voucherId: "V-1" }, source: "bookkeeping", schema: "voucher/v1",
      trace: { store: "bk", ref: "r1" }, fetchImpl: fakeFetch(cap),
    });
    expect(res).toEqual({ id: "evt_1", deduped: false });
    expect(cap.url).toBe("http://bus.local/events");
    expect(cap.init.headers.Authorization).toBe("Bearer JWT");
    expect(cap.body.type).toBe("bookkeeping.voucher.posted");
    expect(cap.body.trace.ref).toBe("r1");
  });

  it("subscribe posts type/consumer/target", async () => {
    const cap: any = {};
    const fetchImpl = async (url: string, init: any) => {
      cap.url = url; cap.body = JSON.parse(init.body);
      return { ok: true, status: 200, json: async () => ({ id: "sub_1" }) } as any;
    };
    const res = await subscribe({
      baseUrl: "http://bus.local", bearer: "JWT", type: "bookkeeping.voucher.posted",
      consumer: "smartcharge", target: { kind: "http", url: "http://x/events", audience: "smartcharge" },
      grantRef: "g", fetchImpl,
    });
    expect(res.id).toBe("sub_1");
    expect(cap.url).toBe("http://bus.local/subscriptions");
    expect(cap.body.consumer).toBe("smartcharge");
  });
});
