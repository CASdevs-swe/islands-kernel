export interface EventEnvelope {
  id: string;
  type: string;
  schema: string;
  source: string;
  org: string;
  principal: string;
  occurredAt: string;
  trace: { store: string; ref: string };
  data: Record<string, unknown>;
}

export interface PublishArgs {
  baseUrl: string;
  bearer: string;
  type: string;
  data: Record<string, unknown>;
  source: string;
  schema: string;
  trace: { store: string; ref: string };
  occurredAt?: string;
  id?: string;
  fetchImpl?: typeof fetch;
}

async function postJson(url: string, bearer: string, body: unknown, fetchImpl?: typeof fetch) {
  const f = fetchImpl ?? fetch;
  const res = await f(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`bus call failed: HTTP ${res.status}`);
  return res.json();
}

export async function publish(args: PublishArgs): Promise<{ id: string; deduped: boolean }> {
  const body: Record<string, unknown> = {
    type: args.type, data: args.data, source: args.source, schema: args.schema, trace: args.trace,
  };
  if (args.occurredAt) body.occurredAt = args.occurredAt;
  if (args.id) body.id = args.id;
  return postJson(`${args.baseUrl}/events`, args.bearer, body, args.fetchImpl);
}

export async function subscribe(args: {
  baseUrl: string; bearer: string; type: string; consumer: string;
  target: Record<string, unknown>; grantRef: string; fetchImpl?: typeof fetch;
}): Promise<{ id: string }> {
  return postJson(`${args.baseUrl}/subscriptions`, args.bearer,
    { type: args.type, consumer: args.consumer, target: args.target, grant_ref: args.grantRef },
    args.fetchImpl);
}

export async function replayDeadLetter(args: {
  baseUrl: string; bearer: string; eventId: string; source: string; fetchImpl?: typeof fetch;
}): Promise<{ replayed: number }> {
  const url = `${args.baseUrl}/deadletter/${encodeURIComponent(args.eventId)}/replay`
    + `?source=${encodeURIComponent(args.source)}`;
  return postJson(url, args.bearer, {}, args.fetchImpl);
}
