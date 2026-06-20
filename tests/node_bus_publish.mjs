// Node publisher: POST one envelope to the served bus, print the JSON result.
const [, , baseUrl, bearer] = process.argv;
const body = {
  type: "bookkeeping.voucher.posted", schema: "voucher/v1", source: "bookkeeping",
  trace: { store: "bk", ref: "r1" }, data: { voucherId: "V-1" }, id: "evt_node",
};
const res = await fetch(`${baseUrl}/events`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
  body: JSON.stringify(body),
});
if (!res.ok) {
  console.error(`HTTP ${res.status}`);
  process.exit(1);
}
process.stdout.write(JSON.stringify(await res.json()));
