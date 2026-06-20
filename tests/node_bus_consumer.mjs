// Node consumer: serve an HTTP endpoint that receives a pushed envelope and prints its voucherId.
import http from "node:http";
const server = http.createServer((req, res) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => {
    res.writeHead(202).end();
    try {
      const env = JSON.parse(data);
      process.stdout.write(`${env.data.voucherId}\n`);
    } catch {
      process.stdout.write("PARSE_ERROR\n");
    }
  });
});
server.listen(0, "127.0.0.1", () => {
  process.stdout.write(`${server.address().port}\n`);   // first line = the port
});
