// Local-loopback soak: identity + the bus/bridge soak boot. Start with:
//   pm2 start deploy/soak.ecosystem.cjs
// Secrets (KERNEL_SIGNING_SEED, SOAK_PRINCIPAL_MAP) come from the shell env / a
// 0600 env file sourced before start — never commit them.
const path = require("path");
const REPO = __dirname.replace(/\/deploy$/, "");
const PY = process.env.SOAK_PYTHON || "python";
module.exports = {
  apps: [
    {
      name: "soak-identity",
      cwd: REPO,
      script: PY,
      args: "-m uvicorn identity.app:app --host 127.0.0.1 --port 8081 --log-level warning",
      env: {
        IDENTITY_BOOT: "1",
        KERNEL_ISSUER: "http://127.0.0.1:8081",
        KERNEL_JWKS_URL: "http://127.0.0.1:8081/.well-known/jwks.json",
        KERNEL_KID: "kid-1",
        KERNEL_IDENTITY_DB: path.join(REPO, "vault-store", "identity.sqlite"),
        // KERNEL_SIGNING_SEED supplied from the shell env (0600), not here.
      },
    },
    {
      name: "soak-bus-bridge",
      cwd: REPO,
      script: PY,
      args: "-m uvicorn deploy.soak_boot:app --host 127.0.0.1 --port 8083 --log-level warning",
      env: {
        SOAK_BOOT: "1",
        BUS_AUDIENCE: "bus",
        KERNEL_ISSUER: "http://127.0.0.1:8081",
        KERNEL_JWKS_URL: "http://127.0.0.1:8081/.well-known/jwks.json",
        KERNEL_IDENTITY_DB: path.join(REPO, "vault-store", "identity.sqlite"),
        SOAK_ORG: "org_caput",
        SOAK_OBSERVATION_VAULT: path.join(REPO, "soak-observation-vault"),
        SOAK_LOG: path.join(REPO, "soak.log"),
        SOAK_ROUTE_MJS: path.join(REPO, "..", "cloud-hub", "skills", "capture-route", "scripts", "route.mjs"),
        // SOAK_PRINCIPAL_MAP supplied from the shell env (JSON, contains the real Telegram id).
      },
    },
  ],
};
