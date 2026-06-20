// pm2 process file for the served kernel: identity, vault, bus.
// Each service binds 127.0.0.1 on its own port (set in the env file); Caddy
// terminates TLS and reverse-proxies in. Secrets live ONLY in KERNEL_ENV_FILE
// (a 0600 host file) — never in this file or in `pm2 save`'s dump.
//
//   KERNEL_ENV_FILE   path to the 0600 env file (required)
//   KERNEL_REPO_DIR   repo checkout root (default: this file's parent dir)
//
// Usage: pm2 start deploy/ecosystem.config.js

const path = require('path');

const repoDir = process.env.KERNEL_REPO_DIR || path.resolve(__dirname, '..');
const envFile = process.env.KERNEL_ENV_FILE || path.join(__dirname, '.env');
const runner = path.join(__dirname, 'run-service.sh');

function service(name) {
  return {
    name: `kernel-${name}`,
    script: runner,
    args: name,
    interpreter: 'bash',
    cwd: repoDir,
    autorestart: true,
    max_restarts: 10,
    restart_delay: 2000,
    // run-service.sh sources KERNEL_ENV_FILE itself; we only pass the pointer so
    // no secret value is ever materialised into pm2's process table.
    env: { KERNEL_ENV_FILE: envFile },
  };
}

module.exports = {
  apps: [service('identity'), service('vault'), service('bus')],
};
