# Soak Runbook

This document covers the local-loopback soak: the identity service, the bus bridge, and provisioning the Telegram connector to publish messages to the soak observation vault.

## Generate the signing seed

Generate a 32-byte hex string for `KERNEL_SIGNING_SEED`:

```bash
openssl rand -hex 32
```

Export it to your shell:

```bash
export KERNEL_SIGNING_SEED=<hex string>
```

Or source it from a 0600-mode env file before starting pm2.

## Boot the identity service and bridge

Start both pm2 apps:

```bash
pm2 start deploy/soak.ecosystem.cjs
```

The `soak-identity` app should start cleanly. The `soak-bus-bridge` app will fail to start until provisioned—this is expected; ignore the error for now.

## Provision a soak principal

Provision the bus bridge with a principal grant. Run the provisioning script from the islands-kernel root:

```bash
KERNEL_IDENTITY_DB=./vault-store/identity.sqlite python -m deploy.soak_provision --org org_caput --granted-by prn_owner
```

This prints a credential string. Save it—you will use it to configure the connector.

## Export the principal map

The principal map is a JSON array that maps Telegram user IDs to their soak principal identity and organization. Create a shell variable:

```bash
export SOAK_PRINCIPAL_MAP='[
  {
    "telegram_user_id": <real Telegram user ID from TELEGRAM_ALLOWED_USER_IDS>,
    "principal": "<principal from provisioning output>",
    "org": "org_caput"
  }
]'
```

Restart the bus bridge to apply the principal map:

```bash
pm2 restart soak-bus-bridge
```

## Configure and restart the connector

In `telegram-capture/.env`, set:

```
CONNECTOR_BUS_PUBLISH=true
CONNECTOR_BUS_URL=http://127.0.0.1:8083
CONNECTOR_IDENTITY_URL=http://127.0.0.1:8081
CONNECTOR_CREDENTIAL=<credential from provisioning>
```

Then restart the bot:

```bash
pm2 restart telegram-capture
```

## Verify the soak is working

Send a Telegram message to the bot. Verify:

1. The bot replies as it did before (dispatch is unchanged throughout).
2. A line appears in `soak.log` (the bridge writes observations).
3. A file appears under `soak-observation-vault/raw/inbox/` (structured vault ingest).

## Stop the soak

To stop observing messages, set:

```
CONNECTOR_BUS_PUBLISH=false
```

Restart the bot:

```bash
pm2 restart telegram-capture
```

Clean up the pm2 services:

```bash
pm2 delete soak-identity soak-bus-bridge
```

## Observability Notes

The soak tap sits only on the classify-to-dispatch path. Messages handled by early-return paths—food, approval commands, `/start`, `/help`—are not published to the bus. The soak observes only messages that reach the classify-dispatch boundary, an intentional under-count.

The soak bus uses an in-memory ledger. Restarting `soak-bus-bridge` (e.g., `pm2 restart soak-bus-bridge`) drops in-flight delivery state and dedup history. Duplicate lines in `soak.log` are possible across restarts and are harmless for an observation soak.

The bot's dispatch logic is unchanged throughout the soak. The bridge writes only to the observation vault and does not alter the bot's behavior.
