.PHONY: test dry-run

# Full test suite (includes the deploy dry-run).
test:
	uv run pytest -q

# Local served-kernel dry-run: boots identity + vault + bus on loopback and runs
# the kernel-integration smoke end to end. No VPS, no live Fortnox.
dry-run:
	uv run python -m deploy.dryrun
