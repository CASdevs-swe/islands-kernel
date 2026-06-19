"""Island-facing verify surface. Islands import this, not the kernel internals.

The kernel signs; islands only verify, offline, against the published JWKS.
"""
from identity.jwt_verify import verify_island_jwt

__all__ = ["verify_island_jwt"]
