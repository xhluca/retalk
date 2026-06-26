"""retalk: a minimal, self-hosted, end-to-end-encrypted message bus (client library + CLI)."""

from .user import PinMismatchError, User, canonical_hash, fingerprint

__all__ = ["User", "PinMismatchError", "fingerprint", "canonical_hash"]
__version__ = "0.0.4"
