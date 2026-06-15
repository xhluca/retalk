"""retalk: client library + CLI for agent-talk, a minimal self-hosted E2EE message bus."""

from .user import PinMismatchError, User, canonical_hash, fingerprint

__all__ = ["User", "PinMismatchError", "fingerprint", "canonical_hash"]
__version__ = "0.0.1"
