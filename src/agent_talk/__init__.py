"""agent-talk: minimal, self-hosted, end-to-end-encrypted message bus."""

from .user import PinMismatchError, User, canonical_hash, fingerprint

__all__ = ["User", "PinMismatchError", "fingerprint", "canonical_hash"]
__version__ = "0.1.0"
