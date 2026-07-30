"""retalk: a minimal, self-hosted, end-to-end-encrypted message bus (client library + CLI)."""

from .user import PinMismatchError, User, canonical_hash, fingerprint

__all__ = ["User", "PinMismatchError", "fingerprint", "canonical_hash"]

try:                        # single source of truth: the installed metadata
    from importlib.metadata import version as _version
    __version__ = _version("retalk")
except Exception:           # uninstalled source tree
    __version__ = "0.0.0+unknown"
