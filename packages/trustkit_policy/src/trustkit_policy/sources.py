"""Bundle transport (ADR-0022 §7). The signature makes the transport untrusted."""

from __future__ import annotations

import os
import pathlib
import tempfile
from typing import Protocol

from trustkit_policy.bundle import MAX_BUNDLE_BYTES


class BundleSourceError(Exception):
    """The source exists but could not be read."""


class BundleSink(Protocol):
    def publish(self, data: bytes) -> None: ...


class BundleSource(Protocol):
    def fetch(self) -> bytes | None:
        """The raw bundle, ``None`` if absent; raises ``BundleSourceError`` if unreadable."""


class FileBundleSink:
    """Atomic: write a temp file in the same directory, fsync, then rename."""

    def __init__(self, directory: pathlib.Path, name: str = "bundle.jws") -> None:
        self._dir, self._name = directory, name

    def publish(self, data: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=".bundle-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)  # readers are other (read-only) containers
            os.replace(tmp, self._dir / self._name)
        except BaseException:
            pathlib.Path(tmp).unlink(missing_ok=True)
            raise


class FileBundleSource:
    def __init__(self, path: pathlib.Path) -> None:
        self._path = path

    def fetch(self) -> bytes | None:
        """``None`` if missing; reads at most ``MAX_BUNDLE_BYTES + 1`` bytes."""
        try:
            with self._path.open("rb") as f:
                return f.read(MAX_BUNDLE_BYTES + 1)
        except FileNotFoundError:
            return None
        except OSError:
            raise BundleSourceError("bundle file unreadable") from None
