"""The estate model file: JSON written by the app, read back only by its recorded hash.

Condition 2 of decision 3: models train in the app and live in the app's data
directory, their hash is in the audit chain, and the app never loads a model
file from outside.

The file is JSON. A joblib file, or any other serialized Python object, runs
code when it loads, so a planted one would be code execution, and nothing here
reads one. The JSON holds parameters only: the feature names, the scale, the
group centroids and medians, the drift bins and the forest settings. The
forest itself is refit each day and is not stored.

:func:`write_model` writes the file under ``<data dir>/models/estate/`` with
mode 0600 and returns its sha256. :func:`read_verified` reads a file only when
four things hold:

1. the name is a plain file name, and the path resolves inside the model
   directory;
2. the store records the name, from the fit that wrote it;
3. the sha256 of the bytes on disk is the hash the store records for it;
4. the bytes parse as a model payload of this format.

Any other file raises :class:`ModelRefused`, and the caller fits without it.

Pure Python. The loader runs, and its tests run, without the extra.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "FORMAT",
    "MODEL_SUBDIR",
    "ModelRefused",
    "foreign_files",
    "model_dir",
    "read_verified",
    "remove_model",
    "sha256_of",
    "write_model",
]

FORMAT = "soc-ai-estate-model/1"
MODEL_SUBDIR = Path("models") / "estate"


class ModelRefused(Exception):
    """A model file soc-ai will not load. The message says why, in one sentence."""


def model_dir(data_dir: Path | str) -> Path:
    """The directory the estate model files live in."""
    return Path(data_dir) / MODEL_SUBDIR


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stamp(at: datetime) -> str:
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def write_model(
    data_dir: Path | str, payload: Mapping[str, Any], *, fitted_at: datetime
) -> tuple[str, str]:
    """Write one model file. Returns the file name and the sha256 of its bytes.

    The bytes are written to a temporary name and moved into place, so a
    reader never sees half a file. The name carries the fit time and the first
    12 characters of the hash.
    """
    directory = model_dir(data_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = {"format": FORMAT, **payload}
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    digest = sha256_of(data)
    name = f"estate-{_stamp(fitted_at)}-{digest[:12]}.json"
    target = directory / name
    temporary = directory / f".{name}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, target)
    return name, digest


def _inside(directory: Path, name: str) -> Path:
    if not name or name != Path(name).name or name.startswith("."):
        raise ModelRefused(f"The name {name!r} is not a plain model file name.")
    path = directory / name
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ModelRefused(f"The model file {name} does not exist.") from exc
    if resolved.parent != directory.resolve():
        raise ModelRefused(f"The model file {name} resolves outside the model directory.")
    return resolved


def read_verified(data_dir: Path | str, name: str, recorded: Mapping[str, str]) -> dict[str, Any]:
    """Read one model file, only when the store records its name and its hash.

    ``recorded`` maps each file name a fit wrote to the sha256 the fit
    recorded (:func:`soc_ai.store.estate_model.recorded_files`).
    """
    expected = recorded.get(name)
    if not expected:
        raise ModelRefused(f"No fit on record wrote the file {name}. soc-ai does not load it.")
    path = _inside(model_dir(data_dir), name)
    data = path.read_bytes()
    actual = sha256_of(data)
    if actual != expected:
        raise ModelRefused(
            f"The file {name} has the sha256 {actual[:12]}. The fit recorded "
            f"{expected[:12]}. soc-ai does not load it."
        )
    try:
        payload = json.loads(data)
    except ValueError as exc:
        raise ModelRefused(f"The file {name} is not JSON.") from exc
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise ModelRefused(f"The file {name} is not an estate model of format {FORMAT}.")
    return payload


def foreign_files(data_dir: Path | str, recorded: Mapping[str, str]) -> list[str]:
    """The files in the model directory that no fit on record wrote."""
    directory = model_dir(data_dir)
    if not directory.is_dir():
        return []
    return sorted(
        entry.name
        for entry in directory.iterdir()
        if entry.name not in recorded and not entry.name.startswith(".")
    )


def remove_model(data_dir: Path | str, name: str) -> bool:
    """Delete one model file that a fit wrote. True when a file went."""
    try:
        path = _inside(model_dir(data_dir), name)
    except ModelRefused:
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True
