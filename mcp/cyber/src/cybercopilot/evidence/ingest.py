from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cybercopilot.schemas import EvidenceArtifact


DEFAULT_MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
_HASH_CHUNK_SIZE = 1024 * 1024


class EvidenceIngestError(ValueError):
    """Base error for deterministic evidence ingestion."""


class EvidencePathError(EvidenceIngestError):
    """Raised when an evidence path violates path policy."""


class EvidenceTooLargeError(EvidenceIngestError):
    """Raised when evidence exceeds the configured size limit."""


class EvidenceChangedError(EvidenceIngestError):
    """Raised when a file changes while it is being ingested."""


def _is_within(root: Path, candidate: Path) -> bool:
    root_text = os.path.normcase(str(root))
    candidate_text = os.path.normcase(str(candidate))

    try:
        common = os.path.commonpath(
            [root_text, candidate_text]
        )
    except ValueError:
        return False

    return common == root_text


def _is_junction(path: Path) -> bool:
    checker = getattr(os.path, "isjunction", None)

    if checker is None:
        return False

    try:
        return bool(checker(path))
    except OSError:
        return False


def _reject_reparse_points(
    root: Path,
    lexical_path: Path,
) -> None:
    try:
        relative = lexical_path.relative_to(root)
    except ValueError as exc:
        raise EvidencePathError(
            "evidence path is outside the allowed root"
        ) from exc

    cursor = root

    for part in relative.parts:
        cursor = cursor / part

        if cursor.is_symlink():
            raise EvidencePathError(
                f"symbolic links are not allowed: {cursor}"
            )

        if _is_junction(cursor):
            raise EvidencePathError(
                f"junctions are not allowed: {cursor}"
            )


def resolve_evidence_path(
    *,
    project_root: str | Path,
    requested_path: str | Path,
) -> tuple[Path, Path]:
    """
    Resolve an evidence path safely.

    Returns:
        (resolved_absolute_path, project_relative_path)
    """

    root = Path(project_root).expanduser().resolve(
        strict=True
    )

    if not root.is_dir():
        raise EvidencePathError(
            "project_root must be a directory"
        )

    requested = Path(requested_path).expanduser()

    if requested.is_absolute():
        lexical = Path(
            os.path.abspath(str(requested))
        )
    else:
        lexical = Path(
            os.path.abspath(str(root / requested))
        )

    if not _is_within(root, lexical):
        raise EvidencePathError(
            "evidence path is outside the allowed root"
        )

    _reject_reparse_points(
        root,
        lexical,
    )

    try:
        resolved = lexical.resolve(strict=True)
    except FileNotFoundError as exc:
        raise EvidencePathError(
            f"evidence file does not exist: {requested_path}"
        ) from exc

    if not _is_within(root, resolved):
        raise EvidencePathError(
            "resolved evidence path escapes the allowed root"
        )

    if not resolved.is_file():
        raise EvidencePathError(
            "evidence path must reference a regular file"
        )

    relative = resolved.relative_to(root)

    return resolved, relative


def _artifact_id(
    *,
    case_id: str,
    relative_path: Path,
    sha256: str,
) -> str:
    normalized_path = relative_path.as_posix()

    if os.name == "nt":
        normalized_path = normalized_path.casefold()

    material = (
        case_id
        + "\x1f"
        + normalized_path
        + "\x1f"
        + sha256
    ).encode("utf-8")

    digest = hashlib.sha256(material).hexdigest()

    return f"art-{digest[:24]}"


def ingest_evidence(
    *,
    case_id: str,
    project_root: str | Path,
    requested_path: str | Path,
    max_size_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> EvidenceArtifact:
    """
    Register one existing file as read-only evidence.

    This function does NOT:
    - execute the file
    - parse the file
    - classify it as malicious
    - modify the file
    - follow symlinks or junctions
    """

    if max_size_bytes <= 0:
        raise ValueError(
            "max_size_bytes must be greater than zero"
        )

    resolved, relative = resolve_evidence_path(
        project_root=project_root,
        requested_path=requested_path,
    )

    initial_stat = resolved.stat()

    if initial_stat.st_size > max_size_bytes:
        raise EvidenceTooLargeError(
            "evidence exceeds configured size limit"
        )

    digest = hashlib.sha256()
    bytes_read = 0

    with resolved.open("rb") as handle:
        before = os.fstat(handle.fileno())

        if before.st_size > max_size_bytes:
            raise EvidenceTooLargeError(
                "evidence exceeds configured size limit"
            )

        while True:
            chunk = handle.read(_HASH_CHUNK_SIZE)

            if not chunk:
                break

            bytes_read += len(chunk)

            if bytes_read > max_size_bytes:
                raise EvidenceTooLargeError(
                    "evidence exceeded size limit "
                    "while being read"
                )

            digest.update(chunk)

        after = os.fstat(handle.fileno())

    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or bytes_read != after.st_size
    ):
        raise EvidenceChangedError(
            "evidence changed while being ingested"
        )

    sha256 = digest.hexdigest()

    suffix = relative.suffix.lower().lstrip(".")
    kind = suffix or "file"

    return EvidenceArtifact(
        artifact_id=_artifact_id(
            case_id=case_id,
            relative_path=relative,
            sha256=sha256,
        ),
        case_id=case_id,
        kind=kind,
        path=relative.as_posix(),
        sha256=sha256,
        size_bytes=bytes_read,
        read_only=True,
    )