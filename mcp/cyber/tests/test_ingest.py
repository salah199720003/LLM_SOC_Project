import hashlib

import pytest

from cybercopilot.evidence.ingest import (
    EvidencePathError,
    EvidenceTooLargeError,
    ingest_evidence,
)


def test_ingest_hashes_and_is_deterministic(tmp_path):
    root = tmp_path / "project"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)

    sample = evidence / "sample.xml"
    content = b"<Event>test</Event>"
    sample.write_bytes(content)

    first = ingest_evidence(
        case_id="case-1",
        project_root=root,
        requested_path="evidence/sample.xml",
    )

    second = ingest_evidence(
        case_id="case-1",
        project_root=root,
        requested_path="evidence/sample.xml",
    )

    assert first.artifact_id == second.artifact_id
    assert first.sha256 == hashlib.sha256(
        content
    ).hexdigest()

    assert first.path == "evidence/sample.xml"
    assert first.kind == "xml"
    assert first.size_bytes == len(content)
    assert first.read_only is True


def test_ingest_rejects_path_escape(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    outside = tmp_path / "outside.txt"
    outside.write_text("secret")

    with pytest.raises(
        EvidencePathError,
        match="outside",
    ):
        ingest_evidence(
            case_id="case-1",
            project_root=root,
            requested_path="../outside.txt",
        )


def test_ingest_rejects_oversized_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    sample = root / "large.bin"
    sample.write_bytes(b"A" * 100)

    with pytest.raises(EvidenceTooLargeError):
        ingest_evidence(
            case_id="case-1",
            project_root=root,
            requested_path="large.bin",
            max_size_bytes=50,
        )