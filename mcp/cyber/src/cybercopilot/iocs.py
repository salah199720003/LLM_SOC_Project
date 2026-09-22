from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .schemas import EvidenceRef, Observable

HASH_RE = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
IP_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f:.]{3,45})(?![A-Za-z0-9])")


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_strings(item)


def _normalize_url(value: str) -> str:
    value = value.rstrip(".,;:!?)\"]}")
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, ""))


def _observable_id(*, case_id: str, kind: str, normalized: str, evidence_ref: EvidenceRef | None) -> str:
    provenance = ""
    if evidence_ref is not None:
        provenance = "\x1f".join([evidence_ref.artifact_id, evidence_ref.event_id or "", evidence_ref.locator or "", evidence_ref.sha256 or ""])
    material = "\x1f".join([case_id, kind, normalized, provenance]).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    return f"obs-{digest[:24]}"


def extract_iocs(*, case_id: str, payload: Any, evidence_ref: EvidenceRef | None = None, include_private_ips: bool = True) -> list[Observable]:
    """Extract syntactic observables only; this function does not claim maliciousness."""
    seen: set[tuple[str, str]] = set()
    results: list[Observable] = []
    refs = [evidence_ref] if evidence_ref else []

    def add(kind: str, raw: str, normalized: str, internal: bool | None = None) -> None:
        key = (kind, normalized)
        if key in seen:
            return
        seen.add(key)
        results.append(Observable(observable_id=_observable_id(case_id=case_id, kind=kind, normalized=normalized, evidence_ref=evidence_ref), case_id=case_id, type=kind, value=raw, normalized_value=normalized, internal=internal, evidence_refs=refs))

    for text in _walk_strings(payload):
        for match in HASH_RE.finditer(text):
            raw = match.group(1)
            length_to_kind = {32: "md5", 40: "sha1", 64: "sha256"}
            add(length_to_kind[len(raw)], raw, raw.lower())
        url_spans: list[tuple[int, int]] = []
        for match in URL_RE.finditer(text):
            raw = match.group(0)
            normalized = _normalize_url(raw)
            url_spans.append(match.span())
            add("url", raw, normalized)
            host = urlsplit(normalized).hostname
            if host:
                try:
                    ip = ipaddress.ip_address(host)
                    if include_private_ips or not ip.is_private:
                        add("ipv4" if ip.version == 4 else "ipv6", host, ip.compressed, ip.is_private)
                except ValueError:
                    add("domain", host, host.lower().rstrip("."))
        for match in IP_CANDIDATE_RE.finditer(text):
            raw = match.group(0).strip("[](){}<>,;\"'")
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if include_private_ips or not ip.is_private:
                add("ipv4" if ip.version == 4 else "ipv6", raw, ip.compressed, ip.is_private)
        for match in DOMAIN_RE.finditer(text):
            if any(start <= match.start() < end for start, end in url_spans):
                continue
            raw = match.group(0).rstrip(".")
            try:
                ipaddress.ip_address(raw)
                continue
            except ValueError:
                pass
            add("domain", raw, raw.lower())
    return results
