from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ATTACK_INDEX_SCHEMA_VERSION = "1"
DEFAULT_DESCRIPTION_LIMIT = 2400


class AttackDatasetError(ValueError):
    """Raised when pinned ATT&CK data is missing or malformed."""


def _external_reference(
    obj: dict[str, Any],
) -> dict[str, Any] | None:
    for reference in obj.get("external_references", []):
        if (
            isinstance(reference, dict)
            and reference.get("source_name") == "mitre-attack"
            and isinstance(reference.get("external_id"), str)
        ):
            return reference

    return None


def _technique_record(
    obj: dict[str, Any],
) -> dict[str, Any] | None:
    if obj.get("type") != "attack-pattern":
        return None

    if obj.get("revoked") is True:
        return None

    if obj.get("x_mitre_deprecated") is True:
        return None

    reference = _external_reference(obj)

    if reference is None:
        return None

    attack_id = reference["external_id"].strip()

    if not attack_id.startswith("T"):
        return None

    name = obj.get("name")

    if not isinstance(name, str) or not name.strip():
        return None

    tactics = sorted(
        {
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if (
                isinstance(phase, dict)
                and phase.get("kill_chain_name") == "mitre-attack"
                and isinstance(phase.get("phase_name"), str)
            )
        }
    )

    platforms = sorted(
        {
            item
            for item in obj.get("x_mitre_platforms", [])
            if isinstance(item, str)
        }
    )

    description = obj.get("description", "")

    if not isinstance(description, str):
        description = ""

    return {
        "attack_id": attack_id,
        "stix_id": obj.get("id"),
        "name": name.strip(),
        "description": description.strip(),
        "tactics": tactics,
        "platforms": platforms,
        "is_subtechnique": bool(
            obj.get("x_mitre_is_subtechnique")
        ),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "url": reference.get("url"),
    }


def build_attack_index(
    *,
    raw_path: str | Path,
    index_path: str | Path,
    attack_version: str,
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    raw_file = Path(raw_path)
    output_file = Path(index_path)

    try:
        payload = json.loads(
            raw_file.read_text(
                encoding="utf-8-sig"
            )
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AttackDatasetError(
            f"could not read ATT&CK STIX bundle: {exc}"
        ) from exc

    objects = payload.get("objects")

    if not isinstance(objects, list):
        raise AttackDatasetError(
            "ATT&CK STIX bundle has no objects array"
        )

    techniques: list[dict[str, Any]] = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        record = _technique_record(obj)

        if record is not None:
            techniques.append(record)

    if not techniques:
        raise AttackDatasetError(
            "no active ATT&CK techniques were found"
        )

    techniques.sort(
        key=lambda item: (
            item["attack_id"],
            item["name"].casefold(),
        )
    )

    index = {
        "schema_version": ATTACK_INDEX_SCHEMA_VERSION,
        "attack_version": attack_version,
        "domain": domain,
        "technique_count": len(techniques),
        "techniques": techniques,
    }

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file.write_text(
        json.dumps(
            index,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return index


class AttackStore:
    """
    Deterministic lookup over a pinned local ATT&CK index.

    This class only returns official ATT&CK metadata. It does not
    infer that observed behavior constitutes a technique.
    """

    def __init__(
        self,
        index_path: str | Path,
    ) -> None:
        self.index_path = Path(index_path)

        try:
            payload = json.loads(
                self.index_path.read_text(
                    encoding="utf-8-sig"
                )
            )
        except FileNotFoundError as exc:
            raise AttackDatasetError(
                f"ATT&CK index not found: {self.index_path}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise AttackDatasetError(
                f"invalid ATT&CK index JSON: {exc}"
            ) from exc

        if (
            payload.get("schema_version")
            != ATTACK_INDEX_SCHEMA_VERSION
        ):
            raise AttackDatasetError(
                "unsupported ATT&CK index schema version"
            )

        techniques = payload.get("techniques")

        if not isinstance(techniques, list):
            raise AttackDatasetError(
                "ATT&CK index has no techniques array"
            )

        self.attack_version = str(
            payload.get("attack_version", "")
        )
        self.domain = str(
            payload.get("domain", "")
        )
        self.techniques = techniques

    @staticmethod
    def _bounded_record(
        record: dict[str, Any],
        *,
        description_limit: int,
    ) -> dict[str, Any]:
        description = str(
            record.get("description", "")
        )

        truncated = (
            len(description) > description_limit
        )

        if truncated:
            description = (
                description[:description_limit]
                + "…"
            )

        return {
            "attack_id": record.get("attack_id"),
            "stix_id": record.get("stix_id"),
            "name": record.get("name"),
            "description": description,
            "description_truncated": truncated,
            "tactics": record.get("tactics", []),
            "platforms": record.get("platforms", []),
            "is_subtechnique": bool(
                record.get("is_subtechnique")
            ),
            "created": record.get("created"),
            "modified": record.get("modified"),
            "url": record.get("url"),
        }

    def lookup(
        self,
        query: str,
        *,
        limit: int = 10,
        description_limit: int = DEFAULT_DESCRIPTION_LIMIT,
    ) -> dict[str, Any]:
        text = query.strip()

        if not text:
            raise ValueError(
                "ATT&CK lookup query must not be empty"
            )

        if limit < 1 or limit > 20:
            raise ValueError(
                "ATT&CK lookup limit must be between 1 and 20"
            )

        if description_limit < 200 or description_limit > 8000:
            raise ValueError(
                "description_limit must be between 200 and 8000"
            )

        folded = text.casefold()

        exact_id: list[dict[str, Any]] = []
        exact_name: list[dict[str, Any]] = []
        prefix_name: list[dict[str, Any]] = []
        contains_name: list[dict[str, Any]] = []

        for record in self.techniques:
            attack_id = str(
                record.get("attack_id", "")
            )
            name = str(
                record.get("name", "")
            )

            id_folded = attack_id.casefold()
            name_folded = name.casefold()

            if id_folded == folded:
                exact_id.append(record)

            elif name_folded == folded:
                exact_name.append(record)

            elif name_folded.startswith(folded):
                prefix_name.append(record)

            elif (
                folded in name_folded
                or folded in id_folded
            ):
                contains_name.append(record)

        ordered = (
            exact_id
            + exact_name
            + prefix_name
            + contains_name
        )

        # Preserve ranking while removing accidental duplicates.
        seen: set[str] = set()
        results: list[dict[str, Any]] = []

        for record in ordered:
            stix_id = str(
                record.get("stix_id", "")
            )

            if stix_id in seen:
                continue

            seen.add(stix_id)

            results.append(
                self._bounded_record(
                    record,
                    description_limit=description_limit,
                )
            )

            if len(results) >= limit:
                break

        return {
            "source": "MITRE ATT&CK",
            "attack_version": self.attack_version,
            "domain": self.domain,
            "query": text,
            "count": len(results),
            "results": results,
            "interpretation_notice": (
                "Lookup results are reference metadata only. "
                "A matching name or ID does not establish that "
                "the technique occurred in the investigated case."
            ),
        }


def _main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build the compact deterministic ATT&CK lookup index."
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    build = subparsers.add_parser(
        "build"
    )

    build.add_argument(
        "--raw",
        required=True,
    )
    build.add_argument(
        "--index",
        required=True,
    )
    build.add_argument(
        "--version",
        required=True,
    )
    build.add_argument(
        "--domain",
        default="enterprise-attack",
    )

    args = parser.parse_args()

    if args.command == "build":
        index = build_attack_index(
            raw_path=args.raw,
            index_path=args.index,
            attack_version=args.version,
            domain=args.domain,
        )

        print(
            json.dumps(
                {
                    "attack_version": index[
                        "attack_version"
                    ],
                    "domain": index["domain"],
                    "technique_count": index[
                        "technique_count"
                    ],
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    _main()
