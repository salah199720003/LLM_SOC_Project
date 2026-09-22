import json

from cybercopilot.attack_store import (
    AttackStore,
    build_attack_index,
)


def _bundle():
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--one",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "name": "PowerShell",
                "description": "Official reference text.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution",
                    }
                ],
                "x_mitre_platforms": [
                    "Windows"
                ],
                "x_mitre_is_subtechnique": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": (
                            "https://attack.mitre.org/"
                            "techniques/T1059/001/"
                        ),
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deprecated",
                "name": "Old Thing",
                "x_mitre_deprecated": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999",
                    }
                ],
            },
        ],
    }


def test_build_and_exact_id_lookup(tmp_path):
    raw = tmp_path / "attack.json"
    index = tmp_path / "index.json"

    raw.write_text(
        json.dumps(_bundle()),
        encoding="utf-8",
    )

    built = build_attack_index(
        raw_path=raw,
        index_path=index,
        attack_version="19.2",
    )

    assert built["technique_count"] == 1

    store = AttackStore(index)

    result = store.lookup("T1059.001")

    assert result["attack_version"] == "19.2"
    assert result["count"] == 1
    assert result["results"][0]["name"] == "PowerShell"
    assert result["results"][0]["tactics"] == [
        "execution"
    ]


def test_lookup_by_name_is_case_insensitive(tmp_path):
    raw = tmp_path / "attack.json"
    index = tmp_path / "index.json"

    raw.write_text(
        json.dumps(_bundle()),
        encoding="utf-8",
    )

    build_attack_index(
        raw_path=raw,
        index_path=index,
        attack_version="19.2",
    )

    result = AttackStore(index).lookup(
        "powershell"
    )

    assert result["count"] == 1
    assert (
        result["results"][0]["attack_id"]
        == "T1059.001"
    )


def test_deprecated_technique_is_not_indexed(tmp_path):
    raw = tmp_path / "attack.json"
    index = tmp_path / "index.json"

    raw.write_text(
        json.dumps(_bundle()),
        encoding="utf-8",
    )

    build_attack_index(
        raw_path=raw,
        index_path=index,
        attack_version="19.2",
    )

    result = AttackStore(index).lookup(
        "T9999"
    )

    assert result["count"] == 0
