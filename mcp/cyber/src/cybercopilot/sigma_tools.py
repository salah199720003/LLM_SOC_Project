from __future__ import annotations

import fnmatch
import re
from typing import Any

import yaml
from sigma.collection import SigmaCollection


MAX_RULE_BYTES = 64 * 1024
MAX_TEST_EVENTS = 100
MAX_FIELD_TEXT = 8192

SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "cased",
    "all",
    "exists",
}


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict:
    mapping = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(
            key_node,
            deep=deep,
        )

        if key in mapping:
            raise SigmaToolError(
                f"duplicate YAML key: {key}"
            )

        mapping[key] = loader.construct_object(
            value_node,
            deep=deep,
        )

    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)

class SigmaToolError(ValueError):
    """Base error for deterministic Sigma tooling."""


class UnsupportedSigmaFeature(SigmaToolError):
    """Raised when the bounded local matcher cannot safely evaluate a rule."""


def _bounded_rule_text(rule_yaml: str) -> str:
    if not isinstance(rule_yaml, str) or not rule_yaml.strip():
        raise SigmaToolError("rule_yaml must not be empty")
    if len(rule_yaml.encode("utf-8")) > MAX_RULE_BYTES:
        raise SigmaToolError("Sigma rule exceeds 64 KiB limit")
    return rule_yaml


def validate_sigma_rule(rule_yaml: str) -> dict[str, Any]:
    """
    Parse a Sigma rule with pySigma.

    This validates rule syntax/structure. It does not claim that the rule is
    high quality, low-noise, or correct for a particular SIEM.
    """
    text = _bounded_rule_text(rule_yaml)
    errors: list[str] = []

    try:
        loaded = yaml.load(text, Loader=_UniqueKeyLoader)
    except Exception as exc:
        return {
            "valid": False,
            "engine": "pySigma-1.5.0",
            "spec_target": "Sigma rule specification 2.1.0",
            "errors": [f"YAML parse error: {exc}"],
        }

    if not isinstance(loaded, dict):
        return {
            "valid": False,
            "engine": "pySigma-1.5.0",
            "spec_target": "Sigma rule specification 2.1.0",
            "errors": ["exactly one mapping-style Sigma rule is required"],
        }

    try:
        collection = SigmaCollection.from_yaml(
            text,
            collect_errors=True,
            resolve_references=True,
        )
    except Exception as exc:
        return {
            "valid": False,
            "engine": "pySigma-1.5.0",
            "spec_target": "Sigma rule specification 2.1.0",
            "errors": [f"pySigma parse error: {exc}"],
        }

    for error in getattr(collection, "errors", []) or []:
        errors.append(str(error))

    rules = list(getattr(collection, "rules", []) or [])
    for rule in rules:
        for error in getattr(rule, "errors", []) or []:
            errors.append(str(error))

    if len(rules) != 1:
        errors.append(
            f"exactly one detection rule is required; parsed {len(rules)}"
        )

    required = ("title", "logsource", "detection")
    for key in required:
        if key not in loaded:
            errors.append(f"missing required field: {key}")

    detection = loaded.get("detection")
    if isinstance(detection, dict) and "condition" not in detection:
        errors.append("missing required field: detection.condition")

    return {
        "valid": not errors,
        "engine": "pySigma-1.5.0",
        "spec_target": "Sigma rule specification 2.1.0",
        "title": loaded.get("title"),
        "logsource": loaded.get("logsource"),
        "errors": errors[:50],
        "notice": (
            "Validation checks parseability/structure only; it does not establish "
            "detection quality, maliciousness, or SIEM-specific compatibility."
        ),
    }


def _flatten_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Build a case-insensitive field index.

    Nested EventRecord.fields values are exposed by both full dotted path and
    leaf name, so a Sysmon event_data.Image field can satisfy Sigma field Image.
    """
    result: dict[str, Any] = {}

    def walk(value: Any, path: list[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, path + [str(key)])
            return

        if isinstance(value, list):
            if path:
                full = ".".join(path).lower()
                result.setdefault(full, value)
                result.setdefault(path[-1].lower(), value)
            return

        if path:
            full = ".".join(path).lower()
            result.setdefault(full, value)
            result.setdefault(path[-1].lower(), value)

    walk(event, [])
    return result


def _as_values(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _string(value: Any) -> str:
    text = "" if value is None else str(value)
    return text[:MAX_FIELD_TEXT]


def _match_one(
    actual: Any,
    expected: Any,
    *,
    modifiers: list[str],
) -> bool:
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedSigmaFeature(
            "unsupported Sigma modifier(s) in local matcher: "
            + ", ".join(sorted(unknown))
        )

    cased = "cased" in modifiers
    values = actual if isinstance(actual, list) else [actual]

    if "exists" in modifiers:
        if not isinstance(expected, bool):
            raise UnsupportedSigmaFeature(
                "exists modifier requires a boolean value"
            )
        exists = actual is not None
        return exists is expected

    def compare(item: Any) -> bool:
        a = _string(item)
        e = _string(expected)
        if not cased:
            a = a.casefold()
            e = e.casefold()

        if "contains" in modifiers:
            return e in a
        if "startswith" in modifiers:
            return a.startswith(e)
        if "endswith" in modifiers:
            return a.endswith(e)

        # Default Sigma string matching supports * and ? wildcards.
        if "*" in e or "?" in e:
            return fnmatch.fnmatchcase(a, e)
        return a == e

    return any(compare(item) for item in values)


def _match_field(
    event_fields: dict[str, Any],
    field_expr: str,
    expected: Any,
) -> bool:
    parts = field_expr.split("|")
    field_name = parts[0].strip().lower()
    modifiers = [part.strip().lower() for part in parts[1:] if part.strip()]

    if not field_name:
        raise UnsupportedSigmaFeature("empty Sigma field name")

    actual = event_fields.get(field_name)
    expected_values = _as_values(expected)

    if "all" in modifiers:
        return all(
            _match_one(actual, item, modifiers=modifiers)
            for item in expected_values
        )

    return any(
        _match_one(actual, item, modifiers=modifiers)
        for item in expected_values
    )


def _match_selection(
    event_fields: dict[str, Any],
    selection: Any,
) -> bool:
    if isinstance(selection, dict):
        return all(
            _match_field(event_fields, str(field), expected)
            for field, expected in selection.items()
        )

    if isinstance(selection, list) and all(
        isinstance(item, dict) for item in selection
    ):
        return any(
            _match_selection(event_fields, item)
            for item in selection
        )

    raise UnsupportedSigmaFeature(
        "local matcher v1 supports mapping selections and lists of mappings; "
        "keyword/list-only selections are not yet supported"
    )


_TOKEN_RE = re.compile(
    r"\s*(\(|\)|\bAND\b|\bOR\b|\bNOT\b|\bTRUE\b|\bFALSE\b|"
    r"[A-Za-z_][A-Za-z0-9_-]*)",
    re.IGNORECASE,
)


def _replace_quantifiers(
    condition: str,
    selection_results: dict[str, bool],
) -> str:
    pattern = re.compile(
        r"\b(all|\d+)\s+of\s+(them|[A-Za-z_][A-Za-z0-9_-]*\*)\b",
        re.IGNORECASE,
    )

    def repl(match: re.Match[str]) -> str:
        count_token = match.group(1).lower()
        target = match.group(2)

        if target.lower() == "them":
            names = list(selection_results)
        else:
            prefix = target[:-1].casefold()
            names = [
                name
                for name in selection_results
                if name.casefold().startswith(prefix)
            ]

        if not names:
            raise UnsupportedSigmaFeature(
                f"condition quantifier matched no selections: {match.group(0)}"
            )

        matched = sum(bool(selection_results[name]) for name in names)
        required = len(names) if count_token == "all" else int(count_token)
        return " TRUE " if matched >= required else " FALSE "

    return pattern.sub(repl, condition)


def _eval_boolean_condition(
    condition: str,
    selection_results: dict[str, bool],
) -> bool:
    condition = _replace_quantifiers(condition, selection_results)

    tokens: list[str] = []
    position = 0
    while position < len(condition):
        match = _TOKEN_RE.match(condition, position)
        if not match:
            remainder = condition[position:].strip()
            if remainder:
                raise UnsupportedSigmaFeature(
                    f"unsupported condition syntax near: {remainder[:80]}"
                )
            break
        tokens.append(match.group(1))
        position = match.end()

    if not tokens:
        raise UnsupportedSigmaFeature("empty Sigma condition")

    index = 0

    def parse_or() -> bool:
        nonlocal index
        value = parse_and()
        while index < len(tokens) and tokens[index].lower() == "or":
            index += 1
            rhs = parse_and()
            value = value or rhs
        return value

    def parse_and() -> bool:
        nonlocal index
        value = parse_not()
        while index < len(tokens) and tokens[index].lower() == "and":
            index += 1
            rhs = parse_not()
            value = value and rhs
        return value

    def parse_not() -> bool:
        nonlocal index
        if index < len(tokens) and tokens[index].lower() == "not":
            index += 1
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        nonlocal index
        if index >= len(tokens):
            raise UnsupportedSigmaFeature("unexpected end of condition")

        token = tokens[index]
        lowered = token.lower()

        if token == "(":
            index += 1
            value = parse_or()
            if index >= len(tokens) or tokens[index] != ")":
                raise UnsupportedSigmaFeature("unbalanced condition parentheses")
            index += 1
            return value

        if token == ")":
            raise UnsupportedSigmaFeature("unexpected ')' in condition")

        index += 1

        if lowered == "true":
            return True
        if lowered == "false":
            return False

        for name, value in selection_results.items():
            if name.casefold() == token.casefold():
                return bool(value)

        raise UnsupportedSigmaFeature(
            f"condition references unknown selection: {token}"
        )

    result = parse_or()
    if index != len(tokens):
        raise UnsupportedSigmaFeature(
            f"unsupported trailing condition syntax: {' '.join(tokens[index:])}"
        )
    return result


def _event_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise UnsupportedSigmaFeature("detection must be a mapping")

    condition = detection.get("condition")
    if not isinstance(condition, (str, list)):
        raise UnsupportedSigmaFeature(
            "local matcher requires a string or list detection.condition"
        )

    selection_results: dict[str, bool] = {}
    fields = _flatten_event(event)

    for name, selection in detection.items():
        if name in {"condition", "timeframe"}:
            continue
        selection_results[str(name)] = _match_selection(fields, selection)

    conditions = condition if isinstance(condition, list) else [condition]
    if not all(isinstance(item, str) for item in conditions):
        raise UnsupportedSigmaFeature(
            "all detection conditions must be strings"
        )

    return any(
        _eval_boolean_condition(item, selection_results)
        for item in conditions
    )


def test_sigma_rule(
    rule_yaml: str,
    *,
    events: list[dict[str, Any]],
    expected_match_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    validation = validate_sigma_rule(rule_yaml)
    if not validation["valid"]:
        return {
            "valid": False,
            "test_supported": False,
            "validation": validation,
            "matched_event_ids": [],
            "errors": ["rule failed validation"],
        }

    if len(events) > MAX_TEST_EVENTS:
        raise SigmaToolError(
            f"too many events; maximum is {MAX_TEST_EVENTS}"
        )

    loaded = yaml.load(_bounded_rule_text(rule_yaml), Loader=_UniqueKeyLoader)
    if not isinstance(loaded, dict):
        raise SigmaToolError("Sigma rule must be a mapping")

    matched_event_ids: list[str] = []

    try:
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                raise SigmaToolError(
                    f"event at index {index} is not a mapping"
                )
            if _event_matches(loaded, event):
                event_id = str(
                    event.get("event_id")
                    or event.get("id")
                    or f"index:{index}"
                )
                matched_event_ids.append(event_id)
    except UnsupportedSigmaFeature as exc:
        return {
            "valid": True,
            "test_supported": False,
            "validation": validation,
            "matcher": "bounded_local_matcher_v1",
            "matched_event_ids": [],
            "errors": [str(exc)],
            "notice": (
                "The rule is valid Sigma, but this local matcher intentionally "
                "refuses unsupported features instead of approximating them."
            ),
        }

    result: dict[str, Any] = {
        "valid": True,
        "test_supported": True,
        "validation": validation,
        "matcher": "bounded_local_matcher_v1",
        "event_count": len(events),
        "match_count": len(matched_event_ids),
        "matched_event_ids": matched_event_ids,
        "errors": [],
        "notice": (
            "Fixture matching is deterministic but limited to the documented "
            "local matcher subset; it is not a SIEM deployment test."
        ),
    }

    if expected_match_event_ids is not None:
        expected = set(expected_match_event_ids)
        actual = set(matched_event_ids)
        result["expectation"] = {
            "expected_match_event_ids": sorted(expected),
            "false_negatives": sorted(expected - actual),
            "false_positives": sorted(actual - expected),
            "passed": expected == actual,
        }

    return result

# Prevent pytest from collecting this public library function as a test when
# it is imported into tests/test_sigma_tools.py.
test_sigma_rule.__test__ = False


