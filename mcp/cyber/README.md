# SOC analysis module

This is a local, deterministic toolkit for **defensive case analysis**. It can
register evidence with a SHA-256 hash, parse Sysmon XML into normalized events,
query and correlate those events, extract observable values, build a timeline,
and validate or test Sigma rules. It keeps case records in local SQLite files.
It does not collect endpoint telemetry, decide that an observable is malicious,
or take remediation actions.

This module is separate from the Bonsai chat server. You can use its Python API
directly, or expose its tools to a client that supports **stdio MCP**. Starting
the model alone does not give it access to these tools.

## Install and check

From the repository root, install [uv](https://docs.astral.sh/uv/) and run:

```powershell
uv sync --project mcp/cyber --extra dev
uv run --project mcp/cyber --extra dev python -m pytest mcp/cyber/tests
```

The same commands work in a macOS/Linux shell. Python 3.11 or newer is required.

## Analyze a Sysmon export with Python

Put an exported Sysmon XML file at `mcp/evidence/sysmon.xml`. Create the
`mcp/evidence` directory if needed. Evidence paths must stay inside `mcp`, and
the parser currently accepts Sysmon XML files up to 8 MiB.

From the repository root, start Python with the module installed:

```text
uv run --project mcp/cyber python
```

Paste these lines into the Python prompt:

```python
from pathlib import Path
from cybercopilot.tool_service import CyberToolService

root = Path("mcp").resolve()
service = CyberToolService(
    project_root=root,
    db_path=root / "data" / "cases" / "cybercopilot.sqlite3",
)
case = service.create_case(title="Sysmon investigation")
case_id = case["case_id"]
artifact = service.ingest_evidence(
    case_id=case_id, path="evidence/sysmon.xml"
)["artifact"]
parsed = service.parse_events(
    case_id=case_id, artifact_id=artifact["artifact_id"]
)
events = service.query_events(case_id=case_id, limit=100)
print("Case:", case_id, "Parsed:", parsed["parsed_count"], "Found:", events["count"])
```

Use event IDs from `events["events"]` for the next steps. For example, after
confirming the export contains events:

```python
event_ids = [event["event_id"] for event in events["events"]]
print(service.correlate_activity(case_id=case_id, event_ids=event_ids[:100]))
print(service.extract_iocs(case_id=case_id, event_ids=event_ids[:100]))
print(service.build_timeline(case_id=case_id))
```

The output records observations and evidence references; review the underlying
events before drawing conclusions. Case databases live in `mcp/data/cases`,
and local evidence and audit logs remain on your machine.

## Connect an MCP client

Configure a client that supports stdio MCP to launch this command from the
repository root (use an absolute project path in the client's configuration):

```text
uv run --project mcp/cyber python -m cybercopilot.mcp_stdio
```

The process reads MCP messages on standard input and writes responses on
standard output. It is not a web page or a standalone chat UI. The Bonsai
llama-server web UI accepts HTTP MCP servers, so its use with this stdio module
requires an HTTP bridge that this repository does not currently provide.

ATT&CK lookup needs a local Enterprise ATT&CK index at
`mcp/data/reference/attack/v19.2/enterprise-attack-index.json`. That index is
not bundled. The other case tools do not require it.
