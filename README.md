# LLM SOC Project

I'm building a local assistant for investigating security events. The idea is
to let a language model help explain a case while regular Python code handles
the evidence, so the model doesn't have to guess what happened in a log.

This is still a work in progress. The repository currently has two parts:

- **Bonsai demo:** runs the Bonsai 2 27B model on your own computer and gives
  you a chat page at `http://localhost:8080`.
- **SOC tools:** a Python module in [`mcp/cyber`](mcp/cyber/README.md) for
  importing Sysmon XML, creating cases, searching and correlating events,
  extracting observables, and checking Sigma rules.

The two parts are **not connected automatically yet**. You can use the SOC
tools from Python or a client that supports stdio MCP. The Bonsai chat page
needs an HTTP bridge before it can call those tools. This repository also does
not include model weights, personal logs, case databases, or API keys.

## Run the local model

The default setup downloads Bonsai 2 27B and the matching runtime. Expect a
large download (roughly 8 GB for the model and vision projector) and use a
machine with enough memory for a 27B model. A GPU will help, but the scripts
also support CPU mode. Bonsai 2 needs the runtime downloaded by these setup
scripts; a normal llama.cpp build will not run it correctly.

**Windows (PowerShell)**

```powershell
git clone https://github.com/salah199720003/LLM_SOC_Project.git
cd LLM_SOC_Project
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1
.\scripts\start_llama_server.ps1
```

**macOS or Linux**

```bash
git clone https://github.com/salah199720003/LLM_SOC_Project.git
cd LLM_SOC_Project
./setup.sh
./scripts/start_llama_server.sh
```

Once the server says it is ready, open <http://localhost:8080>. Stop it with
`Ctrl+C` in the terminal. If you do not use Git, download the repository ZIP
from GitHub and run the same setup commands inside the extracted folder.

More model choices, hardware settings, and troubleshooting notes are in the
[Bonsai demo reference](BONSAI_DEMO_REFERENCE.md).

## Try the SOC tools

The SOC module currently works with **Sysmon XML exports**. It does not collect
logs from a computer by itself. With Python 3.11+ and `uv` installed, run this
from the repository folder:

```powershell
uv sync --project mcp/cyber --extra dev
uv run --project mcp/cyber --extra dev python -m pytest mcp/cyber/tests
```

Put a Sysmon export in `mcp/evidence/sysmon.xml`, then follow the
[short case walkthrough](mcp/cyber/README.md#analyze-a-sysmon-export-with-python)
to import it and inspect the events. The example creates a local SQLite case
database under `mcp/data/cases`. These folders are ignored by Git so your
evidence stays out of commits.

The SOC module also has a stdio MCP server. Its launch command and limitations
are in the [SOC guide](mcp/cyber/README.md#connect-an-mcp-client).

## What works so far

- Create cases and hash imported evidence so later changes can be detected.
- Parse Sysmon XML into structured events, then filter and correlate them.
- Extract IPs, domains, URLs, and other observable values with evidence links.
- Build timelines and validate or test Sigma rules against case events.
- Run the SOC tools directly or expose them through stdio MCP.

What is still missing: a built-in connection from the Bonsai chat page to the
SOC tools, live endpoint collection, and an investigation UI. ATT&CK lookup
needs a local reference index that is not included here. The tools do not make
automatic threat verdicts or take remediation actions.

## Repository layout

| Folder | What it contains |
|--------|------------------|
| `mcp/cyber/` | SOC analysis code, tests, and its own usage guide |
| `scripts/` | Bonsai launchers and setup helpers |
| `models/` and `bin/` | Downloaded locally during setup; not committed |
| `mcp/evidence/` and `mcp/data/` | Your local evidence and case data; not committed |

## Credit

The Bonsai model and most of the model setup/demo code come from
[PrismML's Bonsai Demo](https://github.com/PrismML-Eng/Bonsai-demo), under the
[Apache 2.0 license](LICENSE). This project adds its SOC analysis work and
local changes around that demo. The model weights are downloaded from the
publishers during setup; I did not train the Bonsai base model.
