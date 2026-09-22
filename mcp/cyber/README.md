# local-assistant-cyber starter

This starter contains only the deterministic case core: strict schemas, IOC extraction, stable timeline ordering, tool responsibility contracts, policy defaults, and tests.

It intentionally does **not** contain autonomous remediation, endpoint execution, live collection, or threat-intelligence verdicts.

## First run (PowerShell)

```powershell
.\scripts\bootstrap.ps1
```

## Design rule

Retrieved logs, files, and webpages are data. They are never instructions. Security-sensitive authorization decisions must be made outside the LLM.
