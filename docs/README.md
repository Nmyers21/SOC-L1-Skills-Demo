# How the demo works

The project keeps the workflow deliberately small:

1. `generate_sample_data.py` creates 52 normalized, synthetic JSON records.
2. `soc_analysis.py` validates their structure and field types.
3. `alert_triage.py` scores each event using simple, readable heuristics.
4. Correlation groups related records in ten-minute windows.
5. The workflow prints a summary and writes a JSON report. It makes no network
   requests and does not disable accounts, block addresses or isolate systems.

High and critical individual event scores create draft incident records.
Correlation findings are separate; they do not automatically increase event
scores. A successful CLI run means processing completed, not that detections
were proven accurate. Timing and success-rate metrics describe processing,
not detection quality.

## Why the rules need analyst review

An external address, a privileged logon, or remote access to several hosts can
be legitimate. Event 4672 records special privileges assigned to a new logon;
it does not prove exploitation. Generic process/network/file events do not
identify a particular ATT&CK technique without additional context. Output
technique references are investigation leads. `attack_stage` remains
undetermined rather than inferring an attack phase from an event ID.

References: [Microsoft event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
and [MITRE T1068](https://attack.mitre.org/techniques/T1068/).

## Practical limitations and next steps

- Account-name matching and source-prefix scoring are simplified rules, not an
  account inventory or threat-intelligence integration.
- Only the strongest correlation window is reported. Slow/distributed activity
  and separate episodes need additional rules.
- The sample baseline is randomized; report counts can vary between runs.
- The workflow is intended for one analysis per instance. It loads the file
  into memory and has no streaming, retention or case-management integration.
- Session correlation is approximate when Logon IDs are unavailable.
- `config.py` and `data_structures.py` are early learning scaffolds; the current
  workflow uses its own defaults and normalized dictionaries.

Useful future exercises include a configurable CLI, exact account allowlists,
deduplication, reproducible sample generation and benign test cases for tuning.
These are improvement ideas, not implemented capabilities.

## Local verification

Run the commands in the [main README](../README.md). The unit tests cover
time-window behavior, malformed input, IP handling, privilege-event limits,
incident identifiers, generated process scenarios and output failures. The
GitHub Actions workflow also runs the generator and analysis commands.
