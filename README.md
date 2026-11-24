# SOC L1 Skills Demo

An educational Python demo for Windows security event triage, risk scoring,
MITRE ATT&CK references, and JSON incident reports. It processes normalized JSON
records, not raw EVTX files or live SIEM feeds.

## Quick start

Requires Python 3.8+; Python 3.12 or newer is recommended. No third-party packages are needed.

```bash
git clone https://github.com/Nmyers21/SOC-L1-Skills-Demo.git
cd SOC-L1-Skills-Demo
python3 scripts/generate_sample_data.py
python3 scripts/soc_analysis.py
python3 -m unittest discover -s tests -v
```

The generator writes `sample-data/combined_security_events.json`. Analysis reads
that file and writes `analysis_results_YYYYMMDD_HHMMSS_microseconds.json` in the repository
root. Script paths are resolved relative to the repository, so scripts also work
when launched from another directory. Generated data and results are ignored by Git.

## Input and behavior

Input must be a JSON array of event objects. Common fields are `timestamp`
(ISO 8601), `event_id` (string or integer), `source_ip`, `username`, `hostname`,
`logon_type`, and `process_name`. Optional process evidence includes
`parent_process`, `destination_ip`, and `file_path`. String fields must be strings.
Sample timestamps use UTC; legacy timestamps without offsets are treated as UTC.
Invalid or missing timestamps are excluded from correlation.
Optional string fields such as `parent_process`, `destination_ip`, `file_path`,
`description`, and `logon_id` must also be strings when supplied. Malformed IP
strings are noted without adding external-IP risk or treating them as IP evidence.

- Brute force: at least five failed logons (4625) from one source within ten
  minutes; ten or more attempts receive HIGH correlation severity.
- Privilege assignment for review: event 4672 for an account not matching the demo's
  admin-name heuristics, with a preceding same-user, same-host logon within ten
  minutes. If both events supply a Logon ID, those IDs must match. This is MEDIUM
  priority correlation context, not proof of privilege escalation or T1068.
- Possible lateral movement: network or remote-interactive logons (types 3/10,
  event 4624) across three hosts in the ten-minute window with the most distinct
  hosts. A noisy single-host window must not hide a quieter multi-host window.
- Individual scores combine event type, source IP, and account heuristics.
  Office spawning PowerShell, configured suspicious destinations, and Startup
  folder writes add risk. Scores are capped at 20. Thresholds are MEDIUM 7,
  HIGH 12, and CRITICAL 15. HIGH/CRITICAL individual events create incident reports
  with unique IDs and suggested response actions.

The JSON output includes per-event priority counts, incident reports, correlation
findings, threat summaries, and processing metrics. Correlation findings are
reported separately; they do not promote individual event scores or create incidents.
Input, processing, correlation, or output errors cause an unsuccessful CLI exit.

## Scope and limitations

This is a learning project, not a validated production detector. Event IDs alone
cannot establish an attack or its MITRE technique; mappings are investigation
hints. Event 4672 does not prove exploitation, and multi-host logons may be legitimate.
Account-name matching and suspicious IP prefixes are simplified demo heuristics.
The generator includes 52 events with randomized baseline activity. Documentation
ranges and the configured suspicious destination are synthetic scenario indicators,
not a live threat intelligence feed. There are no measured accuracy, false-positive,
or throughput guarantees. Business-hours scoring and live ingestion are not implemented.

Correlation reports the strongest window per source/user, rather than every separate
attack episode. Analysts must review the underlying evidence. Adapt rules, account
allowlists, retention, and escalation practices before considering operational use.
Missing Logon IDs allow only an approximate user/host/time association. Event
records are assumed to be normalized and deduplicated upstream. Generated reports
are triage suggestions, not confirmed incidents or actions performed.

## Layout

- `scripts/alert_triage.py`: scoring, correlation, incident reporting.
- `scripts/generate_sample_data.py`: attack and baseline sample records.
- `scripts/soc_analysis.py`: CLI orchestration and JSON output.
- `tests/test_soc.py`: regression checks.
- `.github/workflows/tests.yml`: Python compatibility and sample workflow checks.

See [the workflow guide](docs/README.md) for the processing steps, design choices
and remaining improvements.

Author: [Noah Myers](https://github.com/Nmyers21)
