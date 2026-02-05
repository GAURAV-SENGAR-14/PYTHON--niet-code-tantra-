# Keylogger Detector (Defensive)

This repository contains a small, runnable Python project that scans the local machine for
potential keylogger indicators by reviewing running processes and active network connections.
The tool is defensive and educational, aiming to highlight suspicious behavior rather than perform
any interception.

## Features
- **Process monitoring:** flags processes with suspicious keywords, high CPU usage, or high memory
  usage.
- **Network monitoring:** highlights connections using common data-exfiltration ports (SMTP).
- **JSON reports:** output structured results to stdout or a file.

## Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python -m keylogger_detector.cli --sample-interval 1.5 --output report.json
```

## Report Fields
- `process_findings`: processes that match keyword or resource heuristics.
- `network_findings`: network connections on suspicious ports.

## Notes
- This tool does not capture keystrokes or install hooks.
- Adjust thresholds in `keylogger_detector/config.py` to tune sensitivity.
