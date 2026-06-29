# HScanner

Local, hash-based file triage for Linux that uses online scan engines for analysis.
It is not an antivirus.

HScanner inventories a folder, classifies files by a local policy, checks selected
file hashes with VirusTotal, MetaDefender, or both, and produces an attention-focused
report. It does not quarantine, delete, clean, or block files.

## Quick Start

```bash
./run.sh
```

The script creates `.venv`, installs the app, starts the web UI on
`http://127.0.0.1:8765`, and opens it in your browser.

## Requirements

- A VirusTotal and/or MetaDefender API key are required for online scans.

## CLI

Install and activate the project environment first:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Examples:

```bash
hscanner scan /path/to/folder

HS_API_KEY_VIRUSTOTAL=your_key hscanner scan /path/to/folder --engine virustotal
HS_API_KEY_METADEFENDER=your_key hscanner scan /path/to/folder --engine metadefender

HS_API_KEY_VIRUSTOTAL=your_key \
HS_API_KEY_METADEFENDER=your_key \
hscanner scan /path/to/folder --engine combined

hscanner scan /path/to/folder --json
hscanner scan /path/to/folder --report report.html
hscanner scan /path/to/folder --report report.json
hscanner scan /path/to/folder --report report.csv
```

Common options:

- `--engine virustotal|metadefender|combined`
- `--require-engine`
- `--resume`
- `--refresh`
- `--max-requests N`
- `--bypass-low-risk` / `--no-bypass-low-risk`

## Privacy And Safety

- Hash lookups send SHA-256 hashes to the selected online engine.
- File contents are not uploaded during the initial scan.
- Unknown eligible files can be uploaded only by explicit action from the report.
- Sensitive files such as `.env`, `*.pem`, `*.key`, and secret-named files are skipped.
- API keys are not written to reports, exports, logs, browser storage, or config files.
- The web server binds to `127.0.0.1` by default.
- Results are triage signals, not proof that a file is safe.