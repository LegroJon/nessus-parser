# Nessus Parser

A Python tool for parsing Nessus XML vulnerability scan files and exporting the data to various formats (JSON, CSV, Excel).

## Features

- Parse Nessus XML (.nessus) files
- Extract vulnerability data, host information, and scan metadata
- Export to multiple formats: JSON, CSV, Excel
- Filter vulnerabilities by severity level or host
- Command-line interface for easy automation
- Exclude informational findings option

## Installation

1. Clone this repository:
```bash
git clone https://github.com/LegroJon/nessus-parser.git
cd nessus-parser
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

For Excel export functionality, also install:
```bash
pip install pandas openpyxl
```

## Usage

#### Show all CLI options

To see all available command-line options and usage instructions, run:

```bash
python cli.py -h
```
or
```bash
python cli.py --help
```

### Command Line Interface

Basic usage:
```bash
python cli.py scan_results.nessus
```

Export to specific format:
```bash
python cli.py scan_results.nessus -f csv -o vulnerabilities.csv
python cli.py scan_results.nessus -f excel -o report.xlsx
python cli.py scan_results.nessus -f json -o data.json
```

Filter vulnerabilities:
```bash
# Filter by severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)
python cli.py scan_results.nessus --filter-severity 4

# Filter by host
python cli.py scan_results.nessus --filter-host "192.168.1.10"

# Exclude informational findings
python cli.py scan_results.nessus --no-info
```

Verbose output:
```bash
python cli.py scan_results.nessus -v
```

### Python API

```python
from parser import NessusParser
from exporter import NessusExporter

# Parse a Nessus file
parser = NessusParser('scan_results.nessus')
scan_data = parser.parse()

# Export to different formats
exporter = NessusExporter(scan_data)
exporter.to_json('output.json')
exporter.to_csv('vulnerabilities.csv')
exporter.to_excel('report.xlsx')
```

## Output Formats

### JSON
Complete scan data including hosts, vulnerabilities, and metadata in JSON format.

### CSV
Flattened vulnerability data with host information, suitable for spreadsheet analysis.

### Excel
Multi-sheet workbook with:
- **Vulnerabilities**: Detailed vulnerability data
- **Hosts**: Host summary with vulnerability counts by severity
- **Scan_Info**: Scan metadata and overall statistics

## Data Structure

The parser extracts the following information:

### Scan Metadata
- Policy name
- Scan name

### Host Information
- Host name/IP
- Operating system
- Host properties
- Associated vulnerabilities

### Vulnerability Details
- Plugin ID and name
- Severity level
- Port and protocol
- Service name
- Description and solution
- Risk factor
- CVSS score
- CVE references

## Requirements

- Python 3.6+
- xml.etree.ElementTree (built-in)
- pathlib (built-in)
- logging (built-in)
- csv (built-in)
- json (built-in)

Optional dependencies:
- pandas (for Excel export)
- openpyxl (for Excel export)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## CLI vs Exporter: What's the Difference?

**CLI (`cli.py`)**

- The command-line interface is the main entry point for end users who want to quickly parse and export Nessus scan results without writing any code.
- It provides a set of command-line options for specifying the input file, output format, filtering options, and more.
- The CLI handles argument parsing, file validation, logging, and calls the parser and exporter modules under the hood.
- Use the CLI if you want to automate Nessus parsing and exporting as part of a script, scheduled job, or manual workflow.

**Exporter (`exporter.py`)**

- The exporter is a Python module that provides programmatic access to export functionality.
- It is designed for developers who want to integrate Nessus parsing and exporting into their own Python applications or workflows.
- The exporter takes parsed scan data (from the parser) and can output it in JSON, CSV, or Excel formats.
- Use the exporter if you want to build custom tools, automate reporting, or further process Nessus data in Python code.

In summary: **Use the CLI for quick, user-friendly command-line operations. Use the exporter module for advanced, programmatic access in your own Python scripts.**

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for legitimate security testing and vulnerability management purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems.
CLI tool to parse Nessus scan results and export filtered findings
