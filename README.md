# PhishSniffer

PhishSniffer is an open-source phishing analysis tool designed to automate Tier-1 email triage and URL investigation. The tool parses raw .eml files, extracts indicators of compromise (IoCs), queries threat intelligence sources to calculate a centralized risk score, and exports structured analytical reports.

## Features

### Email Analysis (.eml)
* Header Parsing: Extracts and displays routing history, evaluating SPF, DKIM, and DMARC alignment.
* IoC Extraction: Uses regular expressions to pull file hashes, IPv4 addresses, and domains from the email body.
* Multi-API Enrichment: Correlates extracted data against VirusTotal, AbuseIPDB, Google Safe Browsing, and URLscan.io.
* Automated Summary: Integrates an LLM to parse raw API returns into a plain-text timeline narrative of the threat.

### URL Scanner & Typosquatting Detection
* Standalone URL verification module.
* Cross-references input domains against a database of 400+ known brands to flag lookalike/typosquatted domains.
* Generates a normalized 0-100 risk score based on aggregated threat intel.

### Reporting & Export Engine
* Generates on-demand artifact reports for incident documentation and external sharing.
* Supports three export formats:
  * PDF: Polished executive summary and analyst breakdown for formal ticketing attachments.
  * HTML: Interactive standalone report webpage with complete data visualizations.
  * JSON: Raw structured data payload optimized for SIEM ingestion or upstream SOAR orchestration.

### Analyst Dashboard & Session Management
* Secure user authentication with localized database logging.
* Metrics tracking: total investigations, historical average risk scores, and volume trends.
* History vault with timestamped logs, allowing direct filtering by verdict (Clear, Suspicious, Malicious, Unknown) and investigation type (Email, URL, Unified).

## Architecture & Data Flow

1. Input: User uploads an .eml file or inputs a raw URL into the web application.
2. Extraction Core: Backend extracts raw text indicators and matches domains against typosquatting signatures.
3. Orchestration Layer: Script executes parallel asynchronous GET requests to external threat intelligence endpoints.
4. Reporting Layer: Normalizes data pools and compiles metrics into PDF, HTML, or JSON templates based on analyst selection.
5. Normalization: Aggregates security scores, runs payload text through a local AI summarizer block, and outputs the data to the frontend template.

## Technical Details

* Backend: Structured around request handling, API integrations, and secure database interactions.
* Security Controls: Implements parameterized SQL queries to maintain cross-user data isolation and data boundaries.
* Core Libraries: `requests` for data orchestration, `re` for token isolation, and `json` for multi-source payload parsing.

## License

MIT