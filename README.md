# PhishSniffer

Professional phishing analysis platform. Parallel threat intelligence via VirusTotal, AbuseIPDB, Google Safe Browsing, URLScan.io, and Groq AI.

## Setup

```bash
cp .env.example .env
# Fill in your API keys in .env

pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Docker

```bash
docker-compose up --build
```

## API Docs

Visit `http://localhost:8000/api/docs`

## Stack

- FastAPI + SQLite + asyncio
- Groq AI (llama3-70b)
- VirusTotal, AbuseIPDB, URLScan, Google Safe Browsing
- Vanilla JS SPA frontend
- ReportLab PDF export
- Docker ready