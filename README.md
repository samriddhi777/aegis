# Aegis — Intelligent Log Analyzer

A privacy-first cybersecurity tool that uses a locally hosted LLM to analyze server logs and detect attack patterns. Zero data leaves your machine.

![Aegis Demo](demo.gif)

## What it does

Paste any server log — SSH auth logs, Apache access logs, or Linux privilege logs — and Aegis automatically:

- Detects the log type
- Extracts IP addresses, usernames, and failed attempt counts
- Classifies the attack pattern (brute force, SQL injection, privilege escalation)
- Assigns a severity level (CRITICAL / HIGH / MEDIUM / LOW / CLEAN)
- Generates a structured incident report with recommended actions

## Why local?

Logs contain sensitive data — internal IPs, usernames, file paths. Sending them to a cloud API (OpenAI, Claude) is a compliance risk. Aegis runs entirely on your machine using Ollama. No internet connection required after setup.

## Tech stack

- **Backend** — Python, FastAPI, streaming API
- **Frontend** — React, Vite, TailwindCSS
- **AI** — Ollama (Llama 3.2 3B, runs locally on Apple Silicon)
- **Pre-processing** — custom regex pipeline for log parsing before LLM inference

## Architecture
React Frontend → FastAPI Backend → Pre-processing layer → Ollama (local LLM)

The backend pre-processes every log before the AI sees it — extracting structured fields using regex. This improves analysis accuracy and reduces inference time.

## Setup

**Prerequisites**
- Python 3.11+
- Node.js 18+
- [Ollama](https://ollama.com) installed

**1. Clone the repo**
```bash
git clone https://github.com/samriddhi777/aegis.git
cd aegis
```

**2. Pull the model**
```bash
ollama pull llama3.2:3b
```

**3. Start the backend**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**4. Start the frontend**
```bash
cd frontend
npm install
npm run dev
```

**5. Open in browser**
```
http://localhost:5173
```

## Sample logs included

- SSH brute force attack
- SQL injection attempt
- Privilege escalation
- Clean normal traffic

## Author

Samriddhi Guha — Sophomore, Department of Cybersecurity, Dayananda Sagar University
[GitHub](https://github.com/samriddhi777)
