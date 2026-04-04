# Aegis — Intelligent Locally Hosted Log Analyzer

For ages, log analysis has been a tedious and repetitive process for cybersecurity professionals; going through thousands of logs and coming to final verdict after hours of looking. As the trend of AI rose within the digital world, log analysis became one among the many repetitive tasks that was automated using intelligent ML algorithms, fetching efficient results and ready-made reports.

In the scope of security, the automation of log analysis came as a tradeoff - any SOC analyst using AI to analyse logs got their report at hand in mere seconds, only at the cost of their system's logs being exposed to the AI, which, at an organisational or even personal level, is a massive privacy concern.

Introducing AEGIS (Version 1.0) - A privacy first log analyser that uses a locally hosted LLM (Llama 3.2 3B) to analyse server logs and flag malicious patterns, without your data ever leaving your machine.

The best of both worlds :)

![Aegis Demo](demo.gif)

## What it does

The AEGIS workflow is designed to be beginner friendly and efficient at the same time, such that anyone from a student (like me) to a working SOC professional may use it to their convienience.

Typically, the user would paste any server log - ranging from SSH Auth logs, Apache Access Logs, Linux Privilege logs, etc, and click "ANALYSE".
AEGIS would then do its magic, and perform the following:

1) Detect the log type (SSH, SQLi, Apache Access, general system log or anything else)
2) Dissect the log by extracting the IP Addresses, usernames and failed attempt counts.
3) Classify the attack pattern to a verdict as brute force, SQL Injection, privilege escalation, etc.
4) Assign a severity level to the attack as CRITICAL / HIGH / MEDIUM / LOW / CLEAN.
5) Generate a structured incident report with the necassary information relevant to the attack and recommended actions for the same (if any).

## Why local?

Logs are a fundamental track of a user's activity on a machine, containing timestamped data related to anything and everything that happens in the system that may either be initiated by the user or the OS. Keeping that in mind, it is a given that logs ought to contain sensitive information like internal IP addresses, usernames, file paths, etc. 

Feeding this kind of information to a cloud API like OpenAI, Claude, ChatGPT is a major complaince risk under regulations like GPDR and HIPAA that may compromise the confidentiality aspect of your data. 

AEGIS is a fully local tool that uses a well structured 3 layer pipeline, with a pre-processing layer in between the frontend and Ollama.
Once the entire system is setup, no internet connection is required to access and utilize Aegis, which eliminates the risk of an attack by a huge margin.

## Tech stack

AEGIS comes to life with the following components:

- **Backend** — Python, FastAPI, streaming API
- **Frontend** — React, Vite, TailwindCSS
- **AI** — Ollama (Llama 3.2 3B, runs locally on Apple Silicon)
- **Pre-processing** — custom regex pipeline for log parsing before LLM inference

## Architecture

Simple as is, but powerful regardless. AEGIS follows a 3 layer pipelined architecture as illustrated:

React Frontend → FastAPI Backend → Pre-processing layer → Ollama (local LLM)

**Frontend**: 

The frontend built with React and Vile. React manages the user interfact as a collection of components that automatically update when their data changes, and Vite is a build tool that provides a fast development server with hot module replacement. When you save a file, the browser updates instantly without a full page reload.

TailwindCSS handles the styling through utility classes directly in the JSX. react-markdown renders the AI's markdown-formatted response as proper HTML with headings, bold text and lists.

**Backend**:

The backend was built with a clear separation of concerns. Think of it as a three-layer pipeline: the request comes in from the frontend, passes through the pre-processing layer where your own code extracts structure from the raw log, then gets handed to Ollama with a carefully engineered prompt. The response streams back token by token to the frontend.

The pre-processing layer is the most important part of the project. It is what distinguishes Aegis from a simple LLM wrapper. Every IP address, username, and failed attempt count is extracted by your own regex code before the AI sees anything.

- Imports and application setup:

The main.py file begins by importing the tools needed from each library. FastAPI is initialized as an application object, and CORS middleware is attached to it. CORS (Cross-Origin Resource Sharing) is a browser security mechanism that blocks requests between different ports by default. The frontend runs on port 5173 and the backend on port 8000, so without this middleware the browser would reject every request from the frontend.
app = FastAPI(title='Aegis Log Analyzer')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173'], ...)

- Data validation with Pydantic:

When the frontend sends a log to the backend, it arrives as JSON. Pydantic's BaseModel validates the incoming data automatically before any code touches it. The LogRequest class declares that the request must contain a field called log_content that is a string. If the frontend sends a malformed request, FastAPI rejects it instantly with a clear error message.
class LogRequest(BaseModel):
    log_content: str

- Pre-processing layer:

This is the core of what makes Aegis a real security tool rather than a chatbot. Four functions run on every log before Ollama is involved:

    detect_log_type:

    Uses regex pattern matching to identify whether the log is an SSH authentication log, an Apache/Nginx access log, a Linux privilege log, or a generic system log. The detection works by searching for signature strings unique to each log type — for example, the word sshd or the phrase Failed password identifies SSH logs.

    extract_ip_addresses:

    A regular expression pattern matches the structure of an IPv4 address — three groups of one to three digits separated by dots, followed by a final group of digits. The set() function removes duplicates so the same attacking IP is only listed once. A final validation step ensures each octet falls between 0 and 255.

    extract_usernames:

    Three separate patterns handle the different ways authentication logs record usernames — with or without the phrase 'invalid user', and for both failed and successful logins. Using multiple patterns ensures no username is missed regardless of log format.

    count_failed_attempts:

    Counts every occurrence of failure-indicating phrases across the entire log. This single number is the most important brute force indicator — a high count from a single IP over a short time window is definitively suspicious.

    All four functions are called by a single orchestrating function, preprocess_log(), which returns a clean dictionary containing all extracted metadata. This dictionary is passed alongside the raw log to the prompt builder.

- Prompt engineering: 

The build_prompt() function constructs the instruction that gets sent to Ollama. It injects both the raw log and the pre-extracted metadata into a structured template. The AI is instructed to respond in a specific format — SEVERITY, ATTACK CLASSIFICATION, WHAT HAPPENED, INDICATORS OF COMPROMISE, and RECOMMENDED ACTIONS — ensuring consistent, parseable output every time.

The temperature parameter is set to 0.1, close to zero. Temperature controls how creative the model is. For security analysis, creativity is undesirable — you want factual, consistent output, not imaginative interpretation.

- Streaming API endpoint:

The /analyze endpoint receives POST requests containing log content. Two validation checks run first — rejecting empty logs and logs exceeding 50,000 characters. Then the pre-processing runs, the prompt is built, and the response begins streaming.

Streaming means the response is sent back word by word as Ollama generates it, rather than waiting for the entire response to complete. This is implemented using FastAPI's StreamingResponse with server-sent events. The frontend receives each token as it arrives and appends it to the display, creating the typing effect seen in the UI.

The backend first yields the metadata as a JSON event so the frontend can immediately display the pre-processing results while the AI analysis is still being generated. This two-phase response makes the interface feel fast and responsive.

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

In its first version, AEGIS comes with sample logs for users to test its working and output style. The sample logs include:

- SSH brute force attack
- SQL injection attempt
- Privilege escalation
- Clean normal traffic

## Author

Samriddhi Guha — Sophomore, Department of Cybersecurity, Dayananda Sagar University
[GitHub](https://github.com/samriddhi777)
