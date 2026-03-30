from fastapi import FastAPI, HTTPException #imports fast api and http exception is used for returning error messages
from fastapi.middleware.cors import CORSMiddleware #allows cross port or domain resource sharing (bw FE 5173 and BE 8000)
from fastapi.responses import StreamingResponse #allows for text to be displayed as it is generated in typing style
from pydantic import BaseModel #validates the data before it touches the main code, allows preeliminary checks on the data 
import httpx
import re
import json

app = FastAPI(title="Aegis Log Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], #allow requests from the frontend port only
    allow_methods=["*"], #allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"], #allow all headers (e.g., Content-Type, Authorization, etc.)
)

class LogRequest(BaseModel): #defines the expected structure of the log, uses base model to validate that log content is a string
    log_content: str #the log content that will be analyzed, expected to be a string

#function to check and return log type. uses re.search to look for patterns and return a type.
def detect_log_type(log: str) -> str: #func takes log as a string and returns a string indicating the type of log
    if re.search(r'sshd|Failed Password|Accepted Password',log): #r -> raw string (considers backslashes as literal characters), re.search looks for common SSH log patterns (sshd, Failed Password, Accepted Password) in the log content SSH log patterns.
        return "SSH Authentication Log"
    elif re.search(r'GET|POST|HTTP/[0-9]',log): #looks for common web server log patterns (GET, POST, HTTP/1.1, HTTP/2) in the log content to identify Apache/Nginx access logs.
        return "Apache/Nginx Access Log"
    elif re.search(r'sudo|COMMAND=',log): #looks for common sudo log patterns (sudo, COMMAND=) in the log content to identify Linux privilege escalation logs.
        return "Linux Privilege Log"
    else:
        return "Generic System Log" #fallback catogory

#function to extract ip addresses from the log content. uses regex to find patterns that match IP addresses and returns a list of unique, valid IPs.
def extract_ip_addresses(log: str) -> list:
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = list(set(re.findall(pattern, log)))
    return [ip for ip in ips if all(0 <= int(x) <= 255 for x in ip.split('.'))]

def extract_usernames(log :str) -> list:
    patterns = [
        r'Failed password for (?:invalid user )?(\w+)', #matches failed password attempts, captures the username (with optional "invalid user" prefix)
        r'Invalid user (\w+)', #matches attempts with invalid users, captures the username
        r'Accepted password for (\w+)', #matches successful password attempts, captures the username
    ]
    usernames = []
    for pattern in patterns:
        usernames.extend(re.findall(pattern, log))
        return list(set(usernames)) #returns a list of unique usernames found in the log content

def count_failed_attempts(log: str) -> int:
    return len (re.findall(r'Failed Password| Authentication Failure| FAILED', log)) #counts the number of failed authentication attempts by looking for specific patterns in the log content

def preprocess_log(log: str) -> dict:
    return {
       "log_type": detect_log_type(log), #determines the type of log by calling the function
        "ip_addresses": extract_ip_addresses(log), #extracts all unique and valid IP addresses from the log content using a regular expression pattern that matches typical IPv4 address formats.
        "usernames": extract_usernames(log), #extracts all unique usernames from log contents
        "failed_attempts": count_failed_attempts(log), #counts the number of failed authentication attempts by looking for specific patterns in the log content
        "line_count": len(log.strip().split('\n')) #counts the number of lines in the log content by stripping leading/trailing whitespace and splitting the content into lines based on newline characters, then returns the length of the resulting list.
    }

#prompt
def build_prompt(log: str, metadata: dict) -> str:
    return f"""You are Aegis, an expert cybersecurity analyst.

## Pre-extracted Metadata:
- Log Type: {metadata['log_type']}
- IPs Found: {', '.join(metadata['ip_addresses']) if metadata['ip_addresses'] else 'None'}
- Usernames Targeted: {', '.join(metadata['usernames']) if metadata['usernames'] else 'None'}
- Failed Attempts: {metadata['failed_attempts']}
- Total Lines: {metadata['line_count']}

## Raw Log:
{log}

## Your Task:
Analyze this log and respond in exactly this structure:

**SEVERITY:** [CRITICAL / HIGH / MEDIUM / LOW / CLEAN]

**ATTACK CLASSIFICATION:** [e.g. Brute Force, SQL Injection, Port Scan]

**WHAT HAPPENED:**
[2-3 sentences in plain English]

**INDICATORS OF COMPROMISE:**
[Suspicious IPs, usernames, patterns]

**RECOMMENDED ACTIONS:**
[3 concrete steps]
"""

@app.get("/")
def root():
    return {"status": "Aegis is running"}

@app.post("/analyze")
async def analyze_log(request: LogRequest):
    if not request.log_content.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty")

    if len(request.log_content) > 50000:
        raise HTTPException(status_code=400, detail="Log too large — paste a focused excerpt")

    metadata = preprocess_log(request.log_content)
    prompt = build_prompt(request.log_content, metadata)

    async def stream_response():
        yield f"data: {json.dumps({'type': 'metadata', 'data': metadata})}\n\n"

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama3.2:3b",
                    "prompt": prompt,
                    "stream": True,
                    "options": {"temperature": 0.1}
                }
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        try:
                            chunk = json.loads(line)
                            if "response" in chunk:
                                yield f"data: {json.dumps({'type': 'token', 'data': chunk['response']})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                        except json.JSONDecodeError:
                            continue

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"}
    )