import { useState, useRef } from "react";
import ReactMarkdown from "react-markdown";

const SAMPLE_LOGS = {
  "Brute Force SSH": `Dec 10 02:32:14 server sshd[1337]: Failed password for root from 192.168.1.105 port 52414 ssh2
Dec 10 02:32:15 server sshd[1337]: Failed password for root from 192.168.1.105 port 52415 ssh2
Dec 10 02:32:16 server sshd[1337]: Failed password for admin from 192.168.1.105 port 52416 ssh2
Dec 10 02:32:17 server sshd[1337]: Failed password for admin from 192.168.1.105 port 52417 ssh2
Dec 10 02:32:18 server sshd[1337]: Failed password for ubuntu from 192.168.1.105 port 52418 ssh2
Dec 10 02:32:19 server sshd[1337]: Failed password for ubuntu from 192.168.1.105 port 52419 ssh2
Dec 10 02:32:20 server sshd[1337]: Failed password for pi from 192.168.1.105 port 52420 ssh2
Dec 10 02:32:21 server sshd[1337]: Failed password for pi from 192.168.1.105 port 52421 ssh2
Dec 10 02:32:22 server sshd[1337]: Failed password for root from 192.168.1.105 port 52422 ssh2
Dec 10 02:32:23 server sshd[1337]: Failed password for root from 192.168.1.105 port 52423 ssh2
Dec 10 02:32:24 server sshd[1337]: Failed password for root from 192.168.1.105 port 52424 ssh2
Dec 10 02:32:25 server sshd[1337]: Failed password for root from 192.168.1.105 port 52425 ssh2
Dec 10 02:32:26 server sshd[1337]: Accepted password for root from 192.168.1.105 port 52426 ssh2
Dec 10 02:32:26 server sshd[1337]: pam_unix(sshd:session): session opened for user root by (uid=0)`,

  "SQL Injection": `192.168.2.201 - - [10/Dec/2024:14:22:01 +0000] "GET /search?q=laptops HTTP/1.1" 200 4823
192.168.2.201 - - [10/Dec/2024:14:22:45 +0000] "GET /search?q=1' OR '1'='1 HTTP/1.1" 200 9821
192.168.2.201 - - [10/Dec/2024:14:22:46 +0000] "GET /login?user=admin'-- HTTP/1.1" 302 0
192.168.2.201 - - [10/Dec/2024:14:22:47 +0000] "GET /search?q=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 312
192.168.2.201 - - [10/Dec/2024:14:22:48 +0000] "GET /search?q=1 UNION SELECT null,table_name FROM information_schema.tables-- HTTP/1.1" 200 15302
192.168.2.201 - - [10/Dec/2024:14:22:49 +0000] "GET /admin/dashboard HTTP/1.1" 200 8821
10.0.0.1 - - [10/Dec/2024:14:23:00 +0000] "GET /index.html HTTP/1.1" 200 1234`,

  "Privilege Escalation": `Dec 10 09:15:01 server sudo: developer : TTY=pts/0 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/bash
Dec 10 09:15:01 server sudo: pam_unix(sudo:session): session opened for user root by developer(uid=1001)
Dec 10 09:15:04 server su[2847]: Successful su for root by developer
Dec 10 09:15:04 server su[2847]: + /dev/pts/0 developer:root
Dec 10 09:15:04 server su[2847]: pam_unix(su:session): session opened for user root by developer(uid=0)
Dec 10 09:15:10 server sshd[2901]: Accepted publickey for developer from 10.10.10.55 port 43210 ssh2
Dec 10 09:15:22 server kernel: [UFW BLOCK] IN=eth0 SRC=10.10.10.55 DST=192.168.1.1 PROTO=TCP DPT=22
Dec 10 09:16:01 server cron[3001]: (root) CMD (cat /etc/shadow > /tmp/.hidden_dump)`,

  "Clean Traffic": `Dec 10 08:00:01 server sshd[901]: Accepted publickey for deploy from 10.0.0.5 port 44123 ssh2
Dec 10 08:00:01 server sshd[901]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Dec 10 08:05:22 server sshd[901]: pam_unix(sshd:session): session closed for user deploy
Dec 10 09:00:01 server CRON[1200]: (root) CMD (/usr/local/bin/backup.sh)
Dec 10 09:00:03 server backup.sh: Backup completed successfully. 2.3GB archived.
Dec 10 10:30:15 server sshd[1501]: Accepted publickey for alice from 10.0.0.12 port 55001 ssh2
Dec 10 10:45:00 server sshd[1501]: pam_unix(sshd:session): session closed for user alice`,
};

const SEVERITY_COLORS = {
  CRITICAL: "bg-red-900 text-red-300 border-red-700",
  HIGH: "bg-orange-900 text-orange-300 border-orange-700",
  MEDIUM: "bg-yellow-900 text-yellow-300 border-yellow-700",
  LOW: "bg-blue-900 text-blue-300 border-blue-700",
  CLEAN: "bg-green-900 text-green-300 border-green-700",
};

function MetadataPanel({ metadata }) {
  if (!metadata) return null;
  const hasFlags = metadata.failed_attempts > 0;

  return (
    <div className={`rounded-lg border p-4 mb-4 text-sm ${hasFlags ? "border-orange-700 bg-orange-950" : "border-green-700 bg-green-950"}`}>
      <p className="font-semibold text-gray-300 mb-2">Pre-analysis scan</p>
      <div className="grid grid-cols-2 gap-2 text-gray-400 mb-2">
        <span>Type: <strong className="text-gray-200">{metadata.log_type}</strong></span>
        <span>Lines: <strong className="text-gray-200">{metadata.line_count}</strong></span>
        <span>Failed attempts: <strong className="text-gray-200">{metadata.failed_attempts}</strong></span>
        <span>IPs found: <strong className="text-gray-200">{metadata.ip_addresses?.length || 0}</strong></span>
      </div>
      {metadata.ip_addresses?.length > 0 && (
        <p className="text-gray-400">IPs: <strong className="text-gray-200">{metadata.ip_addresses.join(", ")}</strong></p>
      )}
      {metadata.usernames?.length > 0 && (
        <p className="text-gray-400 mt-1">Usernames targeted: <strong className="text-gray-200">{metadata.usernames.join(", ")}</strong></p>
      )}
      {hasFlags
        ? <p className="text-orange-400 font-medium mt-2">⚠ Suspicious patterns detected in pre-scan</p>
        : <p className="text-green-400 font-medium mt-2">✓ No suspicious patterns detected in pre-scan</p>
      }
    </div>
  );
}

function SeverityBadge({ output }) {
  const match = output.match(/\*\*SEVERITY:\*\*\s*(CRITICAL|HIGH|MEDIUM|LOW|CLEAN)/i);
  if (!match) return null;
  const level = match[1].toUpperCase();
  const colors = SEVERITY_COLORS[level] || "";
  return (
    <span className={`inline-block px-3 py-1 rounded-full border text-xs font-bold tracking-widest mb-3 ${colors}`}>
      {level}
    </span>
  );
}

export default function App() {
  const [logText, setLogText] = useState("");
  const [output, setOutput] = useState("");
  const [metadata, setMetadata] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const outputRef = useRef(null);

  const analyze = async () => {
    if (!logText.trim()) return;
    setLoading(true);
    setOutput("");
    setMetadata(null);
    setError("");

    try {
      const res = await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log_content: logText }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Server error");
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let fullText = "";
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const parsed = JSON.parse(line.slice(6));
            if (parsed.type === "metadata") {
              setMetadata(parsed.data);
            } else if (parsed.type === "token") {
              fullText += parsed.data;
              setOutput(fullText);
              if (outputRef.current) {
                outputRef.current.scrollTop = outputRef.current.scrollHeight;
              }
            } else if (parsed.type === "done") {
              setLoading(false);
            }
          } catch {}
        }
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (name) => {
    setLogText(SAMPLE_LOGS[name]);
    setOutput("");
    setMetadata(null);
    setError("");
  };

  const copyReport = () => {
    navigator.clipboard.writeText(output);
  };

  const downloadReport = () => {
    const blob = new Blob([output], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aegis-incident-report.md";
    a.click();
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-mono">
      <div className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-green-400 font-bold text-lg tracking-wider">AEGIS</span>
          <span className="text-gray-500 text-sm">// intelligent log analyzer v1.0</span>
        </div>
        <span className="text-gray-600 text-xs">local · offline · private</span>
      </div>

      <div className="flex h-[calc(100vh-65px)]">
        <div className="w-1/2 flex flex-col border-r border-gray-800 p-4 gap-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <span className="text-gray-400 text-xs uppercase tracking-widest">Log Input</span>
            <div className="flex gap-2 flex-wrap">
              {Object.keys(SAMPLE_LOGS).map((name) => (
                <button
                  key={name}
                  onClick={() => loadSample(name)}
                  className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-400 hover:border-green-500 hover:text-green-400 transition-colors"
                >
                  {name}
                </button>
              ))}
            </div>
          </div>

          <textarea
            className="flex-1 bg-gray-900 border border-gray-700 rounded-lg p-4 text-sm text-gray-200 resize-none focus:outline-none focus:border-green-500 font-mono placeholder-gray-600"
            placeholder={"Paste your log here...\n\nOr click a sample above to load one."}
            value={logText}
            onChange={(e) => setLogText(e.target.value)}
          />

          <button
            onClick={analyze}
            disabled={loading || !logText.trim()}
            className="w-full py-3 rounded-lg font-bold text-sm tracking-widest transition-all bg-green-500 text-gray-950 hover:bg-green-400 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? "ANALYZING..." : "ANALYZE LOG"}
          </button>
        </div>

        <div className="w-1/2 flex flex-col p-4 gap-3">
          <div className="flex items-center justify-between">
            <span className="text-gray-400 text-xs uppercase tracking-widest">Analysis Report</span>
            {output && (
              <div className="flex gap-2">
                <button
                  onClick={copyReport}
                  className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-400 hover:border-green-500 hover:text-green-400 transition-colors"
                >
                  Copy
                </button>
                <button
                  onClick={downloadReport}
                  className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-400 hover:border-green-500 hover:text-green-400 transition-colors"
                >
                  Download .md
                </button>
              </div>
            )}
          </div>

          <div
            ref={outputRef}
            className="flex-1 bg-gray-900 border border-gray-700 rounded-lg p-4 overflow-y-auto"
          >
            {error && (
              <div className="text-red-400 text-sm border border-red-800 rounded p-3 mb-4">
                Error: {error}
              </div>
            )}

            {!output && !loading && !error && (
              <div className="text-gray-600 text-sm text-center mt-20">
                <p>No analysis yet.</p>
                <p className="mt-1">Load a sample or paste a log and click Analyze.</p>
              </div>
            )}

            {metadata && <MetadataPanel metadata={metadata} />}

            {output && <SeverityBadge output={output} />}

            {output && (
              <div className="prose prose-invert prose-sm max-w-none prose-headings:text-green-400 prose-strong:text-gray-200 prose-li:text-gray-300">
                <ReactMarkdown>{output}</ReactMarkdown>
              </div>
            )}

            {loading && !output && (
              <div className="text-green-400 text-sm animate-pulse">
                Scanning log...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}