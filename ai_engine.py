import os
import json
import time
from pathlib import Path
from google import genai
from google.genai import types
from pydantic import BaseModel
from dotenv import load_dotenv


env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

class SecurityFinding(BaseModel):
    attack_type: str
    severity: str  
    source_ip: str
    evidence: str
    mitigation_command: str

class LogAnalysisResponse(BaseModel):
    overall_threat_level: str  
    executive_summary: str
    total_events_analyzed: int
    findings: list[SecurityFinding]

def get_available_models() -> list[str]:
    preferred = ["gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash"]
    available = []
    try:
        for m in client.models.list():
            name = m.name.replace("models/", "")
            if "gemini" in name and "flash" in name and "tts" not in name and "image" not in name:
                available.append(name)
    except Exception:
        return preferred

    ordered = [m for m in preferred if m in available] + [m for m in available if m not in preferred]
    return ordered if ordered else preferred

def analyze_security_logs(log_content: str) -> dict:
    prompt = f"""
    You are a Senior SOC (Security Operations Center) Analyst.
    Analyze the following raw server/application/authentication logs for security threats, anomalies, or attacks (e.g., SSH brute-force, SQL injection, path traversal, privilege escalation, port scanning).

    Instructions:
    1. Determine the overall_threat_level ('Critical', 'High', 'Moderate', or 'Safe').
    2. Write a concise executive_summary (2-3 sentences) of what is happening in the logs.
    3. Estimate total_events_analyzed based on the log entries.
    4. List each distinct security finding with:
       - attack_type (e.g., "SSH Brute-Force Attempt")
       - severity ('Critical', 'High', 'Medium', or 'Low')
       - source_ip (the offending IP address, or "N/A" if local/internal)
       - evidence (brief quote or description from the log)
       - mitigation_command (exact actionable Linux/ufw/iptables/fail2ban command or remediation step)

    Raw Logs:
    {log_content}
    """

    models_to_try = get_available_models()
    last_error = None

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=LogAnalysisResponse,
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            last_error = e
            time.sleep(0.5)
            continue

    raise RuntimeError(f"AI analysis failed across models. Last error: {last_error}")

def ask_log_assistant(log_content: str, question: str) -> str:
    prompt = f"""
    You are a Cybersecurity Incident Response Assistant. Answer the user's question strictly based on the provided log data.
    Be concise, technical, and cite specific timestamps, IPs, or log lines when relevant.

    Log Data:
    {log_content}

    User Question:
    {question}
    """

    models_to_try = get_available_models()
    last_error = None

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2),
            )
            return response.text
        except Exception as e:
            last_error = e
            time.sleep(0.5)
            continue

    raise RuntimeError(f"AI Q&A failed across models. Last error: {last_error}")
