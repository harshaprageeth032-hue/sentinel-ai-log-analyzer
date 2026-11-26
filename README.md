# SentinelAI — Intelligent Security Log & Incident Analyzer

An AI-powered Security Operations Center (SOC) tool built with **FastAPI**, **Streamlit**, and the **Google Gemini API**. SentinelAI ingests raw server, authentication, and web access logs to detect cyber threats, classify severity levels, generate actionable remediation commands, and enable natural-language forensic log investigation.

## Key Features
* **Automated Threat Detection & Triage:** Uses Gemini Structured Outputs (`Pydantic` schemas) to identify attacks (SSH brute-force, SQL injection, path traversal, privilege escalation), extract offending source IPs, and assign severity levels (`Critical`, `High`, `Medium`, `Low`).
* **Actionable Mitigation Generation:** Automatically recommends exact Linux firewall and remediation commands (e.g., `ufw`, `fail2ban`) tailored to each detected incident.
* **Forensic Log Q&A Assistant:** Context-aware conversational interface allowing security analysts to query uploaded log files in natural language.
* **Fault-Tolerant AI Architecture:** Dynamic model discovery with automatic fallback handling to maintain service reliability during API demand spikes.

## Tech Stack
* **Backend:** Python, FastAPI, Uvicorn, Pydantic
* **AI Integration:** Google GenAI SDK (Structured Outputs & Context-Aware Q&A)
* **Frontend:** Streamlit, Custom CSS, Google Material Symbols, JetBrains Mono

## Local Setup & Installation

1.Install dependencies:
pip install -r requirements.txt

2.Configure Environment Variables
GEMINI_API_KEY=your_gemini_api_key_here

3.Start the FastAPI Backend:
cd backend
python -m uvicorn main:app --reload

4.Launch the Streamlit Frontend (in a new terminal):
cd frontend
python -m streamlit run app.py
