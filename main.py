from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ai_engine import analyze_security_logs, ask_log_assistant

app = FastAPI(title="SentinelAI Security Log Analyzer API", version="1.0.0")

class LogAnalyzeRequest(BaseModel):
    log_content: str

class LogQuestionRequest(BaseModel):
    log_content: str
    question: str

@app.get("/")
def health_check():
    return {"status": "online", "service": "SentinelAI SOC Engine"}

@app.post("/api/logs/analyze")
def analyze_logs_endpoint(payload: LogAnalyzeRequest):
    if not payload.log_content.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty.")
    try:
        result = analyze_security_logs(payload.log_content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logs/ask")
def ask_logs_endpoint(payload: LogQuestionRequest):
    if not payload.log_content.strip() or not payload.question.strip():
        raise HTTPException(status_code=400, detail="Both log content and question are required.")
    try:
        answer = ask_log_assistant(payload.log_content, payload.question)
        return {"answer": answer}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
