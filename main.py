import os
from typing import Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scanner import TokenScanner
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="RugGuard Agent",
    description="AI-powered token security scanner for Web3",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = TokenScanner()

class TokenScanRequest(BaseModel):
    address: str
    chain_id: int = 1  # Default Ethereum

class TokenScanResponse(BaseModel):
    address: str
    chain_id: int
    risk_score: int  # 0-100
    risk_level: str  # Safe, Caution, Danger, Scam
    is_honeypot: bool
    is_mintable: bool
    is_proxy: bool
    owner_can_change_balance: bool
    lp_locked: bool
    top_holder_pct: float
    owner_pct: float
    findings: list[str]
    recommendation: str

@app.get("/")
async def root():
    return {"message": "RugGuard Agent API", "version": "0.1.0"}

@app.post("/scan", response_model=TokenScanResponse)
async def scan_token(request: TokenScanRequest):
    try:
        result = await scanner.scan_token(request.address, request.chain_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/chains")
async def get_supported_chains():
    return {
        "chains": [
            {"id": 1, "name": "Ethereum"},
            {"id": 8453, "name": "Base"},
            {"id": 56, "name": "BNB Chain"},
            {"id": 137, "name": "Polygon"},
            {"id": 42161, "name": "Arbitrum"},
            {"id": 10, "name": "Optimism"},
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
