import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from scanner import TokenScanner

app = FastAPI(title="RugGuard Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = TokenScanner()

@app.get("/")
async def serve_index():
    return FileResponse("index.html")

@app.post("/scan")
async def scan_token(request: dict):
    address = request.get("address")
    chain_id = request.get("chain_id", 1)
    if not address:
        return {"error": "address required"}
    try:
        result = await scanner.scan_token(address, chain_id)
        return result
    except Exception as e:
        return {"error": str(e)}

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

app.mount("/static", StaticFiles(directory="."), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
