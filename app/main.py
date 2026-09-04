from fastapi import FastAPI
import uvicorn
from app.router.gitnexus import router as gitnexus_router
from app.router.scan import router as scan_router
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(title="GitNexus Python API", version="0.1.0")
app.include_router(gitnexus_router)
app.include_router(scan_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
