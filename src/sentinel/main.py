from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from sentinel.api.routes import router

app = FastAPI(
    title="Sentinel",
    version="0.6.0",
    description="Policy-gated, auditable incident response with Nebius-hosted NVIDIA reasoning",
)
app.include_router(router)

web_dir = Path(__file__).resolve().parent / "web"
app.mount("/assets", StaticFiles(directory=web_dir), name="assets")


@app.get("/", include_in_schema=False)
async def dashboard() -> HTMLResponse:
    return HTMLResponse((web_dir / "index.html").read_text())
