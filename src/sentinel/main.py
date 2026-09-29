from fastapi import FastAPI

from sentinel.api.routes import router

app = FastAPI(
    title="Sentinel",
    version="0.1.0",
    description="Deterministic counterfactual incident-response foundation",
)
app.include_router(router)

