from fastapi import FastAPI
from gridvault.routers import admin, analysis, auth, metering, outages

app = FastAPI(title="GridVault")


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(metering.router)
app.include_router(analysis.router)
app.include_router(outages.router)
app.include_router(admin.router)


def main() -> None:
    import uvicorn

    uvicorn.run("gridvault.main:app", host="127.0.0.1", port=8000, reload=True)
