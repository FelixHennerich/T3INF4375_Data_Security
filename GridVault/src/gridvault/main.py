from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gridvault.database import init_db
from gridvault.routers import admin, analysis, auth, metering, outages
from gridvault.services.crypto import IntegrityViolation
from gridvault.services.gateway import GatewayDenied


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield


app = FastAPI(title="GridVault", lifespan=lifespan)


@app.exception_handler(GatewayDenied)
async def gateway_denied_handler(_: Request, exc: GatewayDenied) -> JSONResponse:
    """Every authorization denial answers with the SAME generic message;
    the specific reason is reserved for the audit trail (A3/A5)."""
    return JSONResponse(status_code=exc.status, content={"detail": exc.client_message})


@app.exception_handler(IntegrityViolation)
async def integrity_violation_handler(_: Request, exc: IntegrityViolation) -> JSONResponse:
    """T5: an integrity violation is reported with the bound context,
    i.e. metering point and timestamp of the failed row."""
    return JSONResponse(status_code=409, content={"detail": str(exc)})


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
