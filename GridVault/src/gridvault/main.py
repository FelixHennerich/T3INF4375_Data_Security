from fastapi import FastAPI


app = FastAPI(title="GridVault")


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


def main() -> None:
    import uvicorn

    uvicorn.run("gridvault.main:app", host="127.0.0.1", port=8000, reload=True)