from fastapi import FastAPI

app = FastAPI(
    title="My FastAPI Project",
    description="My REST API",
    version="1.0.0"
)


@app.get("/")
async def root():
    return {
        "message": "Hello World"
    }


@app.get("/health")
async def health():
    return {
        "status": "ok"
    }