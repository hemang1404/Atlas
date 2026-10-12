from contextlib import asynccontextmanager
from fastapi import FastAPI
from core.config import settings
from routers import users


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Application startup & shutdown lifecycle
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)
app.include_router(users.router)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/")
def home():
    return {"message": "Atlas API is running"}
