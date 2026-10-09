from contextlib import asynccontextmanager
from fastapi import FastAPI
from db.session import engine
from models.base import Base
from routers import users


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables automatically if they don't exist
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Atlas API", lifespan=lifespan)
app.include_router(users.router)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/")
def home():
    return {"message": "Atlas API is running"}
