from fastapi import FastAPI
from routers import users

app=FastAPI()
app.include_router(users.router)

@app.get("/health")
def health():
    return{"Status": "Healthy"}

@app.get("/")
def home():
    return {"message":"Atlas API is running"}



