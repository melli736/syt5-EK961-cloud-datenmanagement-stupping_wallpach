from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app import models
from app.database import engine
from app.auth import auth_controller

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)


models.Base.metadata.create_all(bind=engine)

# Starting up FastAPI server
app = FastAPI()
app.include_router(auth_controller.router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"], # Allows all origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Autorization"],
)


@app.get("/")
@limiter.limit("5/minute")  # Limit to 5 requests per minute
async def home(request: Request):
    return {"message": "Hello, world!"}
