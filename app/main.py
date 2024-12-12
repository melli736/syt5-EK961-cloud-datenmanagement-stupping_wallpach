from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Dino imports
from app import models
from app.database import engine
from app.auth import auth_controller

models.Base.metadata.create_all(bind=engine)

# Starting up FastAPI server
app = FastAPI()
app.include_router(auth_controller.router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
