from fastapi import FastAPI, Request, HTTPException
import requests

app = FastAPI()

# Auth Server Details
AUTH_SERVER_URL = "http://127.0.0.1:8000/token"  # Adjust if hosted elsewhere
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"
REDIRECT_URI = "http://127.0.0.1:8001/callback"  # Resource Server URL

@app.get("/callback")
def receive_code(code: str, state: str):
    print(code)
