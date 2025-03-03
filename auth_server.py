from fastapi import FastAPI, Request, HTTPException, Form, Depends, Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import uuid
import bcrypt
import json
from bson import ObjectId
from fastapi import Query
import os
from dotenv import load_dotenv

app = FastAPI()
templates = Jinja2Templates(directory="templates")

load_dotenv()
# MongoDB Setup
MONGO_URI = os.getenv("MONGO_URI")
client = AsyncIOMotorClient(MONGO_URI)
db = client.oauth_db

# OAuth Config
SECRET_KEY = os.getenv("SUPER_SECRET_KEY")
ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES_LOGIN_DAYS = 7

ACCESS_TOKEN_EXPIRE_MINUTES = 5
REFRESH_TOKEN_EXPIRE_DAYS = 30

async def create_token_2(user_id: str, client_id: str, expires_delta: timedelta):
    expire = datetime.utcnow() + expires_delta
    return jwt.encode({"sub": user_id, "exp": expire, "client_id": client_id}, SECRET_KEY, algorithm=ALGORITHM)

async def create_token(user_id: str, expires_delta: timedelta):
    expire = datetime.utcnow() + expires_delta
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

async def verify_token_2(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

async def verify_token(token: str, response: RedirectResponse = None):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        # If user_id is not present, token is invalid
        if not user_id:
            return user_id  

        # Generate a new token and set it in the cookie
        new_token = await create_token(user_id, timedelta(days=ACCESS_TOKEN_EXPIRE_MINUTES_LOGIN_DAYS))
        
        response.set_cookie(key="access_token", value=new_token, httponly=True)

        return user_id  # Return the valid user ID
    except JWTError:
        return None  # Invalid token

@app.get("/login")
async def login_page(request: Request, state: str = None, client_id: str = None, redirect_uri: str = "http://localhost:8001/callback",scope: str = "_id username password", access_token: str = Cookie(None)):
    if access_token:
        print(redirect_uri)
        response = templates.TemplateResponse(
            "consent.html",
            {
                "request": request,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,  # Convert scope to list
                "state": state
            }
        )
        user_id = await verify_token(access_token, response)
        if user_id:

            return response
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Query("/consent")):
    user = await db.users.find_one({"username": username})
    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = await create_token(str(user["_id"]), timedelta(days=ACCESS_TOKEN_EXPIRE_MINUTES_LOGIN_DAYS))
    #IMPORTENT response = RedirectResponse(url=f"/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=openid&state={state}")
    if next:
        response = RedirectResponse(url=next)
    else:
        response = RedirectResponse(url="/dashboard")

    response.set_cookie(key="access_token", value=token, httponly=True)

    # response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/consent")
async def consent(request: Request, client_id: str, redirect_uri: str, scope: str, state: str, access_token: str = Cookie(None)):
    if not access_token:
        return RedirectResponse(url="/login")
    else:
        response = templates.TemplateResponse(
            "consent.html",
            {
                "request": request,
                "client_id": client_id,
                "redirect_uri": redirect_uri ,
                "scope": scope,  # Convert scope to list
                "state": state
            }
        )
        user_id = await verify_token(access_token, response)
        if user_id:
            return response

from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.post("/register")
async def register(username: str, password: str):
    hashed_password = pwd_context.hash(password)  # Hash the password
    user_data = {"username": username, "password": hashed_password}
    
    existing_user = await db["users"].find_one({"username": username})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    await db["users"].insert_one(user_data)
    return {"message": "User registered successfully"}

@app.get("/dashboard")
async def dashboard(request: Request, access_token: str = Cookie(None)):
    if not access_token:
        print(1)
        return templates.TemplateResponse("login.html", {"request": request})
    
    user_id = await verify_token_2(access_token)
    if not user_id:
        print(2)
        return templates.TemplateResponse("login.html", {"request": request})
    response = templates.TemplateResponse("dashboard.html", {"request": request, "user_id": user_id})
    user_id = await verify_token(access_token, response)
    # user = await db.users.find_one({"_id": user_id})
    return response

@app.post("/dashboard")
async def dashboard(request: Request, access_token: str = Cookie(None)):
    if not access_token:
        return templates.TemplateResponse("login.html", {"request": request})
    
    user_id = await verify_token(access_token)
    if not user_id:
        return templates.TemplateResponse("login.html", {"request": request})
    
    user = await db.users.find_one({"_id": user_id})
    return templates.TemplateResponse("dashboard.html", {"request": request, "user_id": user_id, "user_name": user["name"]})


@app.get("/authorize")
async def authorize(client_id: str, scope: str, state: str, redirect_uri: str, access_token: str = Cookie(None)):
    if not access_token:
        return RedirectResponse(url="/login")
    response = RedirectResponse(url="/login")
    user_id = await verify_token_2(access_token)
    if not user_id:
        return RedirectResponse(url="/login")
    
    client = await db.clients.find_one({"client_id": client_id})
    if not client:
        return JSONResponse(content={"error": "Invalid client_id"}, status_code=400)
    print(user_id)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {client_id:  scope.split(" ")}}
    )

    auth_code = str(uuid.uuid4())
    await db.authorization_codes.insert_one({"code": auth_code, "user_id": user_id, "client_id": client_id})
    redirect_url = f"{redirect_uri}?code={auth_code}&state={state}" #TODO
    response = RedirectResponse(url=redirect_url)
    user_id = await verify_token(access_token, response)
    return response

@app.post("/token")
async def token(grant_type: str, code: str = None , refresh_token: str = None): #TODO, client_id: str, client_secret: str = Form(...)):
    # client = await db.clients.find_one({"client_id": client_id, "client_secret": client_secret}) #TODO
    # if not client:                                                                                TODO
    #     raise HTTPException(status_code=400, detail="Invalid client credentials")                 TODO

    if grant_type == "authorization_code":
        auth_code = await db.authorization_codes.find_one({"code": code})
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        user_id = auth_code["user_id"]
        client_id = auth_code["client_id"]
        await db.authorization_codes.delete_one({"code": code})
        
        access_token = await create_token_2(user_id,client_id, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        refresh_token = await create_token_2(user_id,client_id, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
        await db.refresh_tokens.insert_one({"refresh_token": refresh_token, "user_id": user_id})
        
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
    
    elif grant_type == "refresh_token":
        token_in_db = await db.refresh_tokens.find_one({"refresh_token": refresh_token})
        if not token_in_db:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        
        user_id = token_in_db["user_id"]
        new_access_token = await create_token(user_id, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": new_access_token, "token_type": "bearer"}
    
    raise HTTPException(status_code=400, detail="Invalid grant type")
