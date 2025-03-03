from fastapi import FastAPI, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError
from bson import ObjectId
app = FastAPI()

import os
from dotenv import load_dotenv

load_dotenv()
# MongoDB Setup
MONGO_URI = os.getenv("MONGO_URI")
client = AsyncIOMotorClient(MONGO_URI)
db = client.oauth_db

# OAuth Config
SECRET_KEY = os.getenv("SUPER_SECRET_KEY")
ALGORITHM = "HS256"

# Function to Verify Token and Get User
async def verify_token(access_token: str):
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        client_id = payload.get("client_id")
        print(user_id)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Fetch user from database
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        return user, client_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# Protected Resource: Get User Info
@app.get("/user")
async def get_user(access_token: str = Query(...)):
    user, client_id = await verify_token(access_token)
    print(user, client_id)
    if user:
        

        scope = user[str(client_id)]
        d = {}
        for i in scope:
            d[i] = user[i]
        return d
    

# Protected Resource: Get Secure Data
@app.get("/secure-data")
async def get_secure_data(access_token: str = Query(...)):
    user = await verify_token(access_token)
    return {"message": f"Hello, {user['username']}! This is protected data."}
