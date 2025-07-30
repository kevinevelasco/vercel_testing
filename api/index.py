from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
import os

app = FastAPI()

@app.get("/")
async def read_root(request: Request):
    params = dict(request.query_params)
    security_hash = params.get("security_hash")
    oAuthUrl = params.get("oAuthUrl")

    if not security_hash:
        raise HTTPException(status_code=401, detail="Missing security_hash")
    
    if security_hash != "hash_with_clientid_username_password":
        raise HTTPException(status_code=403, detail="Invalid security_hash")

    try:
        # decodifica el JWT sin verificar firma (solo payload)
        payload = jwt.get_unverified_claims(oAuthUrl)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid oAuthUrl token")

    return JSONResponse(content={
        "message": "Valid request",
        "decoded_oauth": payload,
        "security_hash": security_hash
    })
