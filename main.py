import os
import uuid
import time
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib

app = FastAPI()

# MOCKS
EXPECTED_USER = "OB_DP_Rappi"
EXPECTED_PASS = "OB_DP_Rappi_12345"

# Simulación simple de hash (puedes cambiar por hash real con HMAC/sha256 si quieres)
def generate_mock_hash(username, password):
    return f"hash_with_{username}_{password}"

expected_hash = hashlib.sha256(f"{EXPECTED_USER}:{EXPECTED_PASS}".encode()).hexdigest()

# Firma JWT con PS256
def sign_jwt(payload: dict) -> str:
    private_key = os.environ.get("SIGNING_KEY")
    if not private_key:
        raise RuntimeError("SIGNING_KEY env var is not set")

    headers = {
        "kid": "e-IbAW-iMyUnBrk3V-298AlSa1Q=",
        "typ": "JWT",
        "alg": "PS256"
    }

    return jwt.encode(claims=payload, key=private_key, algorithm="PS256", headers=headers)

# Simula un request como el tuyo con redirecciones
def follow_redirects(url: str):
    session = requests.Session()
    current_url = url
    history = []

    while True:
        print(f"\n→ GET {current_url}")
        response = session.get(current_url, allow_redirects=False)
        print(f"Status: {response.status_code}")
        history.append((current_url, response.status_code))

        for key, value in response.headers.items():
            print(f"{key}: {value}")

        if response.is_redirect or response.is_permanent_redirect:
            next_url = response.headers["Location"]
            print(f"\n\n🔁 Redirige a: {next_url}\n\n")
            current_url = next_url
        else:
            print("✅ No hay más redirecciones.\n")
            print("📄 HTML Final:")
            print(response.text[:1000])
            break

@app.get("/")
async def validate_and_redirect(request: Request):
    params = dict(request.query_params)
    security_hash = params.get("security_hash")
    oAuthUrl = params.get("oAuthUrl")

    if not security_hash:
        raise HTTPException(status_code=401, detail="Missing security_hash")
    if security_hash != expected_hash:
        raise HTTPException(status_code=403, detail="Invalid security_hash")

    try:
        unverified = jwt.get_unverified_claims(oAuthUrl)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid oAuthUrl token")

    # Crear nuevo JWT firmado
    ref_id = unverified.get("ref_id", str(uuid.uuid4()))
    correlation_id = unverified.get("correlation_id", str(uuid.uuid4()))
    now = int(time.time())

    new_payload = {
        "ref_id": ref_id,
        "aud": "authserver",
        "nbf": now,
        "status_code": "200",
        "bank_id": unverified.get("bank_id", "1012"),
        "correlation_id": correlation_id,
        "exp": now + 3 * 86400,
        "iat": now,
        "debtor_account_present": False,
        "jti": str(uuid.uuid4()),
        "status": "success"
    }

    signed_jwt = sign_jwt(new_payload)
    final_url = f"https://auth.stage.redebanopenfinance.com/{new_payload['bank_id']}/authorization.sca.oauth2?oAuthUrl={signed_jwt}"

    print("\n🚀 Iniciando request a endpoint final con redirecciones:")
    follow_redirects(final_url)

    return JSONResponse(content={
        "message": "Final request made",
        "final_url": final_url,
        "new_token": signed_jwt
    })
