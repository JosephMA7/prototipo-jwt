# auth.py
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Request, status
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError
from bson import ObjectId
from database import usuarios, db  # <-- 'db' para consultar revoked_tokens
import uuid
import os

# Carga .env si existe
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Configuración JWT
SECRET_KEY = os.getenv("JWT_SECRET", "Gv54sX@JH83kjNsi88$kldpOOqz9LKsajLKWD9jsO3")
ALGORITHM  = os.getenv("JWT_ALG", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES  = int(os.getenv("JWT_EXPIRE_MIN", "40"))
REFRESH_TOKEN_EXPIRE_DAYS    = int(os.getenv("JWT_REFRESH_DAYS", "7"))

def _utc_now():
    return datetime.now(timezone.utc)

def generar_token(usuario_id: str, role: str):
    """
    Genera un ACCESS TOKEN con 'jti' (para permitir revocación por lista negra).
    Retorna: (token, jti)
    """
    now = _utc_now()
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(usuario_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,  # identificador único del token para revocación
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti

def generar_refresh_token(usuario_id: str) -> str:
    """
    Genera un REFRESH TOKEN (typ=refresh) de larga duración.
    """
    now = _utc_now()
    exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(usuario_id),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "typ": "refresh"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decodificar_refresh(token: str) -> dict:
    """
    Decodifica y valida un refresh token (firma/exp y typ=refresh).
    """
    try:
        data = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM],
            options={"require_exp": True, "verify_aud": False},
        )
        if data.get("typ") != "refresh":
            raise JWTError("Tipo de token inválido para refresh")
        return data
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

async def validar_token(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado o formato inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.split(" ", 1)[1].strip()

    try:
        data = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require_exp": True, "verify_aud": False},
        )

        user_id = data.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token sin 'sub'")

        jti = data.get("jti")
        if not jti:
            raise HTTPException(status_code=401, detail="Token sin 'jti'")

        # Bloqueo por lista negra: si el jti está revocado, se rechaza
        if db["revoked_tokens"].find_one({"jti": jti}):
            raise HTTPException(status_code=401, detail="Token revocado")

        user = usuarios.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        return {
            "_id": str(user["_id"]),
            "username": user.get("username"),
            "role": user.get("role"),
            "jti": jti,
        }

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
