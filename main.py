# main.py
from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from bson import ObjectId
from database import usuarios, tareas, notas, refresh_tokens, db
from models import UserLogin, UserCreate
from auth import generar_token, generar_refresh_token, decodificar_refresh, validar_token
from datetime import datetime
import bcrypt

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def home():
    return FileResponse("static/index.html")

@app.get("/login")
def login_get():
    return JSONResponse({"detail": "Usa POST /login con JSON: {username, password}."})

@app.post("/login")
async def login(datos: UserLogin):
    user = usuarios.find_one({"username": datos.username})
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Asegura bytes para checkpw si guardaste el hash como str
    stored_pw = user.get("password")
    if isinstance(stored_pw, str):
        stored_pw = stored_pw.encode("utf-8")

    if not bcrypt.checkpw(datos.password.encode("utf-8"), stored_pw):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # generar_token ahora retorna (token, jti)
    access_token, jti = generar_token(str(user["_id"]), user["role"])
    refresh_token = generar_refresh_token(str(user["_id"]))

    refresh_tokens.insert_one({
        "refresh_token": refresh_token,
        "user_id": str(user["_id"]),
        "created_at": datetime.utcnow()
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "jti": jti   # devuelto solo para pruebas (en prod no es necesario exponerlo)
    }

@app.post("/refresh")
async def refresh_token_endpoint(payload: dict = Body(...)):
    token = payload.get("refresh_token")
    if not token:
        raise HTTPException(status_code=400, detail="Falta refresh_token")

    doc = refresh_tokens.find_one({"refresh_token": token})
    if not doc:
        raise HTTPException(status_code=401, detail="Refresh token inválido o revocado")

    data = decodificar_refresh(token)  # valida firma y exp
    user_id = data.get("sub")
    user = usuarios.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # generar_token retorna (token, jti); aquí solo necesitamos el token
    new_access, _ = generar_token(str(user["_id"]), user["role"])
    return {"access_token": new_access, "token_type": "bearer"}

@app.post("/logout")
async def logout(payload: dict = Body(...)):
    token = payload.get("refresh_token")
    if not token:
        raise HTTPException(status_code=400, detail="Falta refresh_token")
    refresh_tokens.delete_one({"refresh_token": token})
    return {"msg": "Logout OK"}

# Revocar access token por jti (para pruebas de replay). En producción protégelo con rol admin.
@app.post("/revoke")
async def revoke_token(body: dict = Body(...)):
    jti = body.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Falta jti")
    db["revoked_tokens"].insert_one({"jti": jti, "revoked_at": datetime.utcnow()})
    return {"msg": "Token revocado", "jti": jti}

@app.get("/me")
async def me(usuario=Depends(validar_token)):
    return {"usuario": usuario["username"], "rol": usuario["role"]}

def rol_requerido(rol_permitido):
    async def wrapper(usuario=Depends(validar_token)):
        if usuario["role"] != rol_permitido:
            raise HTTPException(status_code=403, detail="No autorizado")
        return usuario
    return wrapper

@app.get("/usuarios")
async def listar_usuarios(usuario=Depends(rol_requerido("admin"))):
    usuarios_lista = usuarios.find({}, {"password": 0})
    return [{**u, "_id": str(u["_id"])} for u in usuarios_lista]

@app.post("/crear_usuario")
async def crear_usuario(data: UserCreate, usuario=Depends(rol_requerido("admin"))):
    if usuarios.find_one({"username": data.username}):
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    password_cifrada = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt())
    usuarios.insert_one({"username": data.username, "password": password_cifrada, "role": data.role})
    return {"msg": "Usuario creado exitosamente"}

@app.post("/subir_tarea")
async def subir_tarea(info: dict = Body(...), usuario=Depends(rol_requerido("profesor"))):
    info["profesor"] = usuario["username"]
    tareas.insert_one(info)
    return {"msg": "Tarea guardada exitosamente"}

@app.get("/estudiantes")
async def ver_estudiantes(usuario=Depends(rol_requerido("profesor"))):
    ests = usuarios.find({"role": "estudiante"}, {"password": 0})
    return [{**e, "_id": str(e["_id"])} for e in ests]

@app.get("/mis_notas")
async def ver_mis_notas(usuario=Depends(rol_requerido("estudiante"))):
    res = notas.find({"estudiante": usuario["username"]})
    return [{**n, "_id": str(n["_id"])} for n in res]

@app.post("/notas")
async def agregar_nota(request: dict, usuario=Depends(rol_requerido("profesor"))):
    notas.insert_one(request)
    return {"mensaje": "Nota registrada correctamente"}
