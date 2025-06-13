from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from app.basedatos import SesionLocal
from app.reglas import Token
from app.crud import obtener_usuario, actualizar_contraseña
from app.auth import ph
from app.reglas import CambioContraseña

load_dotenv()
llave = os.getenv("Clave_Secreta")
algoritmo = "HS256"

ruta = APIRouter()

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.post("/token", response_model=Token)
def login(datos: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(obtener_bd)):
    usuario = obtener_usuario(db, datos.username)
    if not usuario or not ph.verify(usuario.contraseña, datos.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    
    data = {"sub": usuario.matricula, "rol": usuario.rol}
    expire = datetime.now(timezone.utc) + timedelta(hours=2)
    token = jwt.encode({**data, "exp": expire}, llave, algorithm=algoritmo)

    return {"access_token": token, "token_type": "bearer"}

@ruta.post("/establecer-contraseña")
def establecer_contraseña(matricula: str = Query(...), cambio: CambioContraseña = Depends(), db: Session = Depends(obtener_bd)):
    usuario = obtener_usuario(db, matricula)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    nueva_contraseña_hash = ph.hash(cambio.nueva_contraseña)
    actualizar_contraseña(db, matricula, nueva_contraseña_hash)

    return {"mensaje": "Contraseña actualizada correctamente"}
