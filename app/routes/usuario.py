from fastapi import APIRouter, Depends, HTTPException, status, Header, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from app.basedatos import SesionLocal
from app.schemas import GenerarToken, CambioContraseña, ValidarContraseña
from app.crud import obtener_usuario, actualizar_contraseña
from app.auth import ph, jwt, llave, obtener_usuario_actual
from app.modelos import Usuario
from Crypto.PublicKey import RSA

load_dotenv()
llave = os.getenv("Clave_Secreta")
ruta = APIRouter()

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.post("/login", response_model=GenerarToken)
def login(datos: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(obtener_bd)):
    usuario = obtener_usuario(db, datos.username)
    if not usuario or not ph.verify(usuario.contraseña, datos.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    
    datos = {"sub": usuario.matricula, "rol": usuario.rol}
    tiempo = datetime.now(timezone.utc) + timedelta(hours=2)
    token = jwt.encode({**datos, "exp": tiempo}, llave, algorithm="HS256")

    return {"access_token": token, "token_type": "bearer"}

@ruta.post("/validar-contraseña")
def validar_contraseña(datos: ValidarContraseña, db: Session = Depends(obtener_bd)):
    usuario = obtener_usuario(db, datos.matricula)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    try:
        if not ph.verify(usuario.contraseña, datos.contraseña_provisional):
            raise HTTPException(status_code=401, detail="Contraseña provisional incorrecta")
    except:
        raise HTTPException(status_code=401, detail="Contraseña provisional incorrecta")

    tiempo = datetime.now(timezone.utc) + timedelta(minutes=10)
    token = jwt.encode({"sub": usuario.matricula, "cambio_pass": True, "exp": tiempo}, llave, algorithm="HS256")
    return {"change_token": token}

@ruta.post("/establecer-contraseña")
def establecer_contraseña(datos: CambioContraseña, change_token: str = Header(..., alias="Authorizacion"), db: Session = Depends(obtener_bd)):
    if change_token.lower().startswith("bearer "):
        change_token = change_token[7:]

    try:
        payload = jwt.decode(change_token, llave, algorithms=["HS256"])
        matricula = payload.get("sub")
        cambio = payload.get("cambio_pass")
        if not matricula or not cambio:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

    usuario = db.query(Usuario).filter(Usuario.matricula == matricula).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if not usuario.primer_login:
        raise HTTPException(status_code=403, detail="No autorizado para cambiar contraseña")

    actualizar_contraseña(db, usuario.matricula, datos.nueva_contraseña)

    return {"mensaje": "Contraseña establecida correctamente."}

@ruta.post("/generar-claves")
def generar_claves(db: Session = Depends(obtener_bd), usuario: Usuario = Depends(obtener_usuario_actual)):
    if usuario.rol not in ["jefe", "staff"]:
        raise HTTPException(status_code=403, detail="Solo jefes y staff pueden generar claves")

    llave = RSA.generate(2048)
    llave_privada = llave.export_key()
    llave_publica = llave.publickey().export_key()

    usuario = db.merge(usuario)
    usuario.clave_publica = llave_publica.decode("utf-8")
    db.commit()
    db.refresh(usuario)

    return Response(
        content=llave_privada,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=llave_privada.pem"}
    )