from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Header
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from app.basedatos import SesionLocal
from app.schemas import GenerarToken, CambioContraseña, ValidarContraseña
from app.crud import obtener_usuario, actualizar_contraseña
from app.auth import ph, llave, obtener_usuario_actual
from app.modelos import Usuario
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

load_dotenv()
llave = os.getenv("Clave_Secreta")
ruta = APIRouter()
templates = Jinja2Templates(directory="templates")

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.get("/login", response_class=HTMLResponse)
def mostrar_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@ruta.post("/login", response_class=HTMLResponse)
def procesar_login_web(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(obtener_bd)):
    usuario = obtener_usuario(db, username)
    if not usuario or not ph.verify(usuario.contraseña, password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Credenciales inválidas"})
    
    datos_token = {"sub": usuario.matricula, "rol": usuario.rol}
    tiempo = datetime.now(timezone.utc) + timedelta(hours=2)
    token = jwt.encode({**datos_token, "exp": tiempo}, llave, algorithm="HS256")
    
    if usuario.rol == "jefe":
        respuesta = RedirectResponse(url="/jefe/dashboard", status_code=303)
        respuesta.set_cookie(key="access_token", value=token, httponly=True)
        return respuesta
    elif usuario.rol == "staff":
        respuesta = RedirectResponse(url="/staff/dashboard", status_code=303)
        respuesta.set_cookie(key="access_token", value=token, httponly=True)
        return respuesta
    if usuario.rol == "estudiante":
        respuesta = RedirectResponse(url="/estudiante/dashboard", status_code=303)
        respuesta.set_cookie(key="access_token", value=token, httponly=True)
        return respuesta
    
    return templates.TemplateResponse("bienvenida.html", {"request": request, "usuario": usuario})

@ruta.post("/establecer-contraseña")
def establecer_contraseña(
    nueva_contrasena: str = Form(...),
    provisional: str = Form(...),
    token: str = Form(...),
    db: Session = Depends(obtener_bd)
):
    try:
        payload = jwt.decode(token, llave, algorithms=["HS256"])
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

    try:
        if not ph.verify(usuario.contraseña, provisional):
            raise HTTPException(status_code=401, detail="Contraseña provisional incorrecta")
    except:
        raise HTTPException(status_code=401, detail="Contraseña provisional incorrecta")

    contraseña_hash = ph.hash(nueva_contrasena)
    actualizar_contraseña(db, usuario.matricula, contraseña_hash)

    return RedirectResponse(url="/auth/login", status_code=303)

@ruta.post("/generar-claves")
def generar_claves(db: Session = Depends(obtener_bd), usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol not in ["jefe", "staff"]:
        raise HTTPException(status_code=403, detail="Solo jefes y staff pueden generar claves")

    llave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privada_pem = llave_privada.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    publica_pem = llave_privada.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    usuario_actual = db.merge(usuario_actual)
    usuario_actual.clave_publica = publica_pem.decode("utf-8")
    db.commit()
    db.refresh(usuario_actual)

    return Response(
        content=privada_pem,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=llave_privada.pem"}
    )

@ruta.get("/logout")
def logout(response: Response):
    redirect = RedirectResponse(url="/auth/login", status_code=303)
    redirect.delete_cookie(key="access_token")
    return redirect

@ruta.get("/establecer-contraseña", response_class=HTMLResponse)
def mostrar_establecer_contrasena(request: Request, matricula: str):
    datos_token = {"sub": matricula, "cambio_pass": True}
    tiempo = datetime.now(timezone.utc) + timedelta(hours=1)
    token = jwt.encode({**datos_token, "exp": tiempo}, llave, algorithm="HS256")

    return templates.TemplateResponse("establecer_contrasena.html", {
        "request": request,
        "token": token
    })