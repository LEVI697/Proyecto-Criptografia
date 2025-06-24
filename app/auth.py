from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from jose import JWTError, jwt
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
#from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from app.crud import obtener_usuario
from app.basedatos import SesionLocal
from typing import Optional

load_dotenv()
llave = os.getenv("Clave_Secreta")
#esquema = OAuth2PasswordBearer(tokenUrl="/auth/login")
ph = PasswordHasher()

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

def verificar_usuario(db: Session, matricula: str, contraseña: str):
    user = obtener_usuario(db, matricula)
    if not user:
        return None
    try:
        ph.verify(user.contraseña, contraseña
        )
    except:
        return None
    return user

def obtener_usuario_actual(request: Request, token: Optional[str] = None, db: Session = Depends(obtener_bd)):
    error_credenciales = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token is None:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):]

    if token is None:
        token = request.cookies.get("access_token")

    try:
        payload = jwt.decode(token, llave, algorithms=["HS256"])
        matricula: str = payload.get("sub")
        if matricula is None:
            raise error_credenciales
    except JWTError:
        raise error_credenciales
    
    usuario = obtener_usuario(db, matricula)
    if usuario is None:
        raise error_credenciales
    return usuario

def enviar_correo(destinatario: str, asunto: str, cuerpo: str, adjunto: bytes = None, nombre_adjunto: str = None):
    smtp_servidor = os.getenv("Servidor_SMTP")
    smtp_puerto = os.getenv("Puerto_SMTP")
    smtp_usuario = os.getenv("Usuario_SMTP")
    smtp_contraseña = os.getenv("Contrasena_SMTP")

    mensaje = MIMEMultipart()
    mensaje["From"] = smtp_usuario
    mensaje["To"] = destinatario
    mensaje["Subject"] = asunto

    mensaje.attach(MIMEText(cuerpo, "plain"))

    if adjunto and nombre_adjunto:
        parte = MIMEApplication(adjunto)
        parte.add_header("Content-Disposition", f'attachment; filename="{nombre_adjunto}"')
        mensaje.attach(parte)

    with smtplib.SMTP(smtp_servidor, smtp_puerto) as server:
        server.starttls()
        server.login(smtp_usuario, smtp_contraseña)
        server.send_message(mensaje)