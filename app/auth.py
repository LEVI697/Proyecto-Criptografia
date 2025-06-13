from jose import JWTError, jwt
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from app.crud import obtener_usuario
from app.basedatos import SesionLocal

load_dotenv()
llave = os.getenv("Clave_Secreta")
esquema = OAuth2PasswordBearer(tokenUrl="/auth/login")
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
        ph.verify(user.contraseña, contraseña)
    except:
        return None
    return user

def obtener_usuario_actual(token: str = Depends(esquema), db: Session = Depends(obtener_bd)):
    error_credenciales = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
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

def enviar_correo(destinatario: str, asunto: str, cuerpo: str):
    smtp_servidor = os.getenv("Servidor_SMTP")
    smtp_puerto = os.getenv("Puerto_SMTP")
    smtp_usuario = os.getenv("Usuario_SMTP")
    smtp_contraseña = os.getenv("Contrasena_SMTP")

    msg = MIMEText(cuerpo)
    msg["Subject"] = asunto
    msg["From"] = smtp_usuario
    msg["To"] = destinatario

    with smtplib.SMTP(smtp_servidor, smtp_puerto) as server:
        server.starttls()
        server.login(smtp_usuario, smtp_contraseña)
        server.sendmail(smtp_usuario, destinatario, msg.as_string())
