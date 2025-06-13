from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.reglas import CrearUsuario
from app.crud import crear_usuario
from app.auth import obtener_usuario_actual, enviar_correo
from app.basedatos import SesionLocal
from app.auth import ph
import string, random

ruta = APIRouter()

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.post("/registrar")
def registrar_usuario(usuario: CrearUsuario, db: Session = Depends(obtener_bd), usuario_actual = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo los administradores pueden registrar usuarios")
    
    longitud = 12
    caracteres = string.ascii_letters + string.digits
    contraseña_provisional = ''.join(random.choice(caracteres) for _ in range(longitud))
    contraseña_hash = ph.hash(contraseña_provisional)
    nuevo_usuario = crear_usuario(
        db,
        nombre=usuario.nombre,
        correo=usuario.correo,
        rol=usuario.rol,
        contraseña=contraseña_hash,
        matricula=usuario.matricula
    )

    enlace_cambio = f"http://localhost:8000/auth/establecer-contraseña?matricula={usuario.matricula}"

    cuerpo_correo = (
        f"Hola {usuario.nombre},\n\n"
        f"Tu cuenta ha sido creada exitosamente.\n"
        f"Tu contraseña provisional es: {contraseña_provisional}\n\n"
        f"PCambia tu contraseña lo antes posible siguiendo el link: \n{enlace_cambio}\n\n"
    )
    enviar_correo(
        destinatario=usuario.correo,
        asunto="Activa tu cuenta y cambia tu contraseña",
        cuerpo=cuerpo_correo
    )
    return {"mensaje": f"Usuario {usuario.nombre} creado correctamente"}
