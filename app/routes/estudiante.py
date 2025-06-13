from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.auth import obtener_usuario_actual
from app.basedatos import SesionLocal

ruta = APIRouter()

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.get("/perfil")
def ver_perfil(usuario_actual = Depends(obtener_usuario_actual), db: Session = Depends(obtener_bd)):
    if usuario_actual.rol != "student":
        raise HTTPException(status_code=403, detail="No autorizado")
    return {
        "nombre": usuario_actual.nombre,
        "correo": usuario_actual.correo,
        "matricula": usuario_actual.matricula
    }
