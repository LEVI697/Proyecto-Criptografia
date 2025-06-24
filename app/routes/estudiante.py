from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.auth import obtener_usuario_actual
from app.basedatos import SesionLocal
from app.modelos import Usuario

ruta = APIRouter()
templates = Jinja2Templates(directory="templates")


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

@ruta.get("/dashboard", response_class=HTMLResponse)
def estudiante_dashboard(request: Request, usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "estudiante":
        raise HTTPException(status_code=403, detail="No autorizado")
    return templates.TemplateResponse("estudiante_dashboard.html", {"request": request, "usuario": usuario_actual})