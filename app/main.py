from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from .basedatos import iniciar_bd
from .routes import jefe, usuario, estudiante, staff
from dotenv import load_dotenv

load_dotenv()
iniciar_bd()

app = FastAPI(
    title="Plataforma de Gestión Académica",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(usuario.ruta, prefix="/auth", tags=["Autenticación"])
app.include_router(jefe.ruta, prefix="/jefe", tags=["Administración"])
app.include_router(estudiante.ruta, prefix="/estudiante", tags=["Estudiantes"])
app.include_router(staff.router, prefix="/staff", tags=["Staff"])
