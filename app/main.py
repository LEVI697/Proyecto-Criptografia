from fastapi import FastAPI
from app.basedatos import iniciar_bd
from app.routes import jefe, usuario, estudiante
from dotenv import load_dotenv

load_dotenv()
iniciar_bd()

app = FastAPI(
    title="Plataforma de Gestión Académica",
    version="1.0.0"
)

app.include_router(usuario.ruta, prefix="/auth", tags=["Autenticación"])
app.include_router(jefe.ruta, prefix="/jefe", tags=["Administración"])
app.include_router(estudiante.ruta, prefix="/estudiante", tags=["Estudiantes"])
