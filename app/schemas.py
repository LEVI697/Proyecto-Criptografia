from pydantic import BaseModel, EmailStr, Field
from typing import Annotated

class CrearUsuario(BaseModel):
    nombre: Annotated[str, Field(min_length=3)]
    correo: EmailStr
    rol: Annotated[str, Field(pattern="^(jefe|staff|estudiante)$")]
    matricula: Annotated[str, Field(min_length=10, max_length=10, pattern=r'^\d+$', description="Debe ser de 10 números")]

class GenerarToken(BaseModel):
    access_token: str
    token_type: str

class ValidarContraseña(BaseModel):
    matricula: int = Field(...)
    contraseña_provisional: str = Field(...)

class CambioContraseña(BaseModel):
    nueva_contraseña: Annotated[
        str,
        Field(
            min_length=8,
            pattern=r"^[\w\W]+$",
            description="Debe tener al menos una minúscula, una mayúscula, un número y un carácter especial."
        )
    ]

class DatosAlumno(BaseModel):
    celular: str

class Documento(BaseModel):
    nombre_archivo: str
    datos: str