from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Text, LargeBinary
from sqlalchemy.orm import relationship
from app.basedatos import Base

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(50), index=True)
    correo = Column(String(30), unique=True, index=True)
    contraseña = Column(String(256))
    matricula = Column(String(10), unique=True)
    rol = Column(String(15))
    primer_login = Column(Boolean, default=True)
    clave_publica = Column(Text, nullable=True)

    estudiante = relationship("Estudiante", uselist=False, back_populates="usuario", cascade="all, delete-orphan")

class Estudiante(Base):
    __tablename__ = "estudiantes"
    id = Column(Integer, ForeignKey("usuarios.id"), primary_key=True)
    telefono = Column(Integer)

    usuario = relationship("Usuario", back_populates="estudiante")
    documentos = relationship("Documento", back_populates="estudiante", cascade="all, delete")
    historial= relationship("Historial_Academico", back_populates="estudiante")

class Documento(Base):
    __tablename__ = "documentos"
    id = Column(Integer, primary_key=True, index=True)
    id_estudiante = Column(Integer, ForeignKey("estudiantes.id"))
    nombre_archivo = Column(String(20))
    datos = Column(Text)

    estudiante = relationship("Estudiante", back_populates="documentos")

class Historial_Academico(Base):
    __tablename__ = "historiales"
    id = Column(Integer, primary_key=True, index=True)
    id_estudiante = Column(Integer, ForeignKey("estudiantes.id"))
    semestre = Column(String(10))
    materia = Column(String(30))
    calificacion = Column(String(5))
    ultima_modificacion = Column(String(100), nullable=True)

    estudiante = relationship("Estudiante", back_populates="historial")