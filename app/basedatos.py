import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from argon2 import PasswordHasher

load_dotenv()

# Se configura para usar SQLite en lugar de MySQL
URL_BD = "sqlite:///./database.db"

motor = create_engine(URL_BD, connect_args={"check_same_thread": False}, pool_pre_ping=True)
SesionLocal = sessionmaker(autocommit=False, autoflush=False, bind=motor)
Base = declarative_base()

def crear_jefe():
    from app import modelos
    db = SesionLocal()
    ph = PasswordHasher()
    try:
        jefe = db.query(modelos.Usuario).filter(modelos.Usuario.rol == "jefe").first()
        if not jefe:
            hash_contraseña = ph.hash("Contraseña123!")
            jefe = modelos.Usuario(
                nombre="Guillermo Pérez Hernández",
                correo="guillermo@gmail.com",
                rol="jefe",
                primer_login=False,
                contraseña=hash_contraseña,
                matricula="12345"
            )
            db.add(jefe)
            db.commit()
            print("Jefe creado en la base de datos.")
        else:
            print("Jefe ya existe en la base de datos.")
    finally:
        db.close()

def iniciar_bd():
    from app import modelos
    Base.metadata.create_all(bind=motor)
    crear_jefe()


