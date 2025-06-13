import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from argon2 import PasswordHasher

load_dotenv()

URL_BD = os.getenv("URL_BaseDatos")
if not URL_BD:
    raise RuntimeError("La URL de la base de datos no está configurada en .env")

motor = create_engine(URL_BD, pool_pre_ping=True)
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
                nombre="Guillermo Pérez",
                correo="guillermo@gmail.com",
                rol="jefe",
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


