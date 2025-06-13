from sqlalchemy.orm import Session
from app import modelos

def obtener_usuario(db: Session, matricula: str):
    return db.query(modelos.Usuario).filter(modelos.Usuario.matricula == matricula).first()

def crear_usuario(db: Session, nombre: str, correo: str, rol: str, contraseña: str, matricula: str):
    user = modelos.Usuario(nombre=nombre, correo=correo, rol=rol, contraseña=contraseña, matricula=matricula)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def actualizar_contraseña(db: Session, matricula: str, nueva_contraseña_hash: str):
    usuario = db.query(modelos.Usuario).filter(modelos.Usuario.matricula == matricula).first()
    if usuario:
        usuario.contraseña = nueva_contraseña_hash
        db.commit()
        db.refresh(usuario)
    return usuario
