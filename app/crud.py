from sqlalchemy.orm import Session
from app import modelos
from fastapi import HTTPException

def obtener_usuario(db: Session, matricula: str):
    return db.query(modelos.Usuario).filter(modelos.Usuario.matricula == matricula).first()

def crear_usuario(db: Session, nombre: str, correo: str, rol: str, contraseña: str, matricula: str):
    usuario = modelos.Usuario(nombre=nombre, correo=correo, rol=rol, contraseña=contraseña, matricula=matricula)
    db.add(usuario)
    db.commit()
    db.refresh(usuario)
    return usuario

def crear_estudiante(db: Session, matricula: str, telefono: int):
    estudiante = modelos.Estudiante(id=matricula, telefono=telefono)
    db.add(estudiante)
    db.commit()
    db.refresh(estudiante)
    return estudiante

def actualizar_contraseña(db: Session, matricula: str, nueva_contraseña_hash: str):
    usuario = db.query(modelos.Usuario).filter(modelos.Usuario.matricula == matricula).first()
    if usuario:
        usuario.contraseña = nueva_contraseña_hash
        usuario.primer_login = False
        db.commit()
        db.refresh(usuario)
    return usuario

def eliminar_usuario(db: Session, matricula: str):
    usuario = db.query(modelos.Usuario).filter(modelos.Usuario.matricula == matricula).first()
    if usuario:
        db.delete(usuario)
        db.commit()
        return True
    return False

def actualizar_calificaciones(db: Session, matricula_estudiante: str, calificaciones: dict, matricula_modificador: str, llave_privada: str):
    usuario = db.query(modelos.Usuario).filter_by(matricula=matricula_estudiante, rol="estudiante").first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Estudiante no encontrado")
    estudiante = db.query(modelos.Estudiante).filter_by(id=usuario.id).first()
    if not estudiante:
        raise HTTPException(status_code=404, detail="Estudiante no encontrado")
    modificador = db.query(modelos.Usuario).filter_by(matricula=matricula_modificador).first()
    if not modificador or modificador.rol not in ["jefe", "staff"]:
        raise HTTPException(status_code=403, detail="No autorizado para modificar calificaciones")
    for materia, calificacion in calificaciones.items():
        historial = db.query(modelos.Historial_Academico).filter_by(id_estudiante=estudiante.id, materia=materia).first()
        if historial:
            historial.calificacion = calificacion
            historial.ultima_modificacion = f"Modificado por {modificador.nombre} ({modificador.matricula})"
        else:
            new_historial = modelos.Historial_Academico(
                id_estudiante=estudiante.id,
                materia=materia,
                calificacion=calificacion,
                ultima_modificacion=f"Modificado por {modificador.nombre} ({modificador.matricula})"
            )
            db.add(new_historial)
    db.commit()