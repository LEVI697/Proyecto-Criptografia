import io
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.schemas import CrearUsuario
from app.crud import crear_estudiante, crear_usuario, eliminar_usuario
from app.auth import obtener_usuario_actual, enviar_correo
from app.basedatos import SesionLocal
from app.auth import ph
import string, random
import base64
import os
from app.cifrado import cifrar_chacha20_poly1305, descifrar_chacha20_poly1305, generar_clave_chacha, cifrar_clave, descifrar_clave
from app.modelos import Documento, Usuario, Historial_Academico
from app.crud import actualizar_calificaciones


ruta = APIRouter()
templates = Jinja2Templates(directory="templates")

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.get("/dashboard", response_class=HTMLResponse)
def jefe_dashboard(request: Request, db: Session = Depends(obtener_bd), usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    staff_list = db.query(Usuario).filter(Usuario.rol == "staff").all()
    estudiantes = db.query(Usuario).filter(Usuario.rol == "estudiante").all()
    historiales = {}
    for estudiante in estudiantes:
        historial = db.query(Historial_Academico).filter_by(id_estudiante=estudiante.id).all()
        historiales[estudiante.matricula] = historial
    return templates.TemplateResponse("jefe_dashboard.html", {"request": request, "usuario": usuario_actual, "staff": staff_list, "estudiantes": estudiantes, "historiales": historiales})


@ruta.post("/dashboard/registrarStaff", response_class=HTMLResponse)
def registrar_staff(nombre: str = Form(...),
    correo: str = Form(...),
    matricula: str = Form(...), 
    db: Session = Depends(obtener_bd), 
    usuario_actual = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo los jefes pueden registrar miembros del staff")
    
    longitud = 10
    caracteres = string.ascii_letters + string.digits
    contraseña_provisional = ''.join(random.choice(caracteres) for _ in range(longitud))
    contraseña_hash = ph.hash(contraseña_provisional)
    
    nuevo_usuario = crear_usuario(
        db,
        nombre=nombre,
        correo=correo,
        rol="staff",
        contraseña=contraseña_hash,
        matricula=matricula
    )

    enlace_cambio = f"http://localhost:8000/auth/establecer-contraseña?matricula={matricula}"

    cuerpo = (
        f"Hola {nombre},\n\n"
        f"Has sido registrado como miembro del staff.\n"
        f"Tu matrícula es: {matricula}\n"
        f"Tu contraseña provisional es: {contraseña_provisional}\n"
        f"Para activar tu cuenta accede al siguiente link: \n{enlace_cambio}\n\n"
    )
    
    enviar_correo(destinatario=correo, asunto="Cambia la contraseña para activar tu cuenta", cuerpo=cuerpo)
    return RedirectResponse(url="/jefe/dashboard", status_code=303)

@ruta.post("/dashboard/eliminarStaff", response_class=HTMLResponse)
def eliminar_staff(matricula: str = Form(...), db: Session = Depends(obtener_bd),
                   usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo los jefes pueden eliminar miembros del staff")
    # Se elimina el usuario staff basado en la matrícula
    eliminado = eliminar_usuario(db, matricula)
    if not eliminado:
        raise HTTPException(status_code=404, detail="Miembro staff no encontrado")
    return RedirectResponse(url="/jefe/dashboard", status_code=303)

@ruta.post("/dashboard/registrarEstudiante", response_class=HTMLResponse)
async def registrar_estudiante(nombre: str = Form(...),
                         correo: str = Form(...),
                         matricula: str = Form(...),
                         telefono: str = Form(...),
                         documento: UploadFile = File(...),
                         llave_simetrica: UploadFile = File(...),
                         db: Session = Depends(obtener_bd),
                         usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo la administración puede registrar estudiantes")
    
    longitud = 10
    caracteres = string.ascii_letters + string.digits
    contraseña_provisional = ''.join(random.choice(caracteres) for _ in range(longitud))
    contraseña_hash = ph.hash(contraseña_provisional)
    nuevo_estudiante = crear_usuario(db, nombre=nombre, correo=correo, rol="estudiante", contraseña=contraseña_hash, matricula=matricula)

    crear_estudiante(db, matricula=nuevo_estudiante.id, telefono=telefono) 
    enlace_cambio = f"http://localhost:8000/auth/establecer-contraseña?matricula={matricula}"
    cuerpo = (
        f"Hola {nombre},\n\n"
        f"Has sido registrado como estudiante.\n"
        f"Tu matrícula es: {matricula}\n"
        f"Tu contraseña provisional es: {contraseña_provisional}\n"
        f"Inicia sesión y cambia tu contraseña en: {enlace_cambio}\n\n"
    )
    enviar_correo(destinatario=correo, asunto="Registro de Estudiante", cuerpo=cuerpo)

    # Leer archivos
    pdf_bytes = await documento.read()
    llave_bytes = await llave_simetrica.read()
    try:
        llave = base64.b64decode(llave_bytes)
    except Exception:
        llave = llave_bytes
    nonce, pdf_cifrado, tag = cifrar_chacha20_poly1305(pdf_bytes, llave)
    datos_guardar = base64.b64encode(nonce + tag + pdf_cifrado).decode("utf-8")

    doc = Documento(
        id_estudiante=nuevo_estudiante.id,
        nombre_archivo=documento.filename,
        datos=datos_guardar
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    return RedirectResponse(url="/jefe/dashboard", status_code=303)

@ruta.post("/generar-clave")
def generar_clave(usuario=Depends(obtener_usuario_actual)):
    print(f"Rol de usuario: {usuario.rol}")
    if usuario.rol != "jefe":
        raise HTTPException(403, "Solo el jefe puede generar claves")
    
    if not usuario.clave_publica:
        raise HTTPException(400, "No hay clave pública registrada para el jefe")

    clave = generar_clave_chacha()
    clave_cifrada = cifrar_clave(clave, usuario.clave_publica)
    print(f"Clave generada: {base64.b64encode(clave).decode('utf-8')}")
    print(f"Clave cifrada: {base64.b64encode(clave_cifrada).decode('utf-8')}")
    clave_cifrada_b64 = base64.b64encode(clave_cifrada).decode()
    print(f"Clave cifrada (base64): {clave_cifrada_b64}")

    buffer = io.BytesIO()
    buffer.write(clave_cifrada_b64.encode())
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=clave_chacha.txt"}
    )

@ruta.post("/enviar-clave/{staff_matricula}")
async def enviar_clave(
    staff_matricula: str,
    clave_simetrica_cifrada: UploadFile = File(...), 
    llave_privada: UploadFile = File(...),         
    db: Session = Depends(obtener_bd),
    usuario=Depends(obtener_usuario_actual)
):
    if usuario.rol != "jefe":
        raise HTTPException(403, "Solo el jefe puede enviar la clave chacha")
    
    clave_simetrica_cifrada_bytes = await clave_simetrica_cifrada.read()
    clave_simetrica_cifrada_bytes = base64.b64decode(clave_simetrica_cifrada_bytes)
    llave_privada_pem = (await llave_privada.read()).decode()

    try:
        clave_simetrica = descifrar_clave(clave_simetrica_cifrada_bytes, llave_privada_pem)
        print(f"Clave secreta: {base64.b64encode(clave_simetrica).decode('utf-8')}")

    except Exception:
        raise HTTPException(400, "Clave privada incorrecta o clave simétrica no válida")

    staff = db.query(Usuario).filter_by(matricula=staff_matricula, rol="staff").first()
    if not staff or not staff.clave_publica:
        raise HTTPException(404, "Staff no encontrado o sin clave pública")

    clave_para_staff = cifrar_clave(clave_simetrica, staff.clave_publica)

    clave_b64 = base64.b64encode(clave_para_staff).decode("utf-8")
    archivo_txt = io.BytesIO(clave_b64.encode("utf-8"))
    nombre_archivo = f"clave_chacha20poly1305_staff_{staff_matricula}.txt"

    enviar_correo(
        destinatario=staff.correo,
        asunto="Clave de cifrado ChaCha20Poly1305",
        cuerpo="[UniTrack] Adjunto encontrarás la clave cifrada para el cifrado de los expedientes.",
        adjunto=archivo_txt.read(),
        nombre_adjunto=nombre_archivo
    )

    return {"mensaje": "Clave enviada correctamente"}

@ruta.post("/dashboard/editarCalificaciones", response_class=HTMLResponse)
async def editar_calificaciones(
    matricula_estudiante: str = Form(...),
    ingenieria_de_software: str = Form(...),
    compiladores: str = Form(...),
    criptografia: str = Form(...),
    sistemas_en_chip: str = Form(...),
    sistemas_distribuidos: str = Form(...),
    llave_privada: UploadFile = File(...),
    db: Session = Depends(obtener_bd),
    usuario_actual: Usuario = Depends(obtener_usuario_actual)
):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo la administración puede editar calificaciones")
    
    # Convertimos el archivo de llave privada en texto
    llave_privada_texto = (await llave_privada.read()).decode()

    # Crear el diccionario con las calificaciones
    calificaciones = {
        "Ingeniería de Software": ingenieria_de_software,
        "Compiladores": compiladores,
        "Criptografía": criptografia,
        "Sistemas en Chip": sistemas_en_chip,
        "Sistemas Distribuidos": sistemas_distribuidos
    }

    # Llamamos a la función para actualizar las calificaciones
    actualizar_calificaciones(db, matricula_estudiante, calificaciones, usuario_actual.matricula, llave_privada_texto)

    return RedirectResponse(url="/jefe/dashboard", status_code=303)

@ruta.post("/dashboard/descargarDocumento/{id_doc}")
async def descargar_documento(
    id_doc: int,
    llave_simetrica: UploadFile = File(...),
    db: Session = Depends(obtener_bd),
    usuario_actual: Usuario = Depends(obtener_usuario_actual)
):
    documentos = db.query(Documento).all()
    print(">>> Documentos existentes en la base de datos:")
    for d in documentos:
        print(f"ID: {d.id}, nombre: {d.nombre_archivo}, estudiante: {d.id_estudiante}")
    
    doc = db.query(Documento).filter_by(id=id_doc).first()
    if not doc:
        raise HTTPException(404, "Documento no encontrado")    
    datos = base64.b64decode(doc.datos)
    nonce = datos[:12]
    tag = datos[12:28]
    ciphertext = datos[28:]
    llave_bytes = await llave_simetrica.read()
    try:
        llave = base64.b64decode(llave_bytes)
    except Exception:
        llave = llave_bytes
    pdf = descifrar_chacha20_poly1305(nonce, ciphertext, tag, llave)
    print("→ Datos descifrados:", pdf[:10])

    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={doc.nombre_archivo}"})

