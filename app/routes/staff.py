import base64
from fastapi import APIRouter, Depends, File, HTTPException, Request, Form, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import string, random
from app.cifrado import cifrar_chacha20_poly1305, descifrar_clave
from app.crud import crear_usuario, eliminar_usuario, crear_estudiante, actualizar_calificaciones
from app.auth import obtener_usuario_actual, enviar_correo, ph
from app.basedatos import SesionLocal
from app.modelos import Documento, Usuario, Historial_Academico

router = APIRouter()
templates = Jinja2Templates(directory="templates")

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/dashboard", response_class=HTMLResponse)
def staff_dashboard(request: Request, db: Session = Depends(obtener_bd), usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "staff":
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    estudiantes = db.query(Usuario).filter(Usuario.rol == "estudiante").all()
    historiales = {}
    for estudiante in estudiantes:
        historial = db.query(Historial_Academico).filter_by(id_estudiante=estudiante.id).all()
        historiales[estudiante.matricula] = historial
    return templates.TemplateResponse("staff_dashboard.html", {"request": request, "usuario": usuario_actual, "estudiantes": estudiantes, "historiales":historiales})

@router.post("/dashboard/registrarEstudiante", response_class=HTMLResponse)
async def registrar_estudiante(nombre: str = Form(...),
                         correo: str = Form(...),
                         matricula: str = Form(...),
                         telefono: str = Form(...),
                         documento: UploadFile = File(...),
                         llave_simetrica: UploadFile = File(...),
                         db: Session = Depends(obtener_bd),
                         usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    
    if usuario_actual.rol != "staff":
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
    
    return RedirectResponse(url="/staff/dashboard", status_code=303)

@router.post("/dashboard/eliminarEstudiante", response_class=HTMLResponse)
def eliminar_estudiante(matricula: str = Form(...), db: Session = Depends(obtener_bd),
                        usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "staff" and usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo la administración puede eliminar estudiantes")
    eliminado = eliminar_usuario(db, matricula)
    if not eliminado:
        raise HTTPException(status_code=404, detail="Estudiante no encontrado")
    
    if usuario_actual.rol == "jefe":
        return RedirectResponse(url="/jefe/dashboard", status_code=303)
    return RedirectResponse(url="/staff/dashboard", status_code=303)

@router.post("/descifrar-clave")
async def descifrar_clave_staff(
    clave_cifrada: UploadFile = File(...),
    llave_privada: UploadFile = File(...),
    usuario=Depends(obtener_usuario_actual)
):
    if usuario.rol != "staff":
        raise HTTPException(403, "Solo el staff puede descifrar su clave")

    try:
        # Leer archivos
        clave_cifrada_bytes = await clave_cifrada.read()
        clave_cifrada_bytes = base64.b64decode(clave_cifrada_bytes)
        llave_privada_pem = (await llave_privada.read()).decode()

        # Intentar descifrado
        clave_simetrica = descifrar_clave(clave_cifrada_bytes, llave_privada_pem)

    except Exception as e:
        raise HTTPException(400, detail="No se pudo descifrar la clave: clave privada incorrecta o archivo dañado")

    # Convertir la clave a texto (codificada en base64)
    clave_simetrica_b64 = base64.b64encode(clave_simetrica).decode("utf-8")

    # Crear un archivo en memoria con el contenido de la clave
    from io import BytesIO
    file_content = BytesIO(clave_simetrica_b64.encode("utf-8"))
    
    headers = {"Content-Disposition": "attachment; filename=clave_simetrica.txt"}
    return StreamingResponse(file_content, media_type="text/plain", headers=headers)

@router.post("/dashboard/editarCalificaciones", response_class=HTMLResponse)
async def editar_calificaciones_staff(
    matricula_estudiante: str = Form(...),
    ingenieria_de_software: str = Form(...),
    compiladores: str = Form(...),
    criptografia: str = Form(...),
    sistemas_en_chip: str = Form(...),
    sistemas_distribuidos: str = Form(...),
    llave_privada: UploadFile = File(...),
    db: Session = Depends(obtener_bd),
    usuario_actual = Depends(obtener_usuario_actual)
):
    # Permitir tanto staff como jefe
    if usuario_actual.rol not in ["staff", "jefe"]:
        return HTMLResponse("No autorizado", status_code=403)
    llave_privada_texto = (await llave_privada.read()).decode()
    calificaciones = {
        "Ingeniería de Software": ingenieria_de_software,
        "Compiladores": compiladores,
        "Criptografía": criptografia,
        "Sistemas en Chip": sistemas_en_chip,
        "Sistemas Distribuidos": sistemas_distribuidos
    }
    actualizar_calificaciones(db, matricula_estudiante, calificaciones, usuario_actual.matricula, llave_privada_texto)
    return RedirectResponse(url="/staff/dashboard", status_code=303)
