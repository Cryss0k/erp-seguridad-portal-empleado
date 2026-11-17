"""
ERP Seguridad LTDA - Portal del Empleado
Evaluación Sumativa 3 - Protección de datos sensibles, sesiones y remediación (Sprint 2)

Medidas aplicadas (ver tickets de Jira):
  - Consultas parametrizadas y validación de entradas en servidor
  - Identidad resuelta solo desde la sesión (anti-IDOR)
  - Contraseñas con hash y sal (scrypt); secretos y llaves por variables de entorno
  - Datos sensibles cifrados en reposo y enmascarados en las vistas
  - Cookie de sesión HttpOnly + SameSite + expiración; protección CSRF
  - Cabeceras HTTP de seguridad; errores genéricos sin información interna
"""
import os
import secrets
import sqlite3
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

import seguridad as seg  # noqa: E402

app = Flask(__name__)
app.config.update(
    SECRET_KEY=seg.exigir_variable("FLASK_SECRET_KEY"),
    SESSION_COOKIE_NAME="portal_sesion",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=16 * 1024,
)
csrf = CSRFProtect(app)

DB_PATH = os.environ.get("PORTAL_DB_PATH", "portal_empleado.db")

# Hash de relleno: se verifica cuando el RUT no existe, para no revelar si la cuenta existe por tiempo de respuesta
HASH_RELLENO = generate_password_hash(secrets.token_urlsafe(16))

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def requiere_sesion():
    return "empleado_id" not in session


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if not request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def pagina_error(codigo, mensaje):
    return render_template("error.html", codigo=codigo, mensaje=mensaje), codigo


@app.errorhandler(400)
def error_400(_e):
    return pagina_error(400, "Solicitud inválida.")


@app.errorhandler(404)
def error_404(_e):
    return pagina_error(404, "Recurso no encontrado.")


@app.errorhandler(405)
def error_405(_e):
    return pagina_error(405, "Método no permitido.")


@app.errorhandler(413)
def error_413(_e):
    return pagina_error(413, "La solicitud es demasiado grande.")


@app.errorhandler(500)
def error_500(_e):
    return pagina_error(500, "Ocurrió un error interno. Intenta nuevamente más tarde.")


@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("dashboard" if "empleado_id" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        rut = request.form.get("rut", "").strip()
        password = request.form.get("password", "")

        if not seg.rut_valido(rut) or not password or len(password) > 128:
            return render_template("login.html", error="Formato de RUT o contraseña inválido"), 400

        conn = get_db()
        fila = conn.execute(
            "SELECT id, nombre, password_hash FROM empleados WHERE rut_idx = ?",
            (seg.indice_rut(seg.normalizar_rut(rut)),),
        ).fetchone()
        conn.close()

        hash_guardado = fila["password_hash"] if fila else HASH_RELLENO
        if check_password_hash(hash_guardado, password) and fila:
            session.clear()
            session.permanent = True
            session["empleado_id"] = fila["id"]
            session["nombre"] = fila["nombre"]
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="RUT o contraseña incorrectos"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if requiere_sesion():
        return redirect(url_for("login"))
    conn = get_db()
    fila = conn.execute(
        "SELECT nombre, rut_enc, email_enc, telefono_enc FROM empleados WHERE id = ?",
        (session["empleado_id"],),
    ).fetchone()
    conn.close()
    if not fila:
        session.clear()
        return redirect(url_for("login"))
    resumen = {
        "nombre": fila["nombre"],
        "rut": seg.enmascarar_rut(seg.descifrar(fila["rut_enc"])),
        "email": seg.enmascarar_email(seg.descifrar(fila["email_enc"])),
        "telefono": seg.enmascarar_telefono(seg.descifrar(fila["telefono_enc"])),
    }
    return render_template("dashboard.html", resumen=resumen)


@app.route("/liquidaciones", methods=["GET"])
def liquidaciones():
    """Lista de liquidaciones del empleado en sesión, con el monto enmascarado."""
    if requiere_sesion():
        return redirect(url_for("login"))
    conn = get_db()
    filas = conn.execute(
        "SELECT id, periodo, monto_enc FROM liquidaciones WHERE empleado_id = ? ORDER BY periodo DESC",
        (session["empleado_id"],),
    ).fetchall()
    conn.close()
    lista = [
        {"id": f["id"], "periodo": f["periodo"], "monto": seg.enmascarar_monto(seg.descifrar(f["monto_enc"]))}
        for f in filas
    ]
    return render_template("liquidaciones.html", liquidaciones=lista)


@app.route("/liquidaciones/<int:liq_id>", methods=["GET"])
def liquidacion_detalle(liq_id):
    """Detalle con el monto completo: solo si la liquidación pertenece al empleado en sesión."""
    if requiere_sesion():
        return redirect(url_for("login"))
    conn = get_db()
    fila = conn.execute(
        "SELECT id, periodo, monto_enc FROM liquidaciones WHERE id = ? AND empleado_id = ?",
        (liq_id, session["empleado_id"]),
    ).fetchone()
    conn.close()
    if not fila:
        abort(404)
    return render_template(
        "liquidacion_detalle.html", periodo=fila["periodo"], monto=seg.descifrar(fila["monto_enc"])
    )


@app.route("/vacaciones", methods=["GET", "POST"])
def vacaciones():
    if requiere_sesion():
        return redirect(url_for("login"))

    empleado_id = session["empleado_id"]
    error, status = None, 200

    if request.method == "POST":
        inicio = seg.fecha_valida(request.form.get("fecha_inicio", ""))
        fin = seg.fecha_valida(request.form.get("fecha_fin", ""))
        motivo = request.form.get("motivo", "").strip()

        if not inicio or not fin:
            error, status = "Las fechas deben tener formato AAAA-MM-DD y ser válidas", 400
        elif fin < inicio:
            error, status = "La fecha de fin no puede ser anterior a la de inicio", 400
        elif len(motivo) > 200:
            error, status = "El motivo no puede superar los 200 caracteres", 400
        else:
            conn = get_db()
            conn.execute(
                "INSERT INTO vacaciones (empleado_id, fecha_inicio, fecha_fin, motivo) VALUES (?, ?, ?, ?)",
                (empleado_id, inicio.isoformat(), fin.isoformat(), motivo),
            )
            conn.commit()
            conn.close()

    conn = get_db()
    solicitudes = conn.execute(
        "SELECT fecha_inicio, fecha_fin, motivo, estado FROM vacaciones WHERE empleado_id = ?",
        (empleado_id,),
    ).fetchall()
    conn.close()
    return render_template("vacaciones.html", solicitudes=solicitudes, error=error), status


@app.route("/datos-personales", methods=["GET", "POST"])
def datos_personales():
    """Los datos se muestran enmascarados; solo se cambian los campos que se completen."""
    if requiere_sesion():
        return redirect(url_for("login"))

    empleado_id = session["empleado_id"]
    error, mensaje, status = None, None, 200

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        telefono = request.form.get("telefono", "").strip()

        if not email and not telefono:
            error, status = "Completa al menos un campo para actualizar", 400
        elif email and not seg.email_valido(email):
            error, status = "Correo electrónico inválido", 400
        elif telefono and not seg.telefono_valido(telefono):
            error, status = "Teléfono inválido (solo dígitos, 8 a 15, con + opcional)", 400
        else:
            conn = get_db()
            if email:
                conn.execute("UPDATE empleados SET email_enc = ? WHERE id = ?", (seg.cifrar(email), empleado_id))
            if telefono:
                conn.execute("UPDATE empleados SET telefono_enc = ? WHERE id = ?", (seg.cifrar(telefono), empleado_id))
            conn.commit()
            conn.close()
            mensaje = "Datos actualizados"

    conn = get_db()
    fila = conn.execute(
        "SELECT rut_enc, email_enc, telefono_enc FROM empleados WHERE id = ?", (empleado_id,)
    ).fetchone()
    conn.close()
    datos = {
        "rut": seg.enmascarar_rut(seg.descifrar(fila["rut_enc"])),
        "email": seg.enmascarar_email(seg.descifrar(fila["email_enc"])),
        "telefono": seg.enmascarar_telefono(seg.descifrar(fila["telefono_enc"])),
    }
    return render_template("datos_personales.html", datos=datos, error=error, mensaje=mensaje), status


if __name__ == "__main__":
    # No revelar versiones de Werkzeug/Python en la cabecera Server
    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.server_version = "Portal-Empleado"
    WSGIRequestHandler.sys_version = ""
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
