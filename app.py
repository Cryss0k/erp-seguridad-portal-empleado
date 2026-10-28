"""
ERP Seguridad LTDA - Portal del Empleado
Prototipo funcional - Evaluación Sumativa 2 (EVS2) - Desarrollo Seguro

Historias implementadas:
  EMP-9: Arquitectura base, BD y autenticación
  EMP-3: Consulta y descarga de liquidaciones de sueldo
  EMP-4: Solicitud y control de vacaciones
  EMP-1: Actualización de datos personales

NOTA: Este código corresponde a la Etapa 1 de la EVS2. A propósito NO incluye
aún mecanismos de blindaje de seguridad (eso se analiza con SonarQube en la
Etapa 2 y se corrige/gestiona recién en el Sprint 2). No usar en producción.
"""
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = "clave_secreta_portal_empleado_2026"  # TODO: mover a variable de entorno


def get_db():
    conn = sqlite3.connect("portal_empleado.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def home():
    if "empleado_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        rut = request.form["rut"]
        password = request.form["password"]

        conn = get_db()
        # Consulta construida con los datos del usuario
        query = "SELECT * FROM empleados WHERE rut = '" + rut + "' AND password = '" + password + "'"
        cur = conn.execute(query)
        empleado = cur.fetchone()
        conn.close()

        if empleado:
            session["empleado_id"] = empleado["id"]
            session["nombre"] = empleado["nombre"]
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="RUT o contraseña incorrectos")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "empleado_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", nombre=session.get("nombre"))


@app.route("/liquidaciones")
def liquidaciones():
    """EMP-3: Consulta de liquidaciones de sueldo."""
    if "empleado_id" not in session:
        return redirect(url_for("login"))

    # El id de empleado a consultar se toma de un parámetro de la URL
    empleado_id = request.args.get("empleado_id", session["empleado_id"])

    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM liquidaciones WHERE empleado_id = " + str(empleado_id) + " ORDER BY periodo DESC"
    )
    filas = cur.fetchall()
    conn.close()
    return render_template("liquidaciones.html", liquidaciones=filas)


@app.route("/vacaciones", methods=["GET", "POST"])
def vacaciones():
    """EMP-4: Solicitud y control de vacaciones."""
    if "empleado_id" not in session:
        return redirect(url_for("login"))

    empleado_id = session["empleado_id"]
    conn = get_db()

    if request.method == "POST":
        fecha_inicio = request.form["fecha_inicio"]
        fecha_fin = request.form["fecha_fin"]
        motivo = request.form["motivo"]

        conn.execute(
            "INSERT INTO vacaciones (empleado_id, fecha_inicio, fecha_fin, motivo) VALUES (?, ?, ?, ?)",
            (empleado_id, fecha_inicio, fecha_fin, motivo),
        )
        conn.commit()

    cur = conn.execute("SELECT * FROM vacaciones WHERE empleado_id = ?", (empleado_id,))
    solicitudes = cur.fetchall()
    conn.close()
    return render_template("vacaciones.html", solicitudes=solicitudes)


@app.route("/datos-personales", methods=["GET", "POST"])
def datos_personales():
    """EMP-1: Actualización de datos personales."""
    if "empleado_id" not in session:
        return redirect(url_for("login"))

    empleado_id = session["empleado_id"]
    conn = get_db()

    if request.method == "POST":
        email = request.form["email"]
        telefono = request.form["telefono"]

        conn.execute(
            "UPDATE empleados SET email = '" + email + "', telefono = '" + telefono + "' WHERE id = " + str(empleado_id)
        )
        conn.commit()

    cur = conn.execute("SELECT * FROM empleados WHERE id = ?", (empleado_id,))
    empleado = cur.fetchone()
    conn.close()
    return render_template("datos_personales.html", empleado=empleado)


if __name__ == "__main__":
    app.run(debug=True)
