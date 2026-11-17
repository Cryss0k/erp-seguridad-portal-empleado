"""
Crea la base de datos SQLite y la puebla con datos de prueba.
Los datos sensibles se guardan cifrados y las contraseñas con hash y sal.
Las contraseñas de prueba NO están en el código: se generan al azar y se
muestran una sola vez en la consola (o se toman de SEED_PASSWORD_1 / _2).

Ejecutar: python init_db.py
"""
import os
import secrets
import sqlite3

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

import seguridad  # noqa: E402  (requiere las variables de entorno cargadas)

ESQUEMA = """
DROP TABLE IF EXISTS vacaciones;
DROP TABLE IF EXISTS liquidaciones;
DROP TABLE IF EXISTS empleados;

CREATE TABLE empleados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rut_idx TEXT NOT NULL UNIQUE,
    rut_enc TEXT NOT NULL,
    nombre TEXT NOT NULL,
    email_enc TEXT NOT NULL,
    telefono_enc TEXT NOT NULL,
    cargo TEXT,
    password_hash TEXT NOT NULL
);

CREATE TABLE liquidaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empleado_id INTEGER NOT NULL,
    periodo TEXT NOT NULL,
    monto_enc TEXT NOT NULL,
    FOREIGN KEY (empleado_id) REFERENCES empleados(id)
);

CREATE TABLE vacaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empleado_id INTEGER NOT NULL,
    fecha_inicio TEXT NOT NULL,
    fecha_fin TEXT NOT NULL,
    motivo TEXT,
    estado TEXT DEFAULT 'Pendiente',
    FOREIGN KEY (empleado_id) REFERENCES empleados(id)
);
"""

# RUT ficticios con dígito verificador válido
EMPLEADOS = [
    ("12.345.678-5", "Juan Pérez", "juan.perez@seguridadltda.cl", "+56912345678", "Analista",
     [("2026-08", "$1.250.000"), ("2026-09", "$1.250.000")]),
    ("9.876.543-3", "María Soto", "maria.soto@seguridadltda.cl", "+56987654321", "Supervisora",
     [("2026-08", "$1.800.000"), ("2026-09", "$1.800.000")]),
]


def crear_bd(ruta="portal_empleado.db", claves=None):
    """Crea la BD. Devuelve {rut: contraseña_de_prueba} (solo para mostrarla una vez)."""
    entregadas = {}
    conn = sqlite3.connect(ruta)
    conn.executescript(ESQUEMA)
    for i, (rut, nombre, email, telefono, cargo, liquidaciones) in enumerate(EMPLEADOS, start=1):
        clave = (claves or {}).get(rut) or os.environ.get(f"SEED_PASSWORD_{i}") or secrets.token_urlsafe(9)
        entregadas[rut] = clave
        conn.execute(
            "INSERT INTO empleados (id, rut_idx, rut_enc, nombre, email_enc, telefono_enc, cargo, password_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (i, seguridad.indice_rut(rut), seguridad.cifrar(rut), nombre,
             seguridad.cifrar(email), seguridad.cifrar(telefono), cargo,
             generate_password_hash(clave)),
        )
        for periodo, monto in liquidaciones:
            conn.execute(
                "INSERT INTO liquidaciones (empleado_id, periodo, monto_enc) VALUES (?, ?, ?)",
                (i, periodo, seguridad.cifrar(monto)),
            )
    conn.commit()
    conn.close()
    return entregadas


if __name__ == "__main__":
    ruta = os.environ.get("PORTAL_DB_PATH", "portal_empleado.db")
    claves = crear_bd(ruta)
    print(f"Base de datos inicializada: {ruta}")
    print("Credenciales de prueba (se muestran solo ahora; no las guardes en el repositorio):")
    for rut, clave in claves.items():
        print(f"  RUT {rut}  contraseña: {clave}")
