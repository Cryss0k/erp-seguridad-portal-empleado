"""
EMP-9: Tarea Técnica - Arquitectura base, BD y autenticación
Crea la base de datos SQLite y la puebla con datos de prueba.
Ejecutar una sola vez: python init_db.py
"""
import sqlite3

conn = sqlite3.connect("portal_empleado.db")
cur = conn.cursor()

cur.executescript("""
DROP TABLE IF EXISTS empleados;
DROP TABLE IF EXISTS liquidaciones;
DROP TABLE IF EXISTS vacaciones;

CREATE TABLE empleados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rut TEXT NOT NULL,
    nombre TEXT NOT NULL,
    email TEXT NOT NULL,
    telefono TEXT,
    cargo TEXT,
    password TEXT NOT NULL
);

CREATE TABLE liquidaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empleado_id INTEGER NOT NULL,
    periodo TEXT NOT NULL,
    monto_liquido TEXT NOT NULL,
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
""")

# Datos de prueba (contraseñas en texto plano: hallazgo esperado para SonarQube)
empleados = [
    (1, "12.345.678-9", "Juan Pérez", "juan.perez@seguridadltda.cl", "+56912345678", "Analista", "clave123"),
    (2, "9.876.543-2", "María Soto", "maria.soto@seguridadltda.cl", "+56987654321", "Supervisora", "clave456"),
]
cur.executemany(
    "INSERT INTO empleados (id, rut, nombre, email, telefono, cargo, password) VALUES (?,?,?,?,?,?,?)",
    empleados,
)

liquidaciones = [
    (1, 1, "2026-08", "$1.250.000"),
    (2, 1, "2026-09", "$1.250.000"),
    (3, 2, "2026-08", "$1.800.000"),
    (4, 2, "2026-09", "$1.800.000"),
]
cur.executemany(
    "INSERT INTO liquidaciones (id, empleado_id, periodo, monto_liquido) VALUES (?,?,?,?)",
    liquidaciones,
)

conn.commit()
conn.close()
print("Base de datos inicializada: portal_empleado.db")
