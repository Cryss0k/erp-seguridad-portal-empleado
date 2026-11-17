"""
Pruebas de seguridad del Portal del Empleado (EVS3).
Verifican las medidas de protección de datos, sesión, cabeceras y validaciones.
Ejecutar: python -m unittest discover tests -v
No contienen contraseñas literales: se generan al azar para cada ejecución.
"""
import glob
import os
import re
import secrets
import sqlite3
import tempfile
import unittest

from cryptography.fernet import Fernet

os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(32)
os.environ["DATA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["PORTAL_DB_PATH"] = _tmp.name
os.environ["FLASK_DEBUG"] = "0"

import app as portal  # noqa: E402
import init_db  # noqa: E402

JUAN, MARIA = "12.345.678-5", "9.876.543-3"


def token(client, url="/login"):
    html = client.get(url).data.decode()
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


class PruebasSeguridad(unittest.TestCase):
    def setUp(self):
        self.claves = init_db.crear_bd(_tmp.name)
        self.c = portal.app.test_client()

    def login(self, client=None, rut=JUAN, password=None):
        client = client or self.c
        clave = password if password is not None else self.claves[rut]
        return client.post("/login", data={"rut": rut, "password": clave, "csrf_token": token(client)})

    def post(self, url, data):
        data = dict(data, csrf_token=token(self.c, url))
        return self.c.post(url, data=data)

    def volcado_bd(self):
        conn = sqlite3.connect(_tmp.name)
        texto = "\n".join(str(r) for t in ("empleados", "liquidaciones", "vacaciones")
                          for r in conn.execute(f"SELECT * FROM {t}"))
        conn.close()
        return texto

    # ---------------- contraseñas, cifrado y secretos
    def test_contrasenas_con_hash_y_sal(self):
        conn = sqlite3.connect(_tmp.name)
        hashes = [r[0] for r in conn.execute("SELECT password_hash FROM empleados")]
        conn.close()
        for h in hashes:
            self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))
        for clave in self.claves.values():
            self.assertNotIn(clave, self.volcado_bd())

    def test_misma_clave_genera_hashes_distintos(self):
        from werkzeug.security import generate_password_hash
        self.assertNotEqual(generate_password_hash("misma-clave"), generate_password_hash("misma-clave"))

    def test_datos_sensibles_cifrados_en_reposo(self):
        volcado = self.volcado_bd()
        for dato in (JUAN, "juan.perez@seguridadltda.cl", "+56912345678", "$1.250.000", "$1.800.000"):
            self.assertNotIn(dato, volcado)

    def test_sin_credenciales_en_el_codigo(self):
        raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        patron = re.compile(r"""(password|passwd|secret|token|key)\w*\s*=\s*["'][^"'\s]{6,}["']""", re.I)
        for ruta in glob.glob(os.path.join(raiz, "*.py")):
            with open(ruta, encoding="utf-8") as f:
                codigo = f.read()
            self.assertIsNone(patron.search(codigo), f"posible credencial en {os.path.basename(ruta)}")

    # ---------------- sesión y cookies
    def test_cookie_de_sesion_httponly_samesite_y_expiracion(self):
        r = self.login()
        self.assertEqual(r.status_code, 302)
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("portal_sesion=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertRegex(cookie, r"Expires=|Max-Age=")
        self.assertEqual(portal.app.config["PERMANENT_SESSION_LIFETIME"].total_seconds(), 900)

    def test_logout_solo_por_post_con_csrf(self):
        self.login()
        self.assertEqual(self.c.get("/logout").status_code, 405)
        r = self.post("/logout", {})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_csrf_sin_token_rechazado(self):
        r = self.c.post("/login", data={"rut": JUAN, "password": self.claves[JUAN]})
        self.assertEqual(r.status_code, 400)

    # ---------------- cabeceras y errores
    def test_cabeceras_http_de_seguridad(self):
        h = self.c.get("/login").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertIn("form-action 'self'", h["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertIn("Permissions-Policy", h)
        self.assertEqual(h["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(h["Cache-Control"], "no-store")

    def test_modo_debug_desactivado(self):
        self.assertFalse(portal.app.debug)

    def test_error_404_generico(self):
        r = self.c.get("/ruta-que-no-existe")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Traceback", r.data)

    def test_error_500_generico(self):
        original = portal.get_db
        portal.get_db = lambda: (_ for _ in ()).throw(sqlite3.OperationalError("tabla secreta"))
        try:
            r = self.c.post("/login", data={"rut": JUAN, "password": "x" * 8, "csrf_token": token(self.c)})
        finally:
            portal.get_db = original
        self.assertEqual(r.status_code, 500)
        self.assertNotIn(b"Traceback", r.data)
        self.assertNotIn(b"tabla secreta", r.data)

    # ---------------- inyección, validación y control de acceso
    def test_sqli_login_bloqueado(self):
        for payload in ("' OR '1'='1", "' OR '1'='1' --", "12.345.678-9'"):
            r = self.login(rut=payload, password="' OR '1'='1")
            self.assertEqual(r.status_code, 400)
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_login_con_dv_incorrecto_o_clave_erronea(self):
        self.assertEqual(self.login(rut="12.345.678-9", password="x" * 8).status_code, 400)
        self.assertEqual(self.login(password="clave-incorrecta").status_code, 401)

    def test_idor_solo_liquidaciones_propias(self):
        self.login()
        lista = self.c.get("/liquidaciones?empleado_id=2").data.decode()
        self.assertEqual(lista.count("Ver detalle"), 2)
        conn = sqlite3.connect(_tmp.name)
        ajena = conn.execute("SELECT id FROM liquidaciones WHERE empleado_id = 2").fetchone()[0]
        propia = conn.execute("SELECT id FROM liquidaciones WHERE empleado_id = 1").fetchone()[0]
        conn.close()
        self.assertEqual(self.c.get(f"/liquidaciones/{ajena}").status_code, 404)
        detalle = self.c.get(f"/liquidaciones/{propia}")
        self.assertEqual(detalle.status_code, 200)
        self.assertIn(b"$1.250.000", detalle.data)

    def test_vistas_requieren_sesion(self):
        for url in ("/dashboard", "/liquidaciones", "/vacaciones", "/datos-personales"):
            self.assertEqual(self.c.get(url).status_code, 302)

    def test_fechas_invalidas_rechazadas(self):
        self.login()
        r = self.post("/vacaciones", {"fecha_inicio": "no-es-una-fecha", "fecha_fin": "tampoco", "motivo": "x"})
        self.assertEqual(r.status_code, 400)
        r = self.post("/vacaciones", {"fecha_inicio": "2026-12-10", "fecha_fin": "2026-12-01", "motivo": "x"})
        self.assertEqual(r.status_code, 400)

    def test_xss_escapado(self):
        self.login()
        r = self.post("/vacaciones", {"fecha_inicio": "2026-12-01", "fecha_fin": "2026-12-10",
                                      "motivo": "<script>alert(1)</script>"})
        self.assertNotIn(b"<script>alert(1)</script>", r.data)
        self.assertIn(b"&lt;script&gt;", r.data)

    def test_sqli_datos_personales_bloqueado(self):
        self.login()
        r = self.post("/datos-personales", {"email": "x@x.cl', telefono_enc='HACKEADO' WHERE id=1 --", "telefono": ""})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("HACKEADO", self.volcado_bd())

    # ---------------- enmascaramiento
    def test_vistas_con_datos_enmascarados(self):
        self.login()
        dash = self.c.get("/dashboard").data.decode()
        self.assertIn("12.***.***-5", dash)
        self.assertIn("j***@seguridadltda.cl", dash)
        self.assertIn("+56*****5678", dash)
        for dato in (JUAN, "juan.perez@seguridadltda.cl", "+56912345678"):
            self.assertNotIn(dato, dash)
        liq = self.c.get("/liquidaciones").data.decode()
        self.assertIn("$*.***.***", liq)
        self.assertNotIn("1.250.000", liq)
        datos = self.c.get("/datos-personales").data.decode()
        for dato in (JUAN, "juan.perez@seguridadltda.cl", "+56912345678"):
            self.assertNotIn(dato, datos)

    def test_actualizar_datos_los_guarda_cifrados(self):
        self.login()
        r = self.post("/datos-personales", {"email": "nuevo.correo@empresa.cl", "telefono": "+56900001111"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("nuevo.correo@empresa.cl", self.volcado_bd())
        self.assertNotIn("+56900001111", self.volcado_bd())
        self.assertIn("n***@empresa.cl", self.c.get("/dashboard").data.decode())


if __name__ == "__main__":
    unittest.main()
