# erp-seguridad-portal-empleado

Prototipo del módulo **Portal del Empleado** — ERP "Seguridad LTDA" (Desarrollo Seguro / DevSecOps).

## Funcionalidades
Login, consulta de liquidaciones, solicitud de vacaciones y actualización de datos personales.

## Cómo ejecutar
```bash
pip install -r requirements.txt
python generar_env.py     # crea .env con llaves aleatorias (no se sube a GitHub)
python init_db.py         # crea la BD y muestra, una sola vez, las claves de prueba
python app.py             # http://127.0.0.1:5000
```
Las contraseñas de prueba **no están en el repositorio**: se generan al azar al ejecutar `init_db.py`.

## Medidas de seguridad (Sprint 2)
| Medida | Dónde |
|---|---|
| Contraseñas con hash y sal (scrypt) | `app.py`, `init_db.py` |
| Secretos y llaves en variables de entorno (`.env` ignorado por Git) | `seguridad.py`, `.env.example` |
| Cifrado en reposo (Fernet) de RUT, correo, teléfono y montos | `seguridad.py`, `init_db.py` |
| Enmascaramiento en vistas (RUT, correo, teléfono, montos) | `seguridad.py`, plantillas |
| Cookie de sesión `HttpOnly`, `SameSite=Lax`, expiración de 15 min | `app.py` |
| Cabeceras HTTP: CSP, X-Frame-Options, nosniff, Referrer-Policy, COOP/CORP | `app.py` |
| Consultas parametrizadas y validación de entradas en servidor | `app.py`, `seguridad.py` |
| Identidad solo desde la sesión (anti-IDOR) y protección CSRF | `app.py` |
| Errores genéricos y modo debug desactivado por defecto | `app.py` |

## Pruebas de seguridad
```bash
python -m unittest discover tests -v
```

## Notas para producción
Servir por HTTPS y definir `COOKIE_SECURE=1` (activa cookie `Secure` y HSTS). Guardar de forma segura
la llave `DATA_ENCRYPTION_KEY`: sin ella no se pueden leer los datos cifrados.
