"""Crea el archivo .env local con llaves aleatorias (no se sube a GitHub)."""
import os
import secrets

from cryptography.fernet import Fernet

if os.path.exists(".env"):
    print(".env ya existe; no se modifica.")
else:
    with open(".env", "w", encoding="utf-8") as f:
        f.write(f"FLASK_SECRET_KEY={secrets.token_hex(32)}\n")
        f.write(f"DATA_ENCRYPTION_KEY={Fernet.generate_key().decode()}\n")
        f.write("FLASK_DEBUG=0\nCOOKIE_SECURE=0\n")
    print(".env creado. Guarda una copia segura de DATA_ENCRYPTION_KEY: sin ella no se pueden leer los datos cifrados.")
