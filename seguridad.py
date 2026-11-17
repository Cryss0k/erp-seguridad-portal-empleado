"""
Utilidades de protección de datos sensibles - Portal del Empleado.

- Cifrado en reposo (Fernet: AES-128-CBC + HMAC-SHA256) con llave en variable de entorno.
- Índice ciego del RUT (HMAC-SHA256) para buscar sin guardar el RUT en claro.
- Enmascaramiento de datos para vistas generales.
- Validaciones de formato en servidor.
"""
import base64
import hashlib
import hmac
import os
import re
from datetime import datetime
from functools import lru_cache

from cryptography.fernet import Fernet

RUT_REGEX = re.compile(r"^\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]$")
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TELEFONO_REGEX = re.compile(r"^\+?\d{8,15}$")


def exigir_variable(nombre: str) -> str:
    valor = os.environ.get(nombre)
    if not valor:
        raise RuntimeError(f"Falta la variable de entorno {nombre} (ver .env.example)")
    return valor


@lru_cache(maxsize=1)
def _llave() -> bytes:
    return exigir_variable("DATA_ENCRYPTION_KEY").encode()


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    return Fernet(_llave())


def cifrar(texto: str) -> str:
    return _fernet().encrypt(texto.encode("utf-8")).decode("ascii")


def descifrar(token: str) -> str:
    return _fernet().decrypt(token.encode("ascii")).decode("utf-8")


def indice_rut(rut_normalizado: str) -> str:
    """Huella HMAC del RUT: permite buscar al empleado sin almacenar el RUT en claro."""
    clave = base64.urlsafe_b64decode(_llave())
    return hmac.new(clave, b"rut-idx:" + rut_normalizado.encode("utf-8"), hashlib.sha256).hexdigest()


# ------------------------------------------------------------ validaciones
def rut_valido(rut: str) -> bool:
    """Formato chileno y dígito verificador (módulo 11)."""
    if not rut or len(rut) > 12 or not RUT_REGEX.match(rut):
        return False
    cuerpo, dv = rut.replace(".", "").upper().split("-")
    suma, mult = 0, 2
    for digito in reversed(cuerpo):
        suma += int(digito) * mult
        mult = 2 if mult == 7 else mult + 1
    resto = 11 - (suma % 11)
    esperado = "0" if resto == 11 else "K" if resto == 10 else str(resto)
    return dv == esperado


def normalizar_rut(rut: str) -> str:
    cuerpo, dv = rut.replace(".", "").upper().split("-")
    return f"{int(cuerpo):,}".replace(",", ".") + "-" + dv


def email_valido(email: str) -> bool:
    return bool(email) and len(email) <= 120 and bool(EMAIL_REGEX.match(email))


def telefono_valido(telefono: str) -> bool:
    return bool(TELEFONO_REGEX.match(telefono or ""))


def fecha_valida(valor: str):
    try:
        return datetime.strptime(valor, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


# ------------------------------------------------------------ enmascaramiento
def enmascarar_rut(rut: str) -> str:
    """12.345.678-5 -> 12.***.***-5"""
    cuerpo, dv = rut.split("-")
    return f"{cuerpo[:2]}.***.***-{dv}"


def enmascarar_email(email: str) -> str:
    """juan.perez@dominio.cl -> j***@dominio.cl"""
    usuario, dominio = email.split("@", 1)
    return f"{usuario[:1]}***@{dominio}"


def enmascarar_telefono(telefono: str) -> str:
    """+56912345678 -> +56*****5678"""
    if len(telefono) <= 7:
        return "*" * len(telefono)
    return telefono[:3] + "*" * (len(telefono) - 7) + telefono[-4:]


def enmascarar_monto(monto: str) -> str:
    """$1.250.000 -> $*.***.***"""
    return re.sub(r"\d", "*", monto)
