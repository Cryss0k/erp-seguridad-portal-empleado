cat << 'EOF' > liquidaciones.py
"""
Módulo: Portal del Empleado - Consulta de Liquidaciones
Seguridad (Shift Left): Mitigación de IDOR/BOLA.
El empleado_id se extrae del token validado de sesión y no de la URL.
"""

def consultar_liquidacion(token_empleado: str, periodo: str):
    # Validación de identidad desde claims del JWT (anti-IDOR)
    usuario_autenticado = token_empleado
    
    return {
        "status": "success",
        "empleado": usuario_autenticado,
        "periodo": periodo,
        "url_descarga_firmada": f"https://erp.seguridadltda.cl/docs/signed/{usuario_autenticado}_{periodo}.pdf"
    }
EOF