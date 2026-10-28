# erp-seguridad-portal-empleado

Prototipo funcional del módulo **Portal del Empleado** — ERP "Seguridad LTDA".
Evaluación Sumativa 2 (EVS2) - Desarrollo Seguro (DevSecOps).

## Funcionalidades (Etapa 1)
- Login (EMP-9)
- Consulta de liquidaciones de sueldo (EMP-3)
- Solicitud de vacaciones (EMP-4)
- Actualización de datos personales (EMP-1)

## Cómo ejecutar
```bash
pip install -r requirements.txt
python init_db.py      # crea portal_empleado.db con datos de prueba
python app.py           # app disponible en http://127.0.0.1:5000
```

Usuario de prueba: RUT `12.345.678-9`, contraseña `clave123`.

## Estado de seguridad
Este código corresponde a la **línea base** de la Etapa 1: se desarrolló de forma
natural, sin mecanismos especiales de blindaje, para que el análisis estático
con SonarQube (Etapa 2) refleje hallazgos reales del equipo. Los hallazgos se
analizan y gestionan en las Etapas 3-5 (ciclo de vida ISO/IEC 27034, validación
de entradas y ética) y se corrigen recién en el Sprint 2 (ver backlog en Jira).

No usar este código en producción tal como está.