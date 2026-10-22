# LINK X Sistemas — Control de asistencia (frontend + backend)

Proyecto completo para desplegar desde GitHub. Incluye interfaz web, API en Python/FastAPI, autenticación con tokens, contraseñas con hash, base de datos y reportes CSV.

## Funciones
- Login por correo y contraseña.
- Roles `admin` y `employee` verificados en el servidor.
- Administrador crea usuarios, activa/desactiva cuentas y consulta la asistencia de hoy.
- Entrada y salida (sin acciones de comida); el servidor impide entradas/salidas duplicadas en el mismo día.
- Colaboradores consultan sus propios movimientos; no pueden consultar los de otros.
- Reporte CSV protegido para administradores.
- Base de datos PostgreSQL en despliegue de Render; SQLite para pruebas locales.
- La página y la API se sirven desde el mismo servicio, por lo que no necesita CORS externo.

## Publicar en GitHub y Render
**GitHub guarda el código, pero no ejecuta el backend.** Render ejecutará Python y PostgreSQL.

1. Descarga el ZIP y descomprímelo.
2. Crea un repositorio nuevo en GitHub y sube el contenido de la carpeta `linkx_asistencia_backend` (el `render.yaml` debe quedar en la raíz del repositorio).
3. En Render, selecciona **New → Blueprint**, conecta GitHub y elige ese repositorio.
4. Render leerá `render.yaml` y propondrá un servicio web y una base PostgreSQL. Confirma la creación.
5. Cuando Render pida `ADMIN_PASSWORD`, establece una contraseña fuerte de al menos 10 caracteres. No la guardes en el repositorio ni la compartas.
6. Espera a que termine el despliegue y abre la URL HTTPS del servicio. Esa URL es la aplicación y también la base de la API.
7. Entra con el correo configurado por `ADMIN_EMAIL` (por defecto `admin@linkx.local`) y la contraseña que definiste en Render.
8. Desde **Usuarios**, crea las cuentas reales del equipo y entrega a cada persona su correo y contraseña temporal por un canal seguro.

Si ya existe una base de datos con usuarios, el sembrado inicial solo crea el administrador si ese correo todavía no existe. Cambiar la variable `ADMIN_PASSWORD` después no cambia la contraseña de una cuenta que ya fue creada; inicia sesión y utiliza el endpoint de cambio de contraseña o actualízala mediante un procedimiento administrativo seguro.

## Pruebas locales (Python 3.11+)
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
```
Crea un archivo `.env` copiando `.env.example`, configura `ADMIN_PASSWORD` y carga las variables de entorno en tu terminal (o usa una herramienta local para cargar `.env`). Después ejecuta:
```bash
uvicorn app.main:app --reload
```
Abre `http://127.0.0.1:8000`. Documentación interactiva de la API: `http://127.0.0.1:8000/docs`.

## Variables de entorno
- `DATABASE_URL`: cadena de conexión; Render la configura desde la base de datos del Blueprint.
- `JWT_SECRET`: secreto largo y aleatorio para firmar sesiones. Render lo genera automáticamente.
- `ADMIN_EMAIL`, `ADMIN_NAME`, `ADMIN_PASSWORD`: administrador inicial. `ADMIN_PASSWORD` debe configurarse manualmente en Render.
- `APP_TIMEZONE`: zona horaria de registros; predeterminado `America/Mexico_City`.
- `ACCESS_TOKEN_MINUTES`: duración del token, por defecto 480 minutos.
- `CORS_ORIGINS`: orígenes permitidos si en el futuro separas el frontend; en el despliegue integrado no se necesita acceso externo.

## Rutas API principales
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/change-password` (JSON: `current_password`, `new_password`)
- `GET /api/users` y `POST /api/users` (administrador)
- `PATCH /api/users/{id}/active` (administrador)
- `POST /api/attendance/entrada`
- `POST /api/attendance/salida`
- `GET /api/attendance/mine`
- `GET /api/attendance` (administrador; filtros `start`, `end`, `user_id`)
- `GET /api/attendance/today-summary` (administrador)
- `GET /api/reports/attendance.csv` (administrador)
- `GET /api/health`

## Notas de seguridad
- No hay contraseñas predeterminadas conocidas; el administrador inicial solo se crea cuando `ADMIN_PASSWORD` está definida.
- No subas `.env`, contraseñas, tokens ni credenciales a GitHub.
- Las contraseñas se almacenan como hashes Argon2; los roles y permisos se verifican en la API, no solo en la interfaz.
- HTTPS es necesario para proteger credenciales durante el envío; usa la URL HTTPS de Render.
- El sistema registra fecha y hora según `APP_TIMEZONE`, pero no sustituye una política institucional de asistencia ni un sistema oficial de Walmart. LINK X es una propuesta independiente.
- Para instalaciones de producción, define una política de respaldo/retención de PostgreSQL y revisa las reglas internas de privacidad y tratamiento de datos del personal.
