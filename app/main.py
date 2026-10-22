import os
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, UniqueConstraint, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

APP_TIMEZONE = ZoneInfo("America/Mexico_City")
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
TOKEN_HOURS = int(os.getenv("TOKEN_HOURS", "8"))
ADMIN_NAME = os.getenv("ADMIN_NAME", "Administrador LINK X")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./attendance.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="employee", nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(APP_TIMEZONE), nullable=False)


class Attendance(Base):
    __tablename__ = "attendance"
    __table_args__ = (UniqueConstraint("user_id", "work_date", name="uq_attendance_user_date"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    work_date: Mapped[date] = mapped_column(Date, index=True, nullable=False)
    check_in: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    check_out: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginInput(BaseModel):
    email: str
    password: str


class EmployeeCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


def user_data(user: User) -> dict:
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "active": user.active}


def attendance_data(row: Attendance, user: User | None = None) -> dict:
    return {
        "id": row.id,
        "user_id": row.user_id,
        "employee_name": user.name if user else None,
        "employee_email": user.email if user else None,
        "work_date": row.work_date.isoformat(),
        "check_in": row.check_in.isoformat(),
        "check_out": row.check_out.isoformat() if row.check_out else None,
        "status": "completa" if row.check_out else "sin_salida",
    }


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Debes iniciar sesión.", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub", ""))
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Token inválido o vencido.")
    user = db.get(User, user_id)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="La cuenta no existe o está desactivada.")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Esta acción requiere permisos de administrador.")
    return user


def create_access_token(user: User) -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=503, detail="Configura JWT_SECRET en las variables de entorno.")
    now = datetime.now(APP_TIMEZONE)
    return jwt.encode(
        {"sub": str(user.id), "role": user.role, "iat": now, "exp": now + timedelta(hours=TOKEN_HOURS)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


app = FastAPI(
    title="LINK X - Sistema de Asistencias",
    description="API de registro de asistencia, consulta personal y administración de empleados.",
    version="1.0.0",
)

cors_raw = os.getenv("CORS_ORIGINS", "*")
origins = [item.strip() for item in cors_raw.split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    if not JWT_SECRET:
        print("ADVERTENCIA: configura JWT_SECRET en las variables de entorno.")
    if ADMIN_EMAIL and ADMIN_PASSWORD:
        with SessionLocal() as db:
            admin = db.scalar(select(User).where(User.email == ADMIN_EMAIL))
            if not admin:
                db.add(User(
                    name=ADMIN_NAME,
                    email=ADMIN_EMAIL,
                    password_hash=password_hash.hash(ADMIN_PASSWORD),
                    role="admin",
                    active=True,
                ))
                db.commit()
    else:
        print("ADVERTENCIA: configura ADMIN_EMAIL y ADMIN_PASSWORD para crear el administrador inicial.")


@app.get("/")
def root():
    return {"app": "LINK X - Sistema de Asistencias", "docs": "/docs", "health": "/api/health"}


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "linkx-asistencia"}


@app.post("/api/auth/login")
def login(payload: LoginInput, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if not user or not user.active or not password_hash.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos.")
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": user_data(user)}


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return user_data(user)


@app.post("/api/attendance/check-in")
def check_in(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    now = datetime.now(APP_TIMEZONE)
    work_date = now.date()
    existing = db.scalar(select(Attendance).where(Attendance.user_id == user.id, Attendance.work_date == work_date))
    if existing:
        raise HTTPException(status_code=409, detail="Ya registraste tu asistencia de hoy.")
    row = Attendance(user_id=user.id, work_date=work_date, check_in=now)
    db.add(row)
    try:
        db.commit()
        db.refresh(row)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail="No se pudo registrar; revisa si ya existe una asistencia de hoy.")
    return {"message": "Entrada registrada correctamente.", "attendance": attendance_data(row, user)}


@app.post("/api/attendance/check-out")
def check_out(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    now = datetime.now(APP_TIMEZONE)
    row = db.scalar(select(Attendance).where(Attendance.user_id == user.id, Attendance.work_date == now.date()))
    if not row:
        raise HTTPException(status_code=404, detail="Primero debes registrar tu entrada de hoy.")
    if row.check_out:
        raise HTTPException(status_code=409, detail="La salida de hoy ya fue registrada.")
    row.check_out = now
    db.commit()
    db.refresh(row)
    return {"message": "Salida registrada correctamente.", "attendance": attendance_data(row, user)}


@app.get("/api/attendance/mine")
def my_attendance(
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    stmt = select(Attendance).where(Attendance.user_id == user.id)
    if start_date:
        stmt = stmt.where(Attendance.work_date >= start_date)
    if end_date:
        stmt = stmt.where(Attendance.work_date <= end_date)
    rows = db.scalars(stmt.order_by(Attendance.work_date.desc())).all()
    return {"items": [attendance_data(row, user) for row in rows]}


@app.get("/api/admin/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.name.asc())).all()
    return {"items": [user_data(item) for item in users]}


@app.post("/api/admin/users", status_code=status.HTTP_201_CREATED)
def create_employee(payload: EmployeeCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Ingresa un correo válido.")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Ya existe una cuenta con ese correo.")
    employee = User(
        name=payload.name.strip(),
        email=email,
        password_hash=password_hash.hash(payload.password),
        role="employee",
        active=True,
    )
    db.add(employee)
    db.commit()
    db.refresh(employee)
    return {"message": "Empleado creado correctamente.", "user": user_data(employee)}


@app.patch("/api/admin/users/{user_id}/active")
def set_user_active(
    user_id: int,
    active: bool = Query(...),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Empleado no encontrado.")
    if target.id == admin.id and not active:
        raise HTTPException(status_code=400, detail="No puedes desactivar tu propia cuenta.")
    target.active = active
    db.commit()
    db.refresh(target)
    return {"message": "Estado actualizado.", "user": user_data(target)}


@app.get("/api/admin/attendance")
def all_attendance(
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    employee_id: int | None = Query(default=None),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    stmt = select(Attendance, User).join(User, Attendance.user_id == User.id)
    if start_date:
        stmt = stmt.where(Attendance.work_date >= start_date)
    if end_date:
        stmt = stmt.where(Attendance.work_date <= end_date)
    if employee_id:
        stmt = stmt.where(Attendance.user_id == employee_id)
    records = db.execute(stmt.order_by(Attendance.work_date.desc(), User.name.asc())).all()
    return {"items": [attendance_data(row, employee) for row, employee in records], "total": len(records)}


@app.get("/api/admin/summary")
def attendance_summary(
    work_date: date | None = Query(default=None),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    selected_date = work_date or datetime.now(APP_TIMEZONE).date()
    employees = db.scalars(select(User).where(User.active.is_(True), User.role == "employee")).all()
    rows = db.scalars(select(Attendance).where(Attendance.work_date == selected_date)).all()
    present_ids = {row.user_id for row in rows}
    return {
        "work_date": selected_date.isoformat(),
        "active_employees": len(employees),
        "registered": len(present_ids),
        "missing": max(0, len(employees) - len(present_ids)),
        "with_check_out": sum(1 for row in rows if row.check_out is not None),
        "without_check_out": sum(1 for row in rows if row.check_out is None),
    }
