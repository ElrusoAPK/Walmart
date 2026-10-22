import os, csv, io
from datetime import datetime, date, time, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy import create_engine, String, Integer, Date, Time, DateTime, ForeignKey, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./linkx_asistencia.db')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
elif DATABASE_URL.startswith('postgresql://') and '+psycopg' not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
connect_args = {'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default='employee', nullable=False)
    active: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    attendance: Mapped[list['Attendance']] = relationship(back_populates='user')
class Attendance(Base):
    __tablename__ = 'attendance'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True, nullable=False)
    movement: Mapped[str] = mapped_column(String(10), nullable=False)
    work_date: Mapped[date] = mapped_column(Date, index=True, nullable=False)
    work_time: Mapped[time] = mapped_column(Time, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user: Mapped[User] = relationship(back_populates='attendance')

Base.metadata.create_all(bind=engine)
password_hash = PasswordHash.recommended()
JWT_SECRET = os.getenv('JWT_SECRET', 'local-dev-secret-change-me')
TOKEN_MINUTES = int(os.getenv('ACCESS_TOKEN_MINUTES', '480'))
security = HTTPBearer(auto_error=False)
app = FastAPI(title='LINK X Sistemas - API de Asistencia', version='1.0.0', description='Backend con autenticación, usuarios y registro de entrada/salida.')
origins = [x.strip() for x in os.getenv('CORS_ORIGINS', '*').split(',') if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins if origins != ['*'] else ['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])

class LoginIn(BaseModel): email: EmailStr; password: str
class UserCreate(BaseModel): name: str = Field(min_length=2, max_length=120); email: EmailStr; password: str = Field(min_length=10, max_length=128); role: str = 'employee'
class UserOut(BaseModel): id: int; name: str; email: str; role: str; active: bool
class AttendanceOut(BaseModel): id: int; user_id: int; name: str; email: str; movement: str; date: str; time: str

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def seed_admin():
    email = os.getenv('ADMIN_EMAIL', 'admin@linkx.local').strip().lower()
    password = os.getenv('ADMIN_PASSWORD')
    if not password:
        # Deliberately do not create a known/default administrator password.
        return
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == email))
        if not existing:
            db.add(User(name=os.getenv('ADMIN_NAME', 'Administrador LINK X'), email=email, password_hash=password_hash.hash(password), role='admin'))
            db.commit()
seed_admin()

def user_dict(u: User): return {'id':u.id,'name':u.name,'email':u.email,'role':u.role,'active':bool(u.active)}
def attendance_dict(a: Attendance): return {'id':a.id,'user_id':a.user_id,'name':a.user.name,'email':a.user.email,'movement':a.movement,'date':a.work_date.isoformat(),'time':a.work_time.strftime('%H:%M:%S')}
def make_token(u: User):
    now = datetime.now(timezone.utc)
    return jwt.encode({'sub':str(u.id),'role':u.role,'iat':now,'exp':now+timedelta(minutes=TOKEN_MINUTES)}, JWT_SECRET, algorithm='HS256')
def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security), db: Session = Depends(get_db)):
    if not creds: raise HTTPException(status_code=401, detail='Inicia sesión para continuar.')
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=['HS256'])
        uid = int(payload['sub'])
    except Exception: raise HTTPException(status_code=401, detail='Sesión inválida o expirada.')
    u = db.get(User, uid)
    if not u or not u.active: raise HTTPException(status_code=401, detail='Cuenta no disponible.')
    return u
def admin_only(u: User = Depends(current_user)):
    if u.role != 'admin': raise HTTPException(status_code=403, detail='Acceso exclusivo para administrador.')
    return u

@app.get('/api/health')
def health(): return {'status':'ok','service':'LINK X Asistencia'}
@app.post('/api/auth/login')
def login(data: LoginIn, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == data.email.lower().strip()))
    if not u or not u.active or not password_hash.verify(data.password, u.password_hash):
        raise HTTPException(status_code=401, detail='Correo o contraseña incorrectos.')
    return {'access_token':make_token(u),'token_type':'bearer','user':user_dict(u)}
@app.get('/api/auth/me')
def me(u: User = Depends(current_user)): return user_dict(u)
@app.post('/api/auth/change-password')
def change_password(payload: dict, u: User = Depends(current_user), db: Session = Depends(get_db)):
    old = str(payload.get('current_password','')); new = str(payload.get('new_password',''))
    if not password_hash.verify(old, u.password_hash): raise HTTPException(status_code=400, detail='La contraseña actual no coincide.')
    if len(new) < 10: raise HTTPException(status_code=400, detail='La nueva contraseña debe tener al menos 10 caracteres.')
    u.password_hash = password_hash.hash(new); db.commit(); return {'message':'Contraseña actualizada.'}
@app.get('/api/users')
def list_users(_: User = Depends(admin_only), db: Session = Depends(get_db)):
    return [user_dict(u) for u in db.scalars(select(User).order_by(User.name)).all()]
@app.post('/api/users', status_code=201)
def create_user(data: UserCreate, _: User = Depends(admin_only), db: Session = Depends(get_db)):
    email = data.email.lower().strip()
    if data.role not in ('employee','admin'): raise HTTPException(status_code=400, detail='Perfil inválido.')
    if db.scalar(select(User).where(User.email == email)): raise HTTPException(status_code=409, detail='Ese correo ya está registrado.')
    u = User(name=data.name.strip(), email=email, password_hash=password_hash.hash(data.password), role=data.role)
    db.add(u); db.commit(); db.refresh(u); return user_dict(u)
@app.patch('/api/users/{user_id}/active')
def toggle_user(user_id: int, payload: dict, admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u: raise HTTPException(status_code=404, detail='Usuario no encontrado.')
    active = bool(payload.get('active'))
    if u.id == admin.id and not active: raise HTTPException(status_code=400, detail='No puedes desactivar tu propia cuenta.')
    u.active = int(active); db.commit(); return user_dict(u)
@app.post('/api/attendance/{movement}', status_code=201)
def mark_attendance(movement: str, u: User = Depends(current_user), db: Session = Depends(get_db)):
    if movement not in ('entrada','salida'): raise HTTPException(status_code=400, detail='Movimiento no válido; usa entrada o salida.')
    now = datetime.now(ZoneInfo(os.getenv('APP_TIMEZONE', 'America/Mexico_City'))); today = now.date()
    existing = db.scalars(select(Attendance).where(Attendance.user_id==u.id, Attendance.work_date==today).order_by(Attendance.work_time)).all()
    if movement == 'entrada' and any(a.movement=='Entrada' for a in existing): raise HTTPException(status_code=409, detail='Ya registraste tu entrada de hoy.')
    if movement == 'salida' and not any(a.movement=='Entrada' for a in existing): raise HTTPException(status_code=409, detail='Primero debes registrar tu entrada.')
    if movement == 'salida' and any(a.movement=='Salida' for a in existing): raise HTTPException(status_code=409, detail='Ya registraste tu salida de hoy.')
    a = Attendance(user_id=u.id, movement='Entrada' if movement=='entrada' else 'Salida', work_date=today, work_time=now.time().replace(tzinfo=None, microsecond=0))
    db.add(a); db.commit(); db.refresh(a); return attendance_dict(a)
@app.get('/api/attendance/mine')
def my_attendance(start: Optional[date]=None, end: Optional[date]=None, u: User=Depends(current_user), db: Session=Depends(get_db)):
    q = select(Attendance).where(Attendance.user_id==u.id)
    if start: q=q.where(Attendance.work_date>=start)
    if end: q=q.where(Attendance.work_date<=end)
    return [attendance_dict(a) for a in db.scalars(q.order_by(Attendance.work_date.desc(), Attendance.work_time.desc())).all()]
@app.get('/api/attendance')
def all_attendance(start: Optional[date]=None, end: Optional[date]=None, user_id: Optional[int]=None, _: User=Depends(admin_only), db: Session=Depends(get_db)):
    q=select(Attendance)
    if start: q=q.where(Attendance.work_date>=start)
    if end: q=q.where(Attendance.work_date<=end)
    if user_id: q=q.where(Attendance.user_id==user_id)
    return [attendance_dict(a) for a in db.scalars(q.order_by(Attendance.work_date.desc(), Attendance.work_time.desc())).all()]
@app.get('/api/attendance/today-summary')
def today_summary(_: User=Depends(admin_only), db: Session=Depends(get_db)):
    today=datetime.now(ZoneInfo(os.getenv('APP_TIMEZONE', 'America/Mexico_City'))).date(); people=db.scalars(select(User).where(User.role!='admin',User.active==1).order_by(User.name)).all()
    result=[]
    for u in people:
        records=db.scalars(select(Attendance).where(Attendance.user_id==u.id,Attendance.work_date==today).order_by(Attendance.work_time)).all()
        entry=next((a for a in records if a.movement=='Entrada'),None)
        exit_=next((a for a in reversed(records) if a.movement=='Salida'),None)
        result.append({'user':user_dict(u),'entry':entry.work_time.strftime('%H:%M:%S') if entry else None,'exit':exit_.work_time.strftime('%H:%M:%S') if exit_ else None,'status':'Jornada cerrada' if exit_ else ('En jornada' if entry else 'Sin registro')})
    return result
@app.get('/api/reports/attendance.csv')
def export_csv(start: Optional[date]=None, end: Optional[date]=None, user_id: Optional[int]=None, _: User=Depends(admin_only), db: Session=Depends(get_db)):
    q=select(Attendance)
    if start:q=q.where(Attendance.work_date>=start)
    if end:q=q.where(Attendance.work_date<=end)
    if user_id:q=q.where(Attendance.user_id==user_id)
    rows=db.scalars(q.order_by(Attendance.work_date.desc(),Attendance.work_time.desc())).all()
    out=io.StringIO(); w=csv.writer(out); w.writerow(['Nombre','Correo','Movimiento','Fecha','Hora'])
    for a in rows:w.writerow([a.user.name,a.user.email,a.movement,a.work_date.isoformat(),a.work_time.strftime('%H:%M:%S')])
    return Response(content='\ufeff'+out.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="reporte_asistencia.csv"'})

app.mount('/static', StaticFiles(directory='app/static'), name='static')
@app.get('/')
def home(): return FileResponse('app/static/index.html')
