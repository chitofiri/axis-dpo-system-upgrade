"""
Axis DPO unified API.
Production: set DATABASE_URL, JWT_SECRET, AXIS_ADMIN_EMAIL, AXIS_ADMIN_PASSWORD.
A single API and shared PostgreSQL database are used for admin + client tenants.
"""
import os, hashlib, secrets
from datetime import datetime, timedelta, timezone, date
from typing import Optional
import jwt
from pwdlib import PasswordHash
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, String, Integer, Boolean, DateTime, Date, Text, ForeignKey, select, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./axis_local.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
passwords = PasswordHash.recommended()
JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET and DATABASE_URL.startswith("postgresql"):
    raise RuntimeError("Set a strong JWT_SECRET environment variable in Render.")
JWT_SECRET = JWT_SECRET or "LOCAL-ONLY-CHANGE-ME"
JWT_ALGORITHM = "HS256"
TOKEN_HOURS = 8

class Base(DeclarativeBase): pass

class Company(Base):
    __tablename__ = "companies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(240), unique=True, index=True)
    registration_number: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    users: Mapped[list["User"]] = relationship(back_populates="company")

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(20), index=True)  # admin / client
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    company: Mapped[Optional[Company]] = relationship(back_populates="users")

class Compliance(Base):
    __tablename__ = "compliance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), unique=True, index=True)
    dp1_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    dp1_reg_number: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    dp1_filename: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dp1_issue_date: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    dp1_expiry_date: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    dp1_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dp2_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    dp2_dpo_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    dp2_filename: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    kaspersky_filename: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vulnerabilities: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    company_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def make_token(user: User):
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user.id), "role": user.role, "company_id": user.company_id,
               "iat": now, "exp": now + timedelta(hours=TOKEN_HOURS)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def current_user(authorization: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please sign in.")
    try:
        claims = jwt.decode(authorization[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = db.get(User, int(claims["sub"]))
    except Exception:
        raise HTTPException(401, "Session is invalid or expired. Please sign in again.")
    if not user or not user.active:
        raise HTTPException(401, "Account is inactive.")
    return user

def require_admin(user: User = Depends(current_user)):
    if user.role != "admin": raise HTTPException(403, "Administrator access required.")
    return user

def require_client(user: User = Depends(current_user)):
    if user.role != "client" or not user.company_id: raise HTTPException(403, "Client DPO access required.")
    return user

def compliance_for(db: Session, company_id: int):
    row = db.scalar(select(Compliance).where(Compliance.company_id == company_id))
    if not row:
        row = Compliance(company_id=company_id)
        db.add(row); db.commit(); db.refresh(row)
    return row

def log(db, user, action, details=""):
    db.add(AuditLog(actor_user_id=user.id if user else None,
                    company_id=user.company_id if user else None,
                    action=action, details=details))
    db.commit()

app = FastAPI(title="Axis DPO Management API", version="3.0.0",
              description="Authenticated multi-company compliance workspace.")
origins = [x.strip() for x in os.getenv("FRONTEND_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET","POST","PATCH","OPTIONS"], allow_headers=["Authorization","Content-Type"])

class LoginBody(BaseModel):
    email: EmailStr
    password: str
class CompanyCreate(BaseModel):
    company_name: str
    registration_number: Optional[str] = None
    dpo_name: str
    dpo_email: EmailStr
    temporary_password: str
class CompanyUpdate(BaseModel):
    active: Optional[bool] = None
class PasswordChange(BaseModel):
    current_password: str
    new_password: str

@app.on_event("startup")
def seed_admin():
    email = os.getenv("AXIS_ADMIN_EMAIL")
    password = os.getenv("AXIS_ADMIN_PASSWORD")
    if not email or not password:
        return
    if len(password) < 12:
        raise RuntimeError("AXIS_ADMIN_PASSWORD must be at least 12 characters.")
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == email.lower()))
        if not existing:
            db.add(User(email=email.lower(), full_name="Axis System Administrator",
                        password_hash=passwords.hash(password), role="admin", active=True))
            db.commit()

@app.get("/health")
def health():
    return {"status":"ok","service":"axis-dpo-unified-api","database":"configured"}

@app.post("/api/v1/auth/login")
def login(payload: LoginBody, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if not user or not user.active or not passwords.verify(payload.password, user.password_hash):
        raise HTTPException(401, "Email or password is incorrect.")
    company = db.get(Company, user.company_id) if user.company_id else None
    return {"access_token": make_token(user), "token_type":"bearer",
            "user":{"id":user.id,"name":user.full_name,"email":user.email,"role":user.role,
                    "company_id":user.company_id,"company_name":company.name if company else "Axis Solutions"}}

@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    company = db.get(Company, user.company_id) if user.company_id else None
    return {"id":user.id,"name":user.full_name,"email":user.email,"role":user.role,
            "company_id":user.company_id,"company_name":company.name if company else "Axis Solutions"}

@app.post("/api/v1/auth/change-password")
def change_password(payload: PasswordChange, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if len(payload.new_password) < 12: raise HTTPException(422, "New password must be at least 12 characters.")
    if not passwords.verify(payload.current_password, user.password_hash): raise HTTPException(400, "Current password is incorrect.")
    user.password_hash = passwords.hash(payload.new_password); db.commit()
    log(db, user, "password_changed")
    return {"changed":True}

@app.get("/api/v1/admin/companies")
def admin_companies(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    companies = db.scalars(select(Company).order_by(Company.name)).all()
    output=[]
    for c in companies:
        dpo=db.scalar(select(User).where(User.company_id==c.id, User.role=="client"))
        r=compliance_for(db,c.id)
        output.append({"id":c.id,"name":c.name,"registration_number":c.registration_number,
                       "dpo_name":dpo.full_name if dpo else None,"dpo_email":dpo.email if dpo else None,
                       "dpo_active":dpo.active if dpo else False,"dp1_verified":r.dp1_verified,
                       "dp1_expiry_date":r.dp1_expiry_date,"dp2_verified":r.dp2_verified,
                       "vulnerabilities":[v for v in r.vulnerabilities.split(",") if v]})
    return {"total":len(output),"companies":output}

@app.post("/api/v1/admin/companies", status_code=201)
def create_company(payload: CompanyCreate, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if len(payload.temporary_password) < 12: raise HTTPException(422,"Temporary password must be at least 12 characters.")
    email=payload.dpo_email.lower().strip()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,"That email already has an account.")
    if db.scalar(select(Company).where(Company.name==payload.company_name.strip())): raise HTTPException(409,"That company is already registered.")
    company=Company(name=payload.company_name.strip(),registration_number=payload.registration_number)
    db.add(company); db.flush()
    dpo=User(email=email,full_name=payload.dpo_name.strip(),password_hash=passwords.hash(payload.temporary_password),
             role="client",company_id=company.id,active=True)
    db.add(dpo); db.add(Compliance(company_id=company.id)); db.commit()
    log(db,user,"company_created",f"company_id={company.id}; dpo_email={email}")
    return {"created":True,"company_id":company.id,"company_name":company.name,"dpo_email":email,
            "message":"Give the DPO their temporary password securely. They should change it after signing in."}

@app.patch("/api/v1/admin/companies/{company_id}/dpo-status")
def set_dpo_status(company_id:int, payload:CompanyUpdate, user:User=Depends(require_admin), db:Session=Depends(get_db)):
    company=db.get(Company,company_id)
    if not company: raise HTTPException(404,"Company not found.")
    dpo=db.scalar(select(User).where(User.company_id==company_id,User.role=="client"))
    if not dpo: raise HTTPException(404,"DPO account not found.")
    if payload.active is not None: dpo.active=payload.active
    db.commit(); log(db,user,"dpo_status_changed",f"company_id={company_id}; active={dpo.active}")
    return {"updated":True,"active":dpo.active}

@app.get("/api/v1/client/records")
def client_records(user:User=Depends(require_client),db:Session=Depends(get_db)):
    c=db.get(Company,user.company_id); r=compliance_for(db,user.company_id)
    days=None
    if r.dp1_expiry_date:
        try: days=(date.fromisoformat(r.dp1_expiry_date)-date.today()).days
        except ValueError: pass
    flags=[v for v in r.vulnerabilities.split(",") if v]
    return {"company":{"id":c.id,"name":c.name,"registration_number":c.registration_number},
            "dpo":{"name":user.full_name,"email":user.email},
            "dp1":{"verified":r.dp1_verified,"reg_number":r.dp1_reg_number,"filename":r.dp1_filename,
                   "issue_date":r.dp1_issue_date,"expiry_date":r.dp1_expiry_date,"days_remaining":days},
            "dp2":{"verified":r.dp2_verified,"dpo_name":r.dp2_dpo_name,"filename":r.dp2_filename},
            "kaspersky":{"filename":r.kaspersky_filename,"flags":flags},
            "updated_at":r.updated_at.isoformat() if r.updated_at else None}

@app.post("/api/v1/client/documents/dp1")
async def upload_dp1(reg_number:str=Form(...),issue_date:str=Form(...),expiry_date:str=Form(...),
                     file:UploadFile=File(...),user:User=Depends(require_client),db:Session=Depends(get_db)):
    if not file.filename.lower().endswith((".pdf",".doc",".docx")): raise HTTPException(422,"Upload a PDF or Word document.")
    try: validity=date.fromisoformat(expiry_date)
    except ValueError: raise HTTPException(422,"Expiry date must use YYYY-MM-DD.")
    if validity < date.today(): raise HTTPException(400,"This licence is expired. Upload a current licence.")
    content=await file.read()
    if len(content)>15*1024*1024: raise HTTPException(413,"File exceeds the 15 MB limit.")
    r=compliance_for(db,user.company_id)
    r.dp1_verified=True;r.dp1_reg_number=reg_number;r.dp1_filename=file.filename
    r.dp1_issue_date=issue_date;r.dp1_expiry_date=expiry_date;r.dp1_sha256=hashlib.sha256(content).hexdigest()
    r.updated_at=datetime.now(timezone.utc);db.commit();log(db,user,"dp1_uploaded",file.filename)
    days=(validity-date.today()).days
    return {"verified":True,"vault_locked":True,"sha256":r.dp1_sha256,
            "licence_validity":{"status":"EXPIRING_SOON" if days<=90 else "VALID","days_remaining":days,"requires_alert":days<=90}}

@app.post("/api/v1/client/documents/dp2")
async def upload_dp2(dpo_name:str=Form(...),file:UploadFile=File(...),
                     user:User=Depends(require_client),db:Session=Depends(get_db)):
    if not file.filename.lower().endswith((".pdf",".doc",".docx")): raise HTTPException(422,"Upload a PDF or Word document.")
    content=await file.read()
    if len(content)>15*1024*1024: raise HTTPException(413,"File exceeds the 15 MB limit.")
    r=compliance_for(db,user.company_id);r.dp2_verified=True;r.dp2_dpo_name=dpo_name
    r.dp2_filename=file.filename;r.updated_at=datetime.now(timezone.utc);db.commit()
    log(db,user,"dp2_uploaded",file.filename)
    return {"verified":True,"vault_locked":True,"dpo_name":dpo_name}

@app.post("/api/v1/client/telemetry/kaspersky")
async def upload_kaspersky(file:UploadFile=File(...),user:User=Depends(require_client),db:Session=Depends(get_db)):
    content=await file.read()
    if len(content)>15*1024*1024: raise HTTPException(413,"File exceeds the 15 MB limit.")
    sample=content.decode("utf-8",errors="ignore").lower()
    flags=[]
    if "unpatched" in sample: flags.append("Unpatched Endpoints")
    if "malware" in sample or "trojan" in sample: flags.append("Active Malware")
    if "ransomware" in sample: flags.append("Ransomware Signature")
    r=compliance_for(db,user.company_id);r.kaspersky_filename=file.filename
    r.vulnerabilities=",".join(flags);r.updated_at=datetime.now(timezone.utc);db.commit()
    log(db,user,"kaspersky_uploaded",file.filename)
    return {"scanned":True,"flags":flags}

@app.get("/api/v1/admin/audit")
def audit(user:User=Depends(require_admin),db:Session=Depends(get_db)):
    rows=db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)).all()
    return [{"actor_user_id":x.actor_user_id,"company_id":x.company_id,"action":x.action,
             "details":x.details,"created_at":x.created_at.isoformat()} for x in rows]
