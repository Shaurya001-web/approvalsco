# ...existing code...
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
import shutil
import os

# =====================================================
# CONFIG
# =====================================================

DATABASE_URL = "sqlite:///./portal.db"
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

if not os.path.exists("uploads"):
    os.makedirs("uploads")

# =====================================================
# DATABASE
# =====================================================

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =====================================================
# MODELS
# =====================================================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    role = Column(String)   # client / admin


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)


class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    text = Column(Text)
    document_id = Column(Integer, ForeignKey("documents.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    action = Column(String)
    user_id = Column(Integer)
    document_id = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# =====================================================
# APP
# =====================================================

app = FastAPI(title="Secure Client Approval Portal")

# =====================================================
# HELPERS
# =====================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=5)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# =====================================================
# AUTH
# =====================================================

@app.post("/register")
def register(username: str, password: str, role: str, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "User already exists")

    user = User(
        username=username,
        password=hash_password(password),
        role=role
    )
    db.add(user)
    db.commit()
    return {"message": "User registered"}


@app.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(401, "Invalid credentials")

    token = create_token({"user_id": user.id})
    return {"access_token": token}

# =====================================================
# DOCUMENT UPLOAD
# =====================================================

@app.post("/upload")
def upload_file(user_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):

    filepath = f"uploads/{file.filename}"

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    doc = Document(filename=file.filename, owner_id=user_id)
    db.add(doc)
    db.commit()

    log = AuditLog(action="uploaded", user_id=user_id, document_id=doc.id)
    db.add(log)
    db.commit()

    return {"message": "File uploaded", "doc_id": doc.id}

# =====================================================
# VIEW DOCUMENTS
# =====================================================

@app.get("/documents")
def list_documents(db: Session = Depends(get_db)):
    return db.query(Document).all()

# =====================================================
# COMMENT SYSTEM
# =====================================================

@app.post("/comment/{doc_id}")
def add_comment(doc_id: int, user_id: int, text: str, db: Session = Depends(get_db)):
    comment = Comment(text=text, document_id=doc_id, user_id=user_id)
    db.add(comment)
    db.commit()
    return {"message": "Comment added"}

# =====================================================
# APPROVAL WORKFLOW
# =====================================================

@app.post("/approve/{doc_id}")
def approve_document(doc_id: int, user_id: int, db: Session = Depends(get_db)):
    doc = db.query(Document).get(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    doc.status = "approved"
    db.commit()

    log = AuditLog(action="approved", user_id=user_id, document_id=doc_id)
    db.add(log)
    db.commit()

    return {"message": "Document approved"}


@app.post("/reject/{doc_id}")
def reject_document(doc_id: int, user_id: int, db: Session = Depends(get_db)):
    doc = db.query(Document).get(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    doc.status = "rejected"
    db.commit()

    log = AuditLog(action="rejected", user_id=user_id, document_id=doc_id)
    db.add(log)
    db.commit()

    return {"message": "Document rejected"}

# =====================================================
# AUDIT HISTORY
# =====================================================

@app.get("/audit")
def audit_logs(db: Session = Depends(get_db)):
    return db.query(AuditLog).all()
# ...existing code...
# ...existing code...
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("Pandas.main:app", host="127.0.0.1", port=8000, reload=True)
