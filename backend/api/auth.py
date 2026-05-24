import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import bcrypt as _bcrypt_lib
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.models.user import User, get_db, init_db

router = APIRouter(prefix="/auth", tags=["Auth"])

SECRET_KEY         = os.getenv("SECRET_KEY", "phishguard-dev-secret-change-in-production")
ALGORITHM          = "HS256"
TOKEN_EXPIRY_HOURS = 24

# using bcrypt directly (passlib 5.x incompatibility)
oauth2  = OAuth2PasswordBearer(tokenUrl="/auth/login")

VALID_ROLES = {"doctor", "nurse", "admin", "it"}

class RegisterRequest(BaseModel):
    name:       str
    email:      str
    password:   str
    role:       str
    department: Optional[str] = None

class UserOut(BaseModel):
    id:         int
    name:       str
    email:      str
    role:       str
    department: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True

class TokenOut(BaseModel):
    access_token: str
    token_type:   str
    user:         UserOut

def _hash(password):        return _bcrypt_lib.hashpw(password.encode(), _bcrypt_lib.gensalt()).decode()
def _verify(plain, hashed): return _bcrypt_lib.checkpw(plain.encode(), hashed.encode())

def _create_token(data):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    err = HTTPException(status_code=401, detail="Invalid or expired token",
                        headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email   = payload.get("sub")
        if not email: raise err
    except JWTError:
        raise err
    user = db.query(User).filter(User.email == email).first()
    if not user: raise err
    return user

@router.post("/register", response_model=TokenOut, status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if req.role.lower() not in VALID_ROLES:
        raise HTTPException(400, f"Role must be one of: {', '.join(VALID_ROLES)}")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "An account with this email already exists.")
    user = User(
        name=req.name.strip(), email=req.email.lower().strip(),
        role=req.role.lower(), department=req.department,
        hashed_password=_hash(req.password),
    )
    db.add(user); db.commit(); db.refresh(user)
    token = _create_token({"sub": user.email, "role": user.role})
    return TokenOut(access_token=token, token_type="bearer", user=user)

@router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username.lower()).first()
    if not user or not _verify(form.password, user.hashed_password):
        raise HTTPException(401, "Incorrect email or password")
    token = _create_token({"sub": user.email, "role": user.role})
    return TokenOut(access_token=token, token_type="bearer", user=user)

@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
