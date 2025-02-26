from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from sqlalchemy import Column, Integer, String, Float, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded


app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware) 

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY no definido en variables de entorno")

SECRET_KEY = SECRET_KEY.encode()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(plaintext: str, key: bytes):
    iv = os.urandom(12) 
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt_data(ciphertext: str, key: bytes):
    try:
        data = base64.b64decode(ciphertext.encode())
        
        iv = data[:12] 
        tag = data[12:28] 
        ciphertext = data[28:] 

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al desencriptar: {str(e)}")


salt = os.urandom(16)  
key = generate_key(SECRET_KEY.decode(), salt)

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ProductDB(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    descripcion = Column(String, nullable=False)
    precio = Column(Float, nullable=False)
    stock = Column(Integer, nullable=False)

Base.metadata.create_all(bind=engine)
# Modelo para validación de datos
class Product(BaseModel):
    nombre: str
    descripcion: str
    precio: float
    stock: int

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

usuario_acceso = {
    "email": "mail@mail.com",
    "hashed_password": "$2b$12$JYgereRXM2J2cw2Urkqu2uhHVH2t29mo5JWyVrBF6uHx7YJC/nT1."
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.exception_handler(RateLimitExceeded)
def rate_limit_error(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Has superado el límite de intentos. Intenta de nuevo más tarde."},
    )
@app.post("/login")
@limiter.limit("5/minute")  
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != usuario_acceso["email"] or not verify_password(form_data.password, usuario_acceso["hashed_password"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


@app.post("/products/")
def create_product(product: Product, user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        encrypted_name = encrypt_data(product.nombre, key)
        encrypted_description = encrypt_data(product.descripcion, key)

        db_product = ProductDB(
            nombre=encrypted_name,
            descripcion=encrypted_description,
            precio=product.precio,
            stock=product.stock
        )
        db.add(db_product)
        db.commit()
        db.refresh(db_product)
        return {"message": "Producto creado", "id": db_product.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/products/{product_id}")
def get_product(product_id: int, user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    product = db.query(ProductDB).filter(ProductDB.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    try:
        if product.nombre and product.descripcion:
            product.nombre = decrypt_data(product.nombre, key)
            product.descripcion = decrypt_data(product.descripcion, key)
        
        return product
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al desencriptar: {str(e)}")


@app.put("/products/{product_id}")
def update_product(product_id: int, product: Product, user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    db_product = db.query(ProductDB).filter(ProductDB.id == product_id).first()
    if not db_product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    try:
        db_product.nombre = encrypt_data(product.nombre, key)
        db_product.descripcion = encrypt_data(product.descripcion, key)
        db_product.precio = product.precio
        db_product.stock = product.stock

        db.commit()
        return {"message": "Producto actualizado"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar: {str(e)}")

@app.delete("/products/{product_id}")
def delete_product(product_id: int, user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    db_product = db.query(ProductDB).filter(ProductDB.id == product_id).first()
    if not db_product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    try:
        db.delete(db_product)
        db.commit()
        return {"message": "Producto eliminado"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar: {str(e)}")
