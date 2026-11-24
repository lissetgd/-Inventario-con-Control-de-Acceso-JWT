import os
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import jwt
from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "tu_clave_secreta_super_segura_cambiala")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- CONFIGURACIÓN DE SEGURIDAD ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- CONTROL DEL POOL DE CONEXIONES ---
db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    db_pool = ThreadedConnectionPool(0, 10, dsn=DATABASE_URL, cursor_factory=RealDictCursor)
    yield
    if db_pool:
        db_pool.closeall()

app = FastAPI(
    title="API de Inventario - Neon Cloud con JWT",
    description="Backend con autenticación JWT y roles (administrador / almacenista).",
    version="2.0.0",
    lifespan=lifespan
)

# --- PERMISOS CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    global db_pool
    try:
        conn = db_pool.getconn()
        if conn.closed != 0:
            db_pool.putconn(conn, close=True)
            conn = db_pool.getconn()
        return conn
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener conexión del pool: {str(e)}"
        )

def release_db_connection(conn):
    global db_pool
    if conn and db_pool:
        try:
            db_pool.putconn(conn)
        except Exception:
            pass


# --- MODELOS PYDANTIC ---
class MovimientoInventario(BaseModel):
    id_producto: int
    tipo_movimiento: str
    cantidad: int
    motivo: str

class CategoriaCreate(BaseModel):
    nombre: str
    descripcion: str | None = None

class ProveedorCreate(BaseModel):
    nombre_empresa: str
    contacto_nombre: str | None = None
    telefono: str | None = None
    email: str | None = None
    direccion: str | None = None

class ProductoCreate(BaseModel):
    codigo_barras: str
    nombre: str
    descripcion: str | None = None
    id_categoria: int | None = None
    id_proveedor: int | None = None
    precio_compra: float
    precio_venta: float
    stock_actual: int
    stock_minimo: int = 5


# --- FUNCIONES DE AUTENTICACIÓN Y ROLES ---
def verificar_password(plain_password, hashed_password):
    # Si guardaste la contraseña en texto plano para pruebas (ej. '123456'), 
    # esto la valida directo. Si usas passlib, puedes dejar pwd_context.verify(...)
    if plain_password == hashed_password:
        return True
    return pwd_context.verify(plain_password, hashed_password)

def obtener_usuario_por_username(username: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Apuntamos a la nueva tabla exclusiva del inventario y usamos username
            cursor.execute("SELECT * FROM usuarios_inventario WHERE username = %s;", (username,))
            return cursor.fetchone()
    finally:
        release_db_connection(conn)

def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        rol: str = payload.get("rol")
        if username is None:
            raise credentials_exception
        return {"username": username, "rol": rol}
    except jwt.PyJWTError:
        raise credentials_exception

# Dependencia para verificar Rol de Administrador
def solo_administrador(usuario: dict = Depends(obtener_usuario_actual)):
    if usuario["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado. Se requiere rol de Administrador."
        )
    return usuario

# Dependencia para verificar Almacenista o Administrador
def almacenista_o_admin(usuario: dict = Depends(obtener_usuario_actual)):
    if usuario["rol"] not in ["administrador", "almacenista"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado. Permisos insuficientes."
        )
    return usuario


# --- ENDPOINTS DE AUTENTICACIÓN ---
@app.post("/token", tags=["Autenticación"])
def login_para_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = obtener_usuario_por_username(form_data.username)
    if not user or not verificar_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user["username"],
        "rol": user["rol"],
        "exp": datetime.utcnow() + access_token_expires
    }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": encoded_jwt, "token_type": "bearer"}


# --- ENDPOINTS ---
@app.get("/")
def root():
    return RedirectResponse(url="/app/")

@app.get("/productos", tags=["Inventario"])
def obtener_inventario(usuario: dict = Depends(almacenista_o_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT 
                    p.id_producto, 
                    p.codigo_barras, 
                    p.nombre AS producto, 
                    c.nombre AS categoria, 
                    prov.nombre_empresa AS proveedor, 
                    p.stock_actual, 
                    p.stock_minimo, 
                    p.precio_venta 
                FROM productos p 
                LEFT JOIN categorias c ON p.id_categoria = c.id_categoria 
                LEFT JOIN proveedores prov ON p.id_proveedor = prov.id_proveedor 
                ORDER BY p.id_producto DESC;
            """
            cursor.execute(query)
            productos = cursor.fetchall()
            return {"productos": productos}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener el inventario: {str(e)}"
        )
    finally:
        release_db_connection(conn)

@app.post("/productos", tags=["Inventario"])
def crear_producto(prod: ProductoCreate, usuario: dict = Depends(almacenista_o_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                INSERT INTO productos (codigo_barras, nombre, descripcion, id_categoria, id_proveedor, precio_compra, precio_venta, stock_actual, stock_minimo)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_producto, nombre, stock_actual;
            """
            cursor.execute(query, (
                prod.codigo_barras, prod.nombre, prod.descripcion, 
                prod.id_categoria, prod.id_proveedor, prod.precio_compra, 
                prod.precio_venta, prod.stock_actual, prod.stock_minimo
            ))
            nuevo = cursor.fetchone()
            conn.commit()
            return {"mensaje": "Producto creado con éxito", "producto": nuevo}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error al crear producto: {str(e)}")
    finally:
        release_db_connection(conn)

@app.get("/categorias", tags=["Catálogos"])
def obtener_categorias(usuario: dict = Depends(almacenista_o_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_categoria, nombre, descripcion FROM categorias;")
            cats = cursor.fetchall()
            return {"categorias": cats}
    finally:
        release_db_connection(conn)

@app.post("/categorias", tags=["Catálogos"])
def crear_categoria(cat: CategoriaCreate, usuario: dict = Depends(solo_administrador)):
    # Solo el Administrador puede crear nuevas categorías (ejemplo de restricción por rol)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                INSERT INTO categorias (nombre, descripcion)
                VALUES (%s, %s)
                RETURNING id_categoria, nombre, descripcion;
            """
            cursor.execute(query, (cat.nombre, cat.descripcion))
            nuevo = cursor.fetchone()
            conn.commit()
            return {"mensaje": "Categoría creada con éxito", "categoria": nuevo}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error al crear categoría: {str(e)}")
    finally:
        release_db_connection(conn)

@app.get("/proveedores", tags=["Catálogos"])
def obtener_proveedores(usuario: dict = Depends(almacenista_o_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_proveedor, nombre_empresa, contacto_nombre, telefono, email, direccion FROM proveedores;")
            provs = cursor.fetchall()
            return {"proveedores": provs}
    finally:
        release_db_connection(conn)

@app.post("/proveedores", tags=["Catálogos"])
def crear_proveedor(prov: ProveedorCreate, usuario: dict = Depends(solo_administrador)):
    # Solo el Administrador puede registrar nuevos proveedores
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                INSERT INTO proveedores (nombre_empresa, contacto_nombre, telefono, email, direccion)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id_proveedor, nombre_empresa, contacto_nombre, telefono, email, direccion;
            """
            cursor.execute(query, (
                prov.nombre_empresa, 
                prov.contacto_nombre, 
                prov.telefono, 
                prov.email, 
                prov.direccion
            ))
            nuevo = cursor.fetchone()
            conn.commit()
            return {"mensaje": "Proveedor registrado con éxito", "proveedor": nuevo}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error al registrar proveedor: {str(e)}")
    finally:
        release_db_connection(conn)

@app.get("/productos/alertas", tags=["Inventario"])
def obtener_alertas_stock(usuario: dict = Depends(almacenista_o_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_producto, codigo_barras, nombre, stock_actual, stock_minimo FROM productos WHERE stock_actual <= stock_minimo;")
            alertas = cursor.fetchall()
            return {"alertas_stock": alertas}
    finally:
        release_db_connection(conn)

@app.post("/movimientos", tags=["Movimientos"])
def registrar_movimiento(movimiento: MovimientoInventario, usuario: dict = Depends(almacenista_o_admin)):
    tipo = movimiento.tipo_movimiento.upper()
    if tipo not in ['ENTRADA', 'SALIDA', 'AJUSTE']:
        raise HTTPException(status_code=400, detail="Tipo de movimiento inválido.")
    if movimiento.cantidad <= 0:
        raise HTTPException(status_code=400, detail="La cantidad debe ser mayor a cero.")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT stock_actual FROM productos WHERE id_producto = %s FOR UPDATE;", 
                (movimiento.id_producto,)
            )
            producto = cursor.fetchone()
            if not producto:
                raise HTTPException(status_code=404, detail="Producto no encontrado.")
            
            stock_actual = producto["stock_actual"]

            if tipo == 'ENTRADA':
                nuevo_stock = stock_actual + movimiento.cantidad
            elif tipo == 'SALIDA':
                nuevo_stock = stock_actual - movimiento.cantidad
                if nuevo_stock < 0:
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Stock insuficiente. Stock actual: {stock_actual}, Intentando retirar: {movimiento.cantidad}"
                    )
            elif tipo == 'AJUSTE':
                nuevo_stock = movimiento.cantidad

            cursor.execute(
                "UPDATE productos SET stock_actual = %s WHERE id_producto = %s;",
                (nuevo_stock, movimiento.id_producto)
            )

            query = """
                INSERT INTO historial_inventario (id_producto, tipo_movimiento, cantidad, motivo)
                VALUES (%s, %s, %s, %s)
                RETURNING id_movimiento, fecha_movimiento;
            """
            cursor.execute(query, (movimiento.id_producto, tipo, movimiento.cantidad, movimiento.motivo))
            resultado = cursor.fetchone()
            
            conn.commit()
            
            return {
                "mensaje": f"Movimiento '{tipo}' registrado con éxito.", 
                "stock_anterior": stock_actual,
                "stock_actual": nuevo_stock,
                "detalle": resultado
            }
            
    except HTTPException as he:
        conn.rollback()
        raise he
    except psycopg2.errors.RaiseException as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=e.pgerror.split("\n")[0])
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error interno al registrar movimiento: {str(e)}")
    finally:
        release_db_connection(conn)

# --- RUTAS DE ARCHIVOS ESTÁTICOS ---
if os.path.exists("static"):
    app.mount("/app", StaticFiles(directory="static", html=True), name="frontend")