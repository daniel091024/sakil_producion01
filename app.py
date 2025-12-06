from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave_super_secreta")

# 🔹 Configuración de PostgreSQL para Render
database_url = os.environ.get("DATABASE_URL")

# Fix para Render: Cambiar postgres:// a postgresql://
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or "postgresql://postgres:password@localhost:5432/sakil"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configuración de correo
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "tu_correo@gmail.com")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "tu_contraseña_app")

mail = Mail(app)

# Serializer para tokens
s = URLSafeTimedSerializer(app.secret_key)

# Carpeta donde se guardarán las imágenes
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "img")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# Crear carpeta de uploads si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("usuario"):
            flash("Debes iniciar sesión para acceder a esta página", "warning")
            return redirect(url_for("login"))
        if session.get("rol") != 1:
            flash("No tienes permisos para acceder a esta página", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario" not in session:
            flash("Debes iniciar sesión para acceder a esta función.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Modelo rol
class Rol(db.Model):
    __tablename__ = "rol"
    id_rol = db.Column(db.Integer, primary_key=True)
    rol = db.Column(db.String(50), nullable=False)

    usuarios = db.relationship("Usuario", back_populates="rol")

class Usuario(db.Model):
    __tablename__ = "usuario"

    id_cliente = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    ciudad = db.Column(db.String(100), nullable=True)
    direccion = db.Column(db.String(100), nullable=True)
    fecha_nac = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefono = db.Column(db.String(20), nullable=True)
    contraseña = db.Column(db.String(255), nullable=False)

    intentos_fallidos = db.Column(db.Integer, default=0)
    bloqueado = db.Column(db.Boolean, default=False)

    id_rol = db.Column(db.Integer, db.ForeignKey("rol.id_rol"), nullable=False)
    estado = db.Column(db.Boolean, default=True)

    rol = db.relationship("Rol", back_populates="usuarios")

# Modelo de la tabla productos
class Producto(db.Model):
    __tablename__ = "productos"
    id_producto = db.Column(db.Integer, primary_key=True)
    nom_producto = db.Column(db.Text, nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    stok = db.Column(db.Integer, nullable=False)
    id_categoria = db.Column(db.Integer, db.ForeignKey("categoria.id_categoria"), nullable=False)
    precio_producto = db.Column(db.String(20), nullable=False)
    foto = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"<Producto {self.nom_producto}>"

# Modelo de la tabla categoria
class Categoria(db.Model):
    __tablename__ = "categoria"
    id_categoria = db.Column(db.Integer, primary_key=True)
    nom_categoria = db.Column(db.Text, nullable=False)

    productos = db.relationship("Producto", backref="categoria", lazy=True)

# ------------------- RUTAS -------------------

@app.route("/")
def home():
    mensaje = session.get("usuario", None)
    whatsapp_url = "https://wa.me/573236421260"
    estilo = 1

    return render_template(
        "home.html",
        mensaje=mensaje,
        whatsapp_url=whatsapp_url,
        estilo=estilo
    )

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario:
            return render_template("login.html", error="Credenciales inválidas")

        if usuario.bloqueado:
            return render_template("login.html", error="Tu cuenta está bloqueada. Restablece tu contraseña.")

        if check_password_hash(usuario.contraseña, password):
            usuario.intentos_fallidos = 0
            db.session.commit()

            session["usuario"] = f"{usuario.nombre} {usuario.apellido}"
            session["rol"] = usuario.id_rol
            flash("Has iniciado sesión correctamente", "success")
            return redirect(url_for("home"))

        else:
            usuario.intentos_fallidos += 1

            if usuario.intentos_fallidos >= 3:
                usuario.bloqueado = True
                db.session.commit()
                flash("Tu cuenta ha sido bloqueada. Restablece tu contraseña.", "danger")
                return redirect(url_for("forgot_password"))

            db.session.commit()
            return render_template("login.html", error=f"Contraseña incorrecta. Intentos: {usuario.intentos_fallidos}/3")

    return render_template("login.html")

# REGISTRO
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        apellido = request.form["apellido"].strip()
        email = request.form["email"].strip().lower()
        raw_password = request.form["password"]

        if Usuario.query.filter_by(email=email).first():
            return render_template("registro.html", error="El correo ya está registrado")

        nuevo_usuario = Usuario(
            nombre=request.form["nombre"],
            apellido=request.form["apellido"],
            ciudad=request.form["ciudad"],
            direccion=request.form["direccion"],
            fecha_nac=request.form.get("fecha_nac"),
            email=request.form["email"],
            telefono=request.form["telefono"],
            contraseña=generate_password_hash(request.form["password"]),
            intentos_fallidos=0,
            bloqueado=False,
            id_rol=2,
            estado=True
        )

        db.session.add(nuevo_usuario)
        db.session.commit()
        flash("Usuario registrado con éxito", "success")
        return redirect(url_for("login"))

    return render_template("registro.html")

# OLVIDE MI CONTRASEÑA
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        user = db.session.execute(
            db.select(Usuario).filter_by(email=email)
        ).scalar_one_or_none()

        if not user:
            flash("⚠️ No existe ninguna cuenta con ese correo.", "danger")
            return redirect(url_for("forgot_password"))

        token = s.dumps(email, salt="reset-password")
        reset_url = url_for("reset_password", token=token, _external=True)
        flash(f"🔗 Enlace de recuperación (pruebas): <a href='{reset_url}'>{reset_url}</a>", "info")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt="reset-password", max_age=3600)
    except:
        flash("❌ El enlace no es válido o ya expiró.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        nueva = request.form["password"]
        hashed = generate_password_hash(nueva)

        user = db.session.execute(
            db.select(Usuario).filter_by(email=email)
        ).scalar_one_or_none()

        if user:
            user.contraseña = hashed
            user.bloqueado = False
            user.intentos_fallidos = 0
            db.session.commit()
            flash("✅ Contraseña restablecida con éxito.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

# LISTAR USUARIOS
@app.route("/usuarios")
@admin_required
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template("usuarios.html", usuarios=usuarios)

# EDITAR USUARIO
@app.route("/editar/<int:id_cliente>", methods=["GET", "POST"])
def editar_usuario(id_cliente):
    usuario = Usuario.query.get_or_404(id_cliente)

    if request.method == "POST":
        usuario.nombre = request.form["nombre"].strip()
        usuario.apellido = request.form["apellido"].strip()
        usuario.email = request.form["email"].strip().lower()

        new_pwd = request.form.get("password", "")
        if new_pwd.strip():
            usuario.contraseña = generate_password_hash(new_pwd)

        db.session.commit()
        flash("Usuario actualizado correctamente", "info")
        return redirect(url_for("listar_usuarios"))

    return render_template("editar.html", usuario=usuario)

# ELIMINAR USUARIO
@app.route("/eliminar/<int:id_cliente>")
def eliminar_usuario(id_cliente):
    usuario = Usuario.query.get_or_404(id_cliente)
    db.session.delete(usuario)
    db.session.commit()
    flash("Usuario eliminado correctamente", "danger")
    return redirect(url_for("listar_usuarios"))

# LOGOUT
@app.route("/logout")
def logout():
    session.pop("usuario", None)
    flash("Sesión cerrada", "warning")
    return redirect(url_for("home"))

# RUTAS ADMIN
@app.route("/admin/productos")
@admin_required
def admin_productos():
    productos = Producto.query.all()
    categorias = Categoria.query.all()
    return render_template(
        "admin_productos.html",
        productos=productos,
        categorias=categorias
    )

@app.route("/admin/productos/nuevo", methods=["GET", "POST"])
def nuevo_producto():
    categorias = Categoria.query.all()
    
    if request.method == "POST":
        nom_producto = request.form["nom_producto"]
        descripcion = request.form["descripcion"]
        precio = request.form["precio_producto"]
        stok = request.form["stok"]
        id_categoria = request.form["id_categoria"]

        file = request.files.get("foto")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        else:
            filename = "default.jpg"

        nuevo = Producto(
            nom_producto=nom_producto,
            descripcion=descripcion,
            precio_producto=precio,
            stok=stok,
            id_categoria=id_categoria,
            foto=filename
        )

        db.session.add(nuevo)
        db.session.commit()
        flash("Producto agregado con éxito", "success")
        return redirect(url_for("admin_productos"))

    return render_template("form_producto.html", accion="Crear", producto=None, categorias=categorias)

@app.route("/admin/productos/editar/<int:id>", methods=["GET", "POST"])
def editar_producto(id):
    producto = Producto.query.get_or_404(id)
    categorias = Categoria.query.all()

    if request.method == "POST":
        producto.nom_producto = request.form["nom_producto"]
        producto.descripcion = request.form["descripcion"]
        producto.precio_producto = request.form["precio_producto"]
        producto.stok = request.form["stok"]
        producto.id_categoria = request.form["id_categoria"]

        file = request.files.get("foto")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            producto.foto = filename

        db.session.commit()
        flash("Producto actualizado con éxito", "info")
        return redirect(url_for("admin_productos"))

    return render_template("form_producto.html", accion="Editar", producto=producto, categorias=categorias)

@app.route("/admin/productos/eliminar/<int:id>", methods=["POST"])
def eliminar_producto(id):
    producto = Producto.query.get_or_404(id)
    db.session.delete(producto)
    db.session.commit()
    flash("🗑️ Producto eliminado con éxito", "danger")
    return redirect(url_for("admin_productos"))

# RUTAS CATÁLOGO PÚBLICO
@app.route("/catalogo")
def catalogo():
    productos = Producto.query.all()
    categorias = Categoria.query.all()
    return render_template(
        "catalogo.html",
        productos=productos,
        categorias=categorias
    )

@app.route("/carrito/agregar/<int:id>")
@login_required
def agregar_carrito(id):
    producto = Producto.query.get_or_404(id)

    if "carrito" not in session:
        session["carrito"] = {}

    carrito = session["carrito"]

    if str(id) in carrito:
        carrito[str(id)]["cantidad"] += 1
    else:
        carrito[str(id)] = {
            "id": producto.id_producto,
            "nombre": producto.nom_producto,
            "precio": float(producto.precio_producto),
            "cantidad": 1
        }

    session["carrito"] = carrito
    flash(f"🛒 {producto.nom_producto} agregado al carrito", "success")
    return redirect(url_for("catalogo"))

@app.route("/carrito")
@login_required
def ver_carrito():
    carrito = session.get("carrito", {})
    total = sum(item["precio"] * item["cantidad"] for item in carrito.values())
    return render_template("carrito.html", carrito=carrito, total=total)

@app.route("/carrito/vaciar")
@login_required
def vaciar_carrito():
    session.pop("carrito", None)
    flash("🧹 Carrito vaciado", "info")
    return redirect(url_for("catalogo"))

@app.route("/catalogo/hombre")
def catalogo_hombre():
    productos = Producto.query.filter_by(id_categoria=1).all()
    return render_template("catalogo.html", productos=productos)

@app.route("/catalogo/mujer")
def catalogo_mujer():
    productos = Producto.query.filter_by(id_categoria=2).all()
    return render_template("catalogo.html", productos=productos)

@app.route("/buscar")
def buscar_productos():
    query = request.args.get("q", "")
    if query:
        productos = Producto.query.filter(
            (Producto.nom_producto.like(f"%{query}%")) |
            (Producto.descripcion.like(f"%{query}%"))
        ).all()
    else:
        productos = []

    return render_template("catalogo.html", productos=productos, busqueda=query)

# ------------------- INICIALIZACIÓN -------------------

def init_db():
    """Inicializa la base de datos con datos por defecto"""
    with app.app_context():
        try:
            db.create_all()
            
            # Crear roles por defecto
            if not Rol.query.filter_by(id_rol=1).first():
                rol_admin = Rol(id_rol=1, rol="Administrador")
                db.session.add(rol_admin)
            
            if not Rol.query.filter_by(id_rol=2).first():
                rol_cliente = Rol(id_rol=2, rol="Cliente")
                db.session.add(rol_cliente)
            
            db.session.commit()

            # Crear admin por defecto
            if not Usuario.query.filter_by(email="admin@admin.com").first():
                admin = Usuario(
                    nombre="Admin",
                    apellido="Principal",
                    ciudad="Bogotá",
                    direccion="Calle 123",
                    fecha_nac="1990-01-01",
                    email="admin@admin.com",
                    telefono="123456789",
                    contraseña=generate_password_hash("admin123"),
                    id_rol=1,
                    estado=True
                )
                db.session.add(admin)

            # Crear cliente por defecto
            if not Usuario.query.filter_by(email="cliente@cliente.com").first():
                cliente = Usuario(
                    nombre="Cliente",
                    apellido="Demo",
                    ciudad="Medellín",
                    direccion="Carrera 456",
                    fecha_nac="2000-05-10",
                    email="cliente@cliente.com",
                    telefono="987654321",
                    contraseña=generate_password_hash("cliente123"),
                    id_rol=2,
                    estado=True
                )
                db.session.add(cliente)

            db.session.commit()
            print("✅ Base de datos inicializada correctamente")
        except Exception as e:
            print(f"❌ Error al inicializar la base de datos: {e}")

# NO inicializar DB en producción (Render)
if os.environ.get("FLASK_ENV") == "development":
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)