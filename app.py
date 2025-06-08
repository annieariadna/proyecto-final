from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'una_clave_secreta_segura_aqui'  # Usa una clave secreta segura
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///utp_lost_found.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Configuración de sesión permanente
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)  # Duración de la sesión: 365 días

# Crear directorio de uploads si no existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Modelos de base de datos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='student')  # 'admin' or 'student'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # 'lost' or 'found'
    object_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date_occurred = db.Column(db.Date, nullable=False)
    reporter_name = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(150), nullable=False)
    image_filename = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')  # 'active', 'resolved', 'deleted'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Crear tablas
with app.app_context():
    db.create_all()

    # Crear usuario admin por defecto si no existe
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@utp.edu.pe',
            password_hash=generate_password_hash('admin123'),
            full_name='Administrador del Sistema',
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

# Rutas de autenticación
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])  # Esto permite tanto GET como POST
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['full_name'] = user.full_name
            session.permanent = True  # Hacer que la sesión sea permanente
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))  # Redirigir al dashboard después de iniciar sesión
        else:
            flash('Credenciales inválidas', 'error')  # Mostrar mensaje de error si las credenciales no son correctas
    
    return render_template('login.html')  # Renderizar la página de inicio de sesión si no se envió el formulario


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        # Validar si el código empieza con 'U' o 'C' dependiendo del rol
        if username[0].lower() not in ['u', 'c'] or len(username) < 9:
            flash('El código de usuario no es válido. Debe comenzar con "U" para estudiante o "C" para administrador.', 'error')
            return render_template('register.html')

        role = 'admin' if username[0].lower() == 'c' else 'student'
        
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('El email ya está registrado', 'error')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            full_name=full_name,
            role=role
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registro exitoso. Ahora puedes iniciar sesión', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('login'))

# Rutas principales
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Obtener parámetros de búsqueda
    search_object = request.args.get('object', '')
    search_location = request.args.get('location', '')
    search_date = request.args.get('date', '')
    search_type = request.args.get('type', '')  # Filtro de tipo (perdido o encontrado)
    
    # Construir query de reportes
    query = Report.query.filter_by(status='active')
    
    if search_object:
        query = query.filter(Report.object_name.contains(search_object))
    if search_location:
        query = query.filter(Report.location.contains(search_location))
    if search_date:
        query = query.filter(Report.date_occurred == search_date)
    if search_type:
        query = query.filter(Report.type == search_type)  # Filtro de tipo (perdido o encontrado)
    
    reports = query.order_by(Report.created_at.desc()).all()
    
    return render_template('dashboard.html', reports=reports)

@app.route('/create_report', methods=['POST'])
def create_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Manejar archivo de imagen
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + '_' + filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            image_filename = unique_filename
    
    report = Report(
        type=request.form['type'],
        object_name=request.form['object_name'],
        description=request.form['description'],
        location=request.form['location'],
        date_occurred=datetime.strptime(request.form['date_occurred'], '%Y-%m-%d').date(),
        reporter_name=request.form['reporter_name'],
        contact_info=request.form['contact_info'],
        image_filename=image_filename,
        user_id=session['user_id']
    )
    
    db.session.add(report)
    db.session.commit()
    
    flash('Reporte creado exitosamente', 'success')
    return redirect(url_for('dashboard'))

@app.route('/report/<int:report_id>')
def view_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    report = Report.query.get_or_404(report_id)
    return render_template('report_detail.html', report=report)

@app.route('/delete_report/<int:report_id>')
def delete_report(report_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('No tienes permisos para realizar esta acción', 'error')
        return redirect(url_for('dashboard'))
    
    report = Report.query.get_or_404(report_id)
    report.status = 'deleted'
    db.session.commit()
    
    flash('Reporte eliminado exitosamente', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('No tienes permisos para acceder a esta página', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
