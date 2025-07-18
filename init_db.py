from app import app, db, User
from werkzeug.security import generate_password_hash

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
        print("✔ Usuario admin creado.")
    else:
        print("ℹ El usuario admin ya existe.")

    print("✔ Base de datos inicializada correctamente.")
