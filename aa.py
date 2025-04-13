from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

ADMIN_EMAIL = 'admin@example.com'

RPL_CLUBS = [
    "Акрон",
    "Ахмат",
    "Динамо Махачкала",
    "Динамо Москва",
    "Зенит",
    "Краснодар",
    "Крылья Советов",
    "Локомотив",
    "Оренбург",
    "Пари НН",
    "Ростов",
    "Рубин",
    "Спартак",
    "Факел",
    "Химки"
    "ЦСКА"
]


class Password_inkognito:
    """
    Класс для шифрования и дешифрования паролей с использованием Fernet.
    Также поддерживает хеширование паролей для дополнительной безопасности.
    """

    def __init__(self):
        # Генерируем ключ шифрования или используем существующий из переменных окружения
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        if not self.encryption_key:
            self.encryption_key = Fernet.generate_key().decode()
            # В реальном приложении следует сохранить этот ключ в безопасное место
        self.cipher_suite = Fernet(self.encryption_key.encode())

    def encrypt_password(self, password):
        """Шифрует пароль и возвращает зашифрованную строку."""
        # Сначала создаем хеш пароля для безопасности
        hashed_pw = generate_password_hash(password)
        # Затем шифруем хеш
        encrypted_pw = self.cipher_suite.encrypt(hashed_pw.encode())
        return encrypted_pw.decode()

    def decrypt_password(self, encrypted_password):
        """Дешифрует пароль и возвращает оригинальный хеш."""
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()

    def verify_password(self, encrypted_password, input_password):
        """
        Проверяет, соответствует ли введенный пароль зашифрованному.
        Возвращает True если соответствует, иначе False.
        """
        try:
            # Дешифруем сохраненный пароль
            hashed_pw = self.decrypt_password(encrypted_password)
            # Проверяем соответствие
            return check_password_hash(hashed_pw, input_password)
        except:
            return False


# Инициализируем наш шифровальщик
pw_secure = Password_inkognito()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    club = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        club = request.form['club']
        password = pw_secure.encrypt_password(request.form['password'])
        is_admin = (email == ADMIN_EMAIL)

        if User.query.filter_by(email=email).first():
            flash('Этот email уже занят!', 'danger')
        else:
            user = User(name=name, email=email, club=club, password=password, is_admin=is_admin)
            db.session.add(user)
            db.session.commit()


            login_user(user)
            flash('Регистрация прошла успешно!', 'success')
            return redirect(url_for('home'))

    return render_template('register.html', clubs=RPL_CLUBS)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and pw_secure.verify_password(user.password, password):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Неверный email или пароль', 'danger')

    return render_template('login.html')


@app.route('/users')
@login_required
def show_users():
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email=ADMIN_EMAIL).first():
            admin = User(
                name='Admin',
                email=ADMIN_EMAIL,
                club='Краснодар',
                password=pw_secure.encrypt_password('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)
