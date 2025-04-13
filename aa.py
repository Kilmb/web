from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

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
    "ЦСКА"
]


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
        password = generate_password_hash(request.form['password'])
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

        if user and check_password_hash(user.password, password):
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
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)