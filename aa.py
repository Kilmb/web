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
    "Химки",
    "ЦСКА"
]


class Password_inkognito:
    def encrypt_password(self, password):
        return generate_password_hash(password)

    def verify_password(self, hashed_password, input_password):
        return check_password_hash(hashed_password, input_password)


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


class RPLTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    position = db.Column(db.Integer, nullable=False)
    team = db.Column(db.String(50), nullable=False, unique=True)
    matches = db.Column(db.Integer, default=0)
    wins = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    goals_for = db.Column(db.Integer, default=0)
    goals_against = db.Column(db.Integer, default=0)
    points = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"RPLTable('{self.team}', {self.points})"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    if current_user.is_authenticated:
        table = RPLTable.query.order_by(RPLTable.position).all()
        return render_template('home.html', rpl_table=table)
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        club = request.form['club']
        password = request.form['password']
        hashed_password = pw_secure.encrypt_password(password)
        is_admin = (email == ADMIN_EMAIL)

        if User.query.filter_by(email=email).first():
            flash('Этот email уже занят!', 'danger')
        else:
            user = User(name=name, email=email, club=club, password=hashed_password, is_admin=is_admin)
            db.session.add(user)
            db.session.commit()

            login_user(user)
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


@app.route('/rpl_table')
@login_required
def show_rpl_table():
    table = RPLTable.query.order_by(RPLTable.position).all()
    return render_template('rpl_table.html', table=table)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('home'))

    user_to_delete = User.query.get_or_404(user_id)

    if user_to_delete.id == current_user.id:
        flash('Вы не можете удалить себя', 'danger')
        return redirect(url_for('show_users'))

    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Пользователь успешно удалён', 'success')
    return redirect(url_for('show_users'))


@app.route('/edit_rpl_table', methods=['GET', 'POST'])
@login_required
def edit_rpl_table():
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        teams = request.form.getlist('team[]')
        matches = request.form.getlist('matches[]')
        wins = request.form.getlist('wins[]')
        draws = request.form.getlist('draws[]')
        losses = request.form.getlist('losses[]')
        goals_for = request.form.getlist('goals_for[]')
        goals_against = request.form.getlist('goals_against[]')

        if any(not team.strip() for team in teams):
            flash('Все названия команд должны быть заполнены!', 'danger')
            return redirect(url_for('edit_rpl_table'))

        for i, team in enumerate(teams):
            record = RPLTable.query.filter_by(position=i + 1).first()
            if record:
                record.team = team.strip()
                record.matches = int(matches[i])
                record.wins = int(wins[i])
                record.draws = int(draws[i])
                record.losses = int(losses[i])
                record.goals_for = int(goals_for[i])
                record.goals_against = int(goals_against[i])
                record.points = record.wins * 3 + record.draws * 1

        db.session.commit()
        flash('Таблица успешно обновлена!', 'success')
        return redirect(url_for('show_rpl_table'))

    table = RPLTable.query.order_by(RPLTable.position).all()
    return render_template('edit_rpl_table.html', table=table)


@app.route('/move_up/<int:position>')
@login_required
def move_up(position):
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('home'))

    if position > 1:
        team1 = RPLTable.query.filter_by(position=position).first()
        team2 = RPLTable.query.filter_by(position=position - 1).first()

        if team1 and team2:
            team1.position, team2.position = team2.position, team1.position
            db.session.commit()

    return redirect(url_for('show_rpl_table'))


@app.route('/move_down/<int:position>')
@login_required
def move_down(position):
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('home'))

    max_position = db.session.query(db.func.max(RPLTable.position)).scalar()

    if position < max_position:
        team1 = RPLTable.query.filter_by(position=position).first()
        team2 = RPLTable.query.filter_by(position=position + 1).first()

        if team1 and team2:
            team1.position, team2.position = team2.position, team1.position
            db.session.commit()

    return redirect(url_for('show_rpl_table'))


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

        if RPLTable.query.count() == 0:
            for i, club in enumerate(RPL_CLUBS, 1):
                team = RPLTable(
                    position=i,
                    team=club,
                    matches=0,
                    wins=0,
                    draws=0,
                    losses=0,
                    goals_for=0,
                    goals_against=0,
                    points=0
                )
                db.session.add(team)
            db.session.commit()

    app.run(debug=True)
