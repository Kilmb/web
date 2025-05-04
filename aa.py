from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import sqlalchemy as sa
import sqlalchemy.orm as orm
import os
from datetime import datetime, timedelta


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
migrate = Migrate(app, db)
SqlAlchemyBase = orm.declarative_base()

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


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


class Password_inkognito:
    def encrypt_password(self, password):
        return generate_password_hash(password)

    def verify_password(self, hashed_password, input_password):
        return check_password_hash(hashed_password, input_password)


pw_secure = Password_inkognito()


class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(100), nullable=False)
    email = sa.Column(sa.String(120), unique=True, nullable=False)
    club = sa.Column(sa.String(50), nullable=False)
    password = sa.Column(sa.String(200), nullable=False)
    is_admin = sa.Column(sa.Boolean, default=False)
    avatar = sa.Column(sa.String(200))

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"


class RPLTable(SqlAlchemyBase):
    __tablename__ = 'rpl_table'

    id = sa.Column(sa.Integer, primary_key=True)
    position = sa.Column(sa.Integer, nullable=False)
    team = sa.Column(sa.String(50), nullable=False, unique=True)
    matches = sa.Column(sa.Integer, default=0)
    wins = sa.Column(sa.Integer, default=0)
    draws = sa.Column(sa.Integer, default=0)
    losses = sa.Column(sa.Integer, default=0)
    goals_for = sa.Column(sa.Integer, default=0)
    goals_against = sa.Column(sa.Integer, default=0)
    points = sa.Column(sa.Integer, default=0)

    def __repr__(self):
        return f"RPLTable('{self.team}', {self.points})"


class Match(SqlAlchemyBase):
    __tablename__ = 'matches'

    id = sa.Column(sa.Integer, primary_key=True)
    home_team = sa.Column(sa.String(50), nullable=False)
    away_team = sa.Column(sa.String(50), nullable=False)
    match_date = sa.Column(sa.DateTime, nullable=False)
    home_score = sa.Column(sa.Integer, nullable=True)
    away_score = sa.Column(sa.Integer, nullable=True)
    is_played = sa.Column(sa.Boolean, default=False)
    tour_number = sa.Column(sa.Integer, nullable=False)

    def __repr__(self):
        return f"Match('{self.home_team} vs {self.away_team}', {self.match_date})"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/')
def home():
    if current_user.is_authenticated:
        table = db.session.query(RPLTable).order_by(RPLTable.position).all()
        current_tour = 27  
        tour_matches = db.session.query(Match)\
            .filter(Match.tour_number == current_tour)\
            .order_by(Match.match_date)\
            .all()
        return render_template('home.html', rpl_table=table, tour_matches=tour_matches, current_tour=current_tour)
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

        if db.session.query(User).filter_by(email=email).first():
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
        user = db.session.query(User).filter_by(email=email).first()

        if user and pw_secure.verify_password(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Неверный email или пароль', 'danger')

    return render_template('login.html')


@app.route('/edit_matches')
@login_required
def edit_matches():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    tours = db.session.query(Match.tour_number).distinct().order_by(Match.tour_number).all()
    matches_by_tour = {}
    for tour in tours:
        matches = db.session.query(Match).filter(Match.tour_number == tour[0]).order_by(Match.match_date).all()
        matches_by_tour[tour[0]] = matches

    return render_template('edit_matches.html', matches_by_tour=matches_by_tour, clubs=RPL_CLUBS)


@app.route('/update_match/<int:match_id>', methods=['POST'])
@login_required
def update_match(match_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    match = db.session.get(Match, match_id)
    if not match:
        return redirect(url_for('edit_matches'))

    try:
        match.home_team = request.form['home_team']
        match.away_team = request.form['away_team']
        match.match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
        match.tour_number = int(request.form['tour_number'])

        if request.form['home_score'] and request.form['away_score']:
            match.home_score = int(request.form['home_score'])
            match.away_score = int(request.form['away_score'])
            match.is_played = True
        else:
            match.home_score = None
            match.away_score = None
            match.is_played = False

        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return redirect(url_for('edit_matches'))


@app.route('/add_match', methods=['POST'])
@login_required
def add_match():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    try:
        new_match = Match(
            home_team=request.form['home_team'],
            away_team=request.form['away_team'],
            match_date=datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M'),
            tour_number=int(request.form['tour_number']),
            home_score=None,
            away_score=None,
            is_played=False
        )
        db.session.add(new_match)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return redirect(url_for('edit_matches'))


@app.route('/delete_match/<int:match_id>', methods=['POST'])
@login_required
def delete_match(match_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    match = db.session.get(Match, match_id)
    try:
        db.session.delete(match)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return redirect(url_for('edit_matches'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                file_ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"user_{current_user.id}.{file_ext}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])

                old_avatar = current_user.avatar
                if old_avatar:
                    old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], old_avatar)
                    if os.path.exists(old_avatar_path):
                        try:
                            os.remove(old_avatar_path)
                        except Exception as e:
                            app.logger.error(f"Ошибка при удалении старого аватара: {e}")

                file.save(filepath)
                current_user.avatar = filename
                db.session.commit()
                return redirect(url_for('profile'))

        new_name = request.form.get('name')
        if new_name and new_name != current_user.name:
            current_user.name = new_name
            db.session.commit()
            return redirect(url_for('profile'))

    return render_template('profile.html')


@app.route('/users')
@login_required
def show_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    users = db.session.query(User).all()
    return render_template('users.html', users=users)


@app.route('/rpl_table')
@login_required
def show_rpl_table():
    table = db.session.query(RPLTable).order_by(RPLTable.position).all()
    return render_template('rpl_table.html', table=table)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        return redirect(url_for('show_users'))

    if user_to_delete.id == current_user.id:
        return redirect(url_for('show_users'))

    if user_to_delete.avatar:
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user_to_delete.avatar)
        if os.path.exists(avatar_path):
            try:
                os.remove(avatar_path)
            except Exception as e:
                app.logger.error(f"Ошибка при удалении аватара пользователя: {e}")

    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('show_users'))


@app.route('/edit_rpl_table', methods=['GET', 'POST'])
@login_required
def edit_rpl_table():
    if not current_user.is_admin:
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
            return redirect(url_for('edit_rpl_table'))

        db.session.query(RPLTable).delete()
        db.session.commit()

        for i in range(len(teams)):
            new_record = RPLTable(
                position=i + 1,
                team=teams[i].strip(),
                matches=int(matches[i]),
                wins=int(wins[i]),
                draws=int(draws[i]),
                losses=int(losses[i]),
                goals_for=int(goals_for[i]),
                goals_against=int(goals_against[i]),
                points=int(wins[i]) * 3 + int(draws[i]) * 1
            )
            db.session.add(new_record)

        db.session.commit()
        return redirect(url_for('show_rpl_table'))

    table = db.session.query(RPLTable).order_by(RPLTable.position).all()
    return render_template('edit_rpl_table.html', table=table)


@app.route('/move_up/<int:position>')
@login_required
def move_up(position):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    if position > 1:
        team1 = db.session.query(RPLTable).filter_by(position=position).first()
        team2 = db.session.query(RPLTable).filter_by(position=position - 1).first()

        if team1 and team2:
            team1.position, team2.position = team2.position, team1.position
            db.session.commit()

    return redirect(url_for('show_rpl_table'))


@app.route('/move_down/<int:position>')
@login_required
def move_down(position):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    max_position = db.session.query(sa.func.max(RPLTable.position)).scalar()

    if position < max_position:
        team1 = db.session.query(RPLTable).filter_by(position=position).first()
        team2 = db.session.query(RPLTable).filter_by(position=position + 1).first()

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
        SqlAlchemyBase.metadata.create_all(db.engine)

        if not db.session.query(User).filter_by(email=ADMIN_EMAIL).first():
            admin = User(
                name='Admin',
                email=ADMIN_EMAIL,
                club='Краснодар',
                password=pw_secure.encrypt_password('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

        if db.session.query(RPLTable).count() == 0:
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

        if db.session.query(Match).count() == 0:
            today = datetime.now()
            matches = [
                Match(home_team="Зенит", away_team="Спартак",
                      match_date=today + timedelta(days=1), tour_number=1)
            ]

            for match in matches:
                db.session.add(match)
            db.session.commit()

    app.run(debug=True)
