from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
import sqlalchemy as sa
import sqlalchemy.orm as orm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
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

# Request parsers
user_parser = reqparse.RequestParser()
user_parser.add_argument('name', type=str, required=True, help="Name is required")
user_parser.add_argument('email', type=str, required=True, help="Email is required")
user_parser.add_argument('club', type=str, required=True, help="Club is required")
user_parser.add_argument('password', type=str, required=True, help="Password is required")

login_parser = reqparse.RequestParser()
login_parser.add_argument('email', type=str, required=True, help="Email is required")
login_parser.add_argument('password', type=str, required=True, help="Password is required")

rpl_table_parser = reqparse.RequestParser()
rpl_table_parser.add_argument('position', type=int, required=True, help="Position is required")
rpl_table_parser.add_argument('team', type=str, required=True, help="Team is required")
rpl_table_parser.add_argument('matches', type=int, required=True, help="Matches is required")
rpl_table_parser.add_argument('wins', type=int, required=True, help="Wins is required")
rpl_table_parser.add_argument('draws', type=int, required=True, help="Draws is required")
rpl_table_parser.add_argument('losses', type=int, required=True, help="Losses is required")
rpl_table_parser.add_argument('goals_for', type=int, required=True, help="Goals for is required")
rpl_table_parser.add_argument('goals_against', type=int, required=True, help="Goals against is required")

# Response fields
user_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'email': fields.String,
    'club': fields.String,
    'is_admin': fields.Boolean
}

rpl_table_fields = {
    'id': fields.Integer,
    'position': fields.Integer,
    'team': fields.String,
    'matches': fields.Integer,
    'wins': fields.Integer,
    'draws': fields.Integer,
    'losses': fields.Integer,
    'goals_for': fields.Integer,
    'goals_against': fields.Integer,
    'points': fields.Integer
}


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


# RESTful Resources
class UserResource(Resource):
    @marshal_with(user_fields)
    def get(self, user_id):
        user = db.session.get(User, user_id)
        if not user:
            abort(404, message="User not found")
        return user

    @login_required
    def delete(self, user_id):
        if not current_user.is_admin:
            abort(403, message="Forbidden")

        user_to_delete = db.session.get(User, user_id)
        if not user_to_delete:
            abort(404, message="User not found")

        if user_to_delete.id == current_user.id:
            abort(400, message="Cannot delete yourself")

        db.session.delete(user_to_delete)
        db.session.commit()
        return {'message': 'User deleted successfully'}, 200


class UserListResource(Resource):
    @marshal_with(user_fields)
    def get(self):
        users = db.session.query(User).all()
        return users

    def post(self):
        args = user_parser.parse_args()

        if db.session.query(User).filter_by(email=args['email']).first():
            abort(409, message="Email already exists")

        hashed_password = pw_secure.encrypt_password(args['password'])
        is_admin = (args['email'] == ADMIN_EMAIL)

        user = User(
            name=args['name'],
            email=args['email'],
            club=args['club'],
            password=hashed_password,
            is_admin=is_admin
        )

        db.session.add(user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201


class LoginResource(Resource):
    def post(self):
        args = login_parser.parse_args()
        user = db.session.query(User).filter_by(email=args['email']).first()

        if user and pw_secure.verify_password(user.password, args['password']):
            login_user(user)
            return {'message': 'Logged in successfully'}, 200
        else:
            abort(401, message="Invalid email or password")


class LogoutResource(Resource):
    @login_required
    def post(self):
        logout_user()
        return {'message': 'Logged out successfully'}, 200


class RPLTableResource(Resource):
    @marshal_with(rpl_table_fields)
    def get(self, team_id):
        team = db.session.get(RPLTable, team_id)
        if not team:
            abort(404, message="Team not found")
        return team

    @login_required
    def put(self, team_id):
        if not current_user.is_admin:
            abort(403, message="Forbidden")

        args = rpl_table_parser.parse_args()
        team = db.session.get(RPLTable, team_id)

        if not team:
            abort(404, message="Team not found")

        team.position = args['position']
        team.team = args['team']
        team.matches = args['matches']
        team.wins = args['wins']
        team.draws = args['draws']
        team.losses = args['losses']
        team.goals_for = args['goals_for']
        team.goals_against = args['goals_against']
        team.points = args['wins'] * 3 + args['draws'] * 1

        db.session.commit()
        return {'message': 'Team updated successfully'}, 200

    @login_required
    def delete(self, team_id):
        if not current_user.is_admin:
            abort(403, message="Forbidden")

        team = db.session.get(RPLTable, team_id)
        if not team:
            abort(404, message="Team not found")

        db.session.delete(team)
        db.session.commit()
        return {'message': 'Team deleted successfully'}, 200


class RPLTableListResource(Resource):
    @marshal_with(rpl_table_fields)
    def get(self):
        table = db.session.query(RPLTable).order_by(RPLTable.position).all()
        return table

    @login_required
    def post(self):
        if not current_user.is_admin:
            abort(403, message="Forbidden")

        args = rpl_table_parser.parse_args()

        team = RPLTable(
            position=args['position'],
            team=args['team'],
            matches=args['matches'],
            wins=args['wins'],
            draws=args['draws'],
            losses=args['losses'],
            goals_for=args['goals_for'],
            goals_against=args['goals_against'],
            points=args['wins'] * 3 + args['draws'] * 1
        )

        db.session.add(team)
        db.session.commit()
        return {'message': 'Team created successfully'}, 201


class MoveTeamResource(Resource):
    @login_required
    def post(self, position, direction):
        if not current_user.is_admin:
            abort(403, message="Forbidden")

        if direction == 'up':
            if position <= 1:
                abort(400, message="Cannot move team up from first position")

            team1 = db.session.query(RPLTable).filter_by(position=position).first()
            team2 = db.session.query(RPLTable).filter_by(position=position - 1).first()

            if team1 and team2:
                team1.position, team2.position = team2.position, team1.position
                db.session.commit()
                return {'message': 'Team moved up successfully'}, 200

        elif direction == 'down':
            max_position = db.session.query(sa.func.max(RPLTable.position)).scalar()

            if position >= max_position:
                abort(400, message="Cannot move team down from last position")

            team1 = db.session.query(RPLTable).filter_by(position=position).first()
            team2 = db.session.query(RPLTable).filter_by(position=position + 1).first()

            if team1 and team2:
                team1.position, team2.position = team2.position, team1.position
                db.session.commit()
                return {'message': 'Team moved down successfully'}, 200

        else:
            abort(400, message="Invalid direction. Use 'up' or 'down'")


# Register API resources
api.add_resource(UserListResource, '/api/users')
api.add_resource(UserResource, '/api/users/<int:user_id>')
api.add_resource(LoginResource, '/api/login')
api.add_resource(LogoutResource, '/api/logout')
api.add_resource(RPLTableListResource, '/api/rpl_table')
api.add_resource(RPLTableResource, '/api/rpl_table/<int:team_id>')
api.add_resource(MoveTeamResource, '/api/rpl_table/move/<int:position>/<string:direction>')


# Existing routes
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def home():
    if current_user.is_authenticated:
        table = db.session.query(RPLTable).order_by(RPLTable.position).all()
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


@app.route('/users')
@login_required
def show_users():
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
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
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('home'))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('show_users'))

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
            record = db.session.query(RPLTable).filter_by(position=i + 1).first()
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

    table = db.session.query(RPLTable).order_by(RPLTable.position).all()
    return render_template('edit_rpl_table.html', table=table)


@app.route('/move_up/<int:position>')
@login_required
def move_up(position):
    if not current_user.is_admin:
        flash('Доступ запрещён', 'danger')
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
        flash('Доступ запрещён', 'danger')
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

    app.run(debug=True)
