from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import requests
import csv
from io import StringIO
import threading
import time

# Инициализация Flask-приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Создание папки для загрузок, если её нет
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
migrate = Migrate(app, db)
TOUR_CONFIG_PATH = Path(__file__).parent / 'current_tour.json'  # Путь к файлу с текущим туром

login_manager = LoginManager(app)
login_manager.login_view = 'login'

ADMIN_EMAIL = 'admin@example.com'

RPL_CLUBS = [
    "Акрон",
    "Ахмат",
    "Балтика",
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
    "Сочи",
    "Спартак",
    "ЦСКА"
]


def main():
    # Основная функция инициализации приложения
    app.run()


def allowed_file(filename):
    # Проверка расширения файла
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


class Password_inkognito:
    # Класс для хэширования и проверки паролей
    def encrypt_password(self, password):
        return generate_password_hash(password)

    def verify_password(self, hashed_password, input_password):
        return check_password_hash(hashed_password, input_password)


pw_secure = Password_inkognito()


class UserTheme(db.Model):
    __tablename__ = 'user_themes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    theme_name = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    purchased_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref='user_themes')


# Список доступных тем
AVAILABLE_THEMES = {
    'light': {'name': 'Светлая', 'price': 0, 'description': 'Стандартная светлая тема'},
    'dark': {'name': 'Темная', 'price': 0, 'description': 'Темная тема для комфортного использования ночью'},
    'blue': {'name': 'Синяя', 'price': 15, 'description': 'Элегантная синяя тема'},
    'green': {'name': 'Зеленая', 'price': 20, 'description': 'Спокойная зеленая тема'},
    'red': {'name': 'Красная', 'price': 25, 'description': 'Энергичная красная тема'},
    'purple': {'name': 'Фиолетовая', 'price': 30, 'description': 'Мистическая фиолетовая тема'},
    'gold': {'name': 'Золотая', 'price': 40, 'description': 'Премиум золотая тема'},
    'rpl': {'name': 'РПЛ', 'price': 50, 'description': 'Официальная тема Российской Премьер-Лиги'}
}


class UserBalance(db.Model):
    __tablename__ = 'user_balances'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    balance = db.Column(db.Integer, default=100)

    user = db.relationship('User', backref=db.backref('balance_record', uselist=False))


class Bet(db.Model):
    __tablename__ = 'bets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    match_id = db.Column(db.Integer, db.ForeignKey('matches.id', ondelete='CASCADE'))
    bet_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_settled = db.Column(db.Boolean, default=False)
    won = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='user_bets')
    match = db.relationship('Match', backref='match_bets')

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    club = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))
    about = db.Column(db.String(250))

class RPLTable(db.Model):
    __tablename__ = 'rpl_table'

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


class Match(db.Model):
    __tablename__ = 'matches'

    id = db.Column(db.Integer, primary_key=True)
    home_team = db.Column(db.String(50), nullable=False)
    away_team = db.Column(db.String(50), nullable=False)
    match_date = db.Column(db.DateTime, nullable=False)
    home_score = db.Column(db.Integer, nullable=True)
    away_score = db.Column(db.Integer, nullable=True)
    is_played = db.Column(db.Boolean, default=False)
    tour_number = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"Match('{self.home_team} vs {self.away_team}', {self.match_date})"


class ClubTest(db.Model):
    __tablename__ = 'club_tests'

    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    correct_answer = db.Column(db.String(200), nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=False)
    option4 = db.Column(db.String(200), nullable=False)
    difficulty = db.Column(db.Integer, default=1)


class TestResult(db.Model):
    __tablename__ = 'test_results'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    test_type = db.Column(db.String(10))
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User')

def get_current_tour_from_api():
    """
    Автоматически определяет текущий тур на основе API матчей
    """
    try:
        # Получаем все матчи сезона
        url = "https://api.sstats.net/games/list?"
        params = {
            'leagueId': 235,
            'year': 2025,
            'format': 'json',
            'limit': 300
        }

        headers = {'apikey': '8ftkpzresyxo7dqz'}

        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        matches_data = data['data']

        if not matches_data:
            return 1

        # Простой подход: считаем что текущий тур = (количество завершенных матчей // 8) + 1
        completed_matches = [m for m in matches_data if m.get('status') == 8]
        current_tour = (len(completed_matches) // 8) + 1

        return min(current_tour, 30)

    except Exception as e:
        print(f"Ошибка при определении текущего тура: {e}")
        return load_current_tour_from_file()


def load_current_tour_from_file():
    try:
        if TOUR_CONFIG_PATH.exists():
            with open(TOUR_CONFIG_PATH, 'r') as f:
                return json.load(f).get('current_tour', 1)
    except Exception:
        pass
    return 1


def save_current_tour(tour_number):
    try:
        with open(TOUR_CONFIG_PATH, 'w') as f:
            json.dump({'current_tour': tour_number}, f)
    except Exception as e:
        print(f"Ошибка при сохранении текущего тура: {e}")


def load_current_tour():
    try:
        current_tour = get_current_tour_from_api()

        save_current_tour(current_tour)

        print(f"Текущий тур автоматически определен: {current_tour}")
        return current_tour

    except Exception as e:
        print(f"Ошибка при автоматическом определении тура: {e}")
        return load_current_tour_from_file()


def schedule_tour_update():
    def update_job():
        while True:
            try:
                # Обновляем каждые 6 часов
                time.sleep(6 * 60 * 60)

                with app.app_context():
                    current_tour = get_current_tour_from_api()
                    save_current_tour(current_tour)
                    print(f"Автоматически обновлен текущий тур: {current_tour}")

            except Exception as e:
                print(f"Ошибка в фоновом обновлении тура: {e}")

    thread = threading.Thread(target=update_job, daemon=True)
    thread.start()


def update_rpl_table_from_sstats():
    try:
        url = "https://api.sstats.net/games/season-table"
        params = {
            'league': 235,
            'year': 2025,
            'format': 'csv',
            'fields': 'Rank,TeamName,Wins,Draws,Loss,GoalsScored,GoalsMissed,Points',
            'orderField': 'Rank'
        }

        headers = {'apikey': '8ftkpzresyxo7dqz'}

        response = requests.get(url, params=params, headers=headers, timeout=30)

        response.raise_for_status()

        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)

        rows = list(reader)
        db.session.query(RPLTable).delete()
        teams_added = 0

        def map_team_name(api_name):
            mapping = {
                "CSKA Moscow": "ЦСКА",
                "FC Krasnodar": "Краснодар",
                "Lokomotiv": "Локомотив",
                "Zenit": "Зенит",
                "Baltika": "Балтика",
                "Spartak Moscow": "Спартак",
                "Rubin": "Рубин",
                "Dynamo": "Динамо Москва",
                "Akhmat": "Ахмат",
                "FC Rostov": "Ростов",
                "Krylia Sovetov": "Крылья Советов",
                "Dinamo Makhachkala": "Динамо Махачкала",
                "Akron": "Акрон",
                "FC Orenburg": "Оренбург",
                "Nizhny Novgorod": "Пари НН",
                "FC Sochi": "Сочи"
            }
            return mapping.get(api_name, api_name)

        for i, row in enumerate(rows):
            try:
                team_name_key = None
                rank_key = None
                wins_key = None
                draws_key = None
                loss_key = None
                goals_scored_key = None
                goals_missed_key = None
                points_key = None

                for key in row.keys():
                    key_lower = key.lower()
                    if 'team' in key_lower:
                        team_name_key = key
                    elif 'rank' in key_lower:
                        rank_key = key
                    elif 'win' in key_lower:
                        wins_key = key
                    elif 'draw' in key_lower:
                        draws_key = key
                    elif 'loss' in key_lower:
                        loss_key = key
                    elif 'score' in key_lower:
                        goals_scored_key = key
                    elif 'goals' in key_lower:
                        goals_missed_key = key
                    elif 'point' in key_lower:
                        points_key = key
                # Преобразуем название команды
                team_name = map_team_name(row[team_name_key])

                position = int(row[rank_key]) if rank_key and row[rank_key] else i + 1
                wins = int(row[wins_key]) if wins_key and row[wins_key] else 0
                draws = int(row[draws_key]) if draws_key and row[draws_key] else 0
                losses = int(row[loss_key]) if loss_key and row[loss_key] else 0
                goals_scored = int(row[goals_scored_key]) if goals_scored_key and row[goals_scored_key] else 0
                goals_missed = int(row[goals_missed_key]) if goals_missed_key and row[goals_missed_key] else 0
                points = int(row[points_key]) if points_key and row[points_key] else 0

                matches = wins + draws + losses

                team = RPLTable(
                    position=position,
                    team=team_name,
                    matches=matches,
                    wins=wins,
                    draws=draws,
                    losses=losses,
                    goals_for=goals_scored,
                    goals_against=goals_missed,
                    points=points
                )

                db.session.add(team)
                teams_added += 1

            except Exception as e:
                print(f"Ошибка при обработке строки {i + 1}: {e}")
                print(f"Данные строки: {row}")
                continue

        db.session.commit()
        teams_in_db = db.session.query(RPLTable).order_by(RPLTable.position).all()
        for team in teams_in_db:
            print(f"{team.position}. {team.team} - {team.points} очков")

        return True, f"Добавлено {teams_added} команд"

    except requests.exceptions.HTTPError as e:
        print(f"HTTP ошибка: {e}")
        print(f"URL: {e.response.url}")
        print(f"Статус: {e.response.status_code}")
        print(f"Ответ: {e.response.text}")
        return False, f"Ошибка API: {e.response.status_code}"
    except Exception as e:
        print(f"Общая ошибка: {e}")
        db.session.rollback()
        return False, f"Ошибка при обновлении таблицы: {e}"


def update_matches_from_sstats():
    try:
        current_tour = load_current_tour()

        offset = (current_tour - 1) * 8

        url = "https://api.sstats.net/games/list?"
        params = {
            'leagueId': 235,
            'year': 2025,
            'format': 'json',
            'offset': offset,
            'limit': 8
        }

        headers = {'apikey': '8ftkpzresyxo7dqz'}

        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()

        matches_data = data['data']
        matches_added = 0
        matches_updated = 0

        def map_team_name(api_name):
            mapping = {
                "CSKA Moscow": "ЦСКА",
                "FC Krasnodar": "Краснодар",
                "Lokomotiv": "Локомотив",
                "Zenit": "Зенит",
                "Baltika": "Балтика",
                "Spartak Moscow": "Спартак",
                "Rubin": "Рубин",
                "Dynamo": "Динамо Москва",
                "Akhmat": "Ахмат",
                "FC Rostov": "Ростов",
                "Krylia Sovetov": "Крылья Советов",
                "Dinamo Makhachkala": "Динамо Махачкала",
                "Akron": "Акрон",
                "FC Orenburg": "Оренбург",
                "Nizhny Novgorod": "Пари НН",
                "FC Sochi": "Сочи"
            }
            return mapping.get(api_name, api_name)

        for match_data in matches_data:
            try:
                home_team_api = match_data['homeTeam']['name']
                away_team_api = match_data['awayTeam']['name']

                home_team = map_team_name(home_team_api)
                away_team = map_team_name(away_team_api)

                match_date_str = match_data['date']
                match_date_utc = datetime.fromisoformat(match_date_str.replace('Z', '+00:00'))
                match_date_msk = match_date_utc.replace(tzinfo=None) + timedelta(hours=3)
                tour_number = current_tour

                home_score = match_data.get('homeResult')
                away_score = match_data.get('awayResult')

                is_played = match_data.get('status') == 8

                existing_match = db.session.query(Match).filter(
                    Match.home_team == home_team,
                    Match.away_team == away_team,
                    Match.match_date == match_date_msk
                ).first()

                if existing_match:
                    existing_match.home_score = home_score if is_played else None
                    existing_match.away_score = away_score if is_played else None
                    existing_match.is_played = is_played
                    existing_match.tour_number = tour_number
                    matches_updated += 1
                else:
                    new_match = Match(
                        home_team=home_team,
                        away_team=away_team,
                        match_date=match_date_msk,
                        home_score=home_score if is_played else None,
                        away_score=away_score if is_played else None,
                        is_played=is_played,
                        tour_number=tour_number
                    )
                    db.session.add(new_match)
                    matches_added += 1

            except Exception as e:
                print(f"Ошибка при обработке матча {home_team_api} vs {away_team_api}: {e}")
                continue

        db.session.commit()

        print(
            f" тур {current_tour}. Добавлено: {matches_added}, Обновлено: {matches_updated}")

        return True, f"тур {current_tour}. Добавлено: {matches_added}, Обновлено: {matches_updated}"

    except requests.exceptions.HTTPError as e:
        print(f"HTTP ошибка: {e}")
        return False, f"Ошибка API: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        print(f"Ошибка подключения: {e}")
        return False, f"Ошибка подключения: {e}"
    except Exception as e:
        print(f"Общая ошибка: {e}")
        db.session.rollback()
        return False, f"Ошибка при обновлении матчей: {e}"


# Загружает пользователя
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.context_processor
def inject_theme():
    if current_user.is_authenticated:
        active_theme = UserTheme.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).first()
        theme_name = active_theme.theme_name if active_theme else 'light'
    else:
        theme_name = 'light'

    return {'current_theme': theme_name}


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.context_processor
def inject_current_tour():
    return {'current_tour': load_current_tour()}


# Главная страница
@app.route('/')
def home():
    table = db.session.query(RPLTable).order_by(RPLTable.position).all()
    current_tour = load_current_tour()

    # Получаем матчи для предыдущего, текущего и следующего туров
    prev_tour_matches = db.session.query(Match).filter(Match.tour_number == current_tour - 1) \
        .order_by(Match.match_date).all() if current_tour > 1 else []

    current_tour_matches = db.session.query(Match).filter(Match.tour_number == current_tour) \
        .order_by(Match.match_date).all()

    next_tour_matches = db.session.query(Match).filter(Match.tour_number == current_tour + 1) \
        .order_by(Match.match_date).all()

    if current_user.is_authenticated:
        return render_template('home.html',
                               rpl_table=table,
                               current_tour_matches=current_tour_matches,
                               prev_tour_matches=prev_tour_matches,
                               next_tour_matches=next_tour_matches,
                               current_tour=current_tour)
    return render_template('home.html',
                           rpl_table=table,
                           current_tour_matches=current_tour_matches,
                           prev_tour_matches=prev_tour_matches,
                           next_tour_matches=next_tour_matches,
                           current_tour=current_tour,
                           show_public_content=True)


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    # GET: Отображает форму регистрации
    # POST: Обрабатывает данные формы, создает пользователя
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


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    # GET: Показывает форму входа
    # POST: Проверяет учетные данные и авторизует пользователя
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


# Тесты только для пользователей
@app.route('/club_tests')
@login_required
def club_tests():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    tests = db.session.query(ClubTest).order_by(ClubTest.id).all()
    return render_template('club_tests.html', tests=tests, clubs=RPL_CLUBS)


# Удаление тестов
@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    test = db.session.get(ClubTest, test_id)
    db.session.delete(test)
    db.session.commit()
    return redirect(url_for('club_tests'))


@app.route('/easy_quiz')
@login_required
def easy_quiz():
    tests = db.session.query(ClubTest).filter(ClubTest.difficulty == 1).order_by(ClubTest.id).limit(10).all()

    if not tests:
        return redirect(url_for('home'))

    return render_template('quiz.html',
                           tests=tests,
                           test_type='easy',
                           title='Лёгкий тест')


@app.route('/medium_quiz')
@login_required
def medium_quiz():
    tests = db.session.query(ClubTest).filter(ClubTest.difficulty == 2).order_by(ClubTest.id).limit(10).all()

    if not tests:
        return redirect(url_for('home'))

    return render_template('quiz.html',
                           tests=tests,
                           test_type='medium',
                           title='Средний тест')


@app.route('/hard_quiz')
@login_required
def hard_quiz():
    tests = db.session.query(ClubTest).filter(ClubTest.difficulty == 3).order_by(ClubTest.id).limit(10).all()

    if not tests:
        return redirect(url_for('home'))

    return render_template('quiz.html',
                           tests=tests,
                           test_type='hard',
                           title='Сложный тест')


# Проверка результатов
@app.route('/check_quiz/<test_type>', methods=['POST'])
@login_required
def check_quiz(test_type):
    score = 0
    results = []
    difficulty_filter = {
        'easy': (1, 1),
        'medium': (2, 2),
        'hard': (3, 3)
    }.get(test_type, (1, 3))

    for question_id, user_answer in request.form.items():
        if question_id.startswith('q_'):
            test = db.session.get(ClubTest, question_id[2:])
            if test and difficulty_filter[0] <= test.difficulty <= difficulty_filter[1]:
                is_correct = (user_answer == test.correct_answer)
                score += 1 if is_correct else 0
                results.append({
                    'question': test.question,
                    'user_answer': user_answer,
                    'correct_answer': test.correct_answer,
                    'is_correct': is_correct,
                    'difficulty': test.difficulty
                })

    result = TestResult(
        user_id=current_user.id,
        test_type=test_type,
        score=score,
        total=len(results),
        date=datetime.now()
    )
    db.session.add(result)
    db.session.commit()

    return render_template('quiz_results.html',
                           score=score,
                           total=len(results),
                           results=results,
                           test_type=test_type)


@app.route('/add_test', methods=['POST'])
@login_required
def add_test():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    options = [
        request.form['option1'],
        request.form['option2'],
        request.form['option3'],
        request.form['option4']
    ]

    new_test = ClubTest(
        question=request.form['question'],
        correct_answer=request.form['correct_answer'],
        option1=options[0],
        option2=options[1],
        option3=options[2],
        option4=options[3],
        difficulty=int(request.form['difficulty'])
    )
    db.session.add(new_test)
    db.session.commit()
    return redirect(url_for('club_tests'))


@app.route('/edit_test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def edit_test(test_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    test = db.session.get(ClubTest, test_id)
    if not test:
        return redirect(url_for('club_tests'))

    if request.method == 'POST':
        options = [
            request.form['option1'],
            request.form['option2'],
            request.form['option3'],
            request.form['option4']
        ]

        test.question = request.form['question']
        test.correct_answer = request.form['correct_answer']
        test.option1 = options[0]
        test.option2 = options[1]
        test.option3 = options[2]
        test.option4 = options[3]
        test.difficulty = int(request.form['difficulty'])

        db.session.commit()
        return redirect(url_for('club_tests'))

    return render_template('edit_test.html', test=test)


@app.route('/restore_table', methods=['POST'])
@login_required
def restore_table():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    db.session.query(RPLTable).delete()

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

    return redirect(url_for('edit_rpl_table'))


# Изменение матчей
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

    return render_template('edit_matches.html', matches_by_tour=matches_by_tour, clubs=RPL_CLUBS,
                           current_tour=load_current_tour())


@app.route('/update_match/<int:match_id>', methods=['POST'])
@login_required
def update_match(match_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    match = db.session.get(Match, match_id)

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


# Обновление таблицы из API
@app.route('/update_table_from_api', methods=['POST'])
@login_required
def update_table_from_api():
    try:
        # Обновляем турнирную таблицу
        success_table, message_table = update_rpl_table_from_sstats()

        # Обновляем матчи текущего тура
        current_tour = load_current_tour()
        success_current, message_current = update_matches_for_tour(current_tour)

        # Обновляем матчи следующего тура
        next_tour = current_tour + 1
        success_next, message_next = update_matches_for_tour(next_tour)

        prev_tour = current_tour - 1
        success_prev, message_prev = update_matches_for_tour(prev_tour)
        # Формируем общее сообщение
        messages = []
        if success_table:
            messages.append(message_table)

        if success_current:
            messages.append(f"Текущий тур: {message_current}")

        if success_next:
            messages.append(f"Следующий тур: {message_next}")

        if success_prev:
            messages.append(f"Следующий тур: {message_prev}")

        if messages:
            flash(" | ".join(messages), 'success')
        else:
            flash("Не удалось обновить данные", 'warning')

    except Exception as e:
        flash(f"Ошибка при обновлении данных: {e}", 'danger')

    return redirect(url_for('home'))

def update_matches_for_tour(tour_number):
    """
    Обновляет матчи для указанного тура
    """
    try:
        offset = (tour_number - 1) * 8

        url = "https://api.sstats.net/games/list?"
        params = {
            'leagueId': 235,
            'year': 2025,
            'format': 'json',
            'offset': offset,
            'limit': 8
        }

        headers = {'apikey': '8ftkpzresyxo7dqz'}

        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        matches_data = data['data']

        if not matches_data:
            return False, f"Нет данных для тура {tour_number}"

        matches_added = 0
        matches_updated = 0
        settled_bets_count = 0

        def map_team_name(api_name):
            mapping = {
                "CSKA Moscow": "ЦСКА",
                "FC Krasnodar": "Краснодар",
                "Lokomotiv": "Локомотив",
                "Zenit": "Зенит",
                "Baltika": "Балтика",
                "Spartak Moscow": "Спартак",
                "Rubin": "Рубин",
                "Dynamo": "Динамо Москва",
                "Akhmat": "Ахмат",
                "FC Rostov": "Ростов",
                "Krylia Sovetov": "Крылья Советов",
                "Dinamo Makhachkala": "Динамо Махачкала",
                "Akron": "Акрон",
                "FC Orenburg": "Оренбург",
                "Nizhny Novgorod": "Пари НН",
                "FC Sochi": "Сочи"
            }
            return mapping.get(api_name, api_name)

        for match_data in matches_data:
            try:
                home_team_api = match_data['homeTeam']['name']
                away_team_api = match_data['awayTeam']['name']

                home_team = map_team_name(home_team_api)
                away_team = map_team_name(away_team_api)

                match_date_str = match_data['date']
                match_date_utc = datetime.fromisoformat(match_date_str.replace('Z', '+00:00'))
                match_date_msk = match_date_utc.replace(tzinfo=None) + timedelta(hours=3)
                home_score = match_data.get('homeResult')
                away_score = match_data.get('awayResult')
                is_played = match_data.get('status') == 8

                # Ищем существующий матч
                existing_match = db.session.query(Match).filter(
                    Match.home_team == home_team,
                    Match.away_team == away_team,
                    Match.tour_number == tour_number
                ).first()

                if existing_match:
                    # Сохраняем предыдущее состояние матча для проверки ставок
                    was_played_before = existing_match.is_played

                    existing_match.home_score = home_score if is_played else None
                    existing_match.away_score = away_score if is_played else None
                    existing_match.is_played = is_played
                    existing_match.match_date = match_date_msk
                    matches_updated += 1

                    # Если матч завершен и ранее не был сыгран, рассчитываем ставки
                    if is_played and not was_played_before:
                        settle_bets(existing_match.id)
                        settled_bets_count += 1

                else:
                    new_match = Match(
                        home_team=home_team,
                        away_team=away_team,
                        match_date=match_date_msk,
                        home_score=home_score if is_played else None,
                        away_score=away_score if is_played else None,
                        is_played=is_played,
                        tour_number=tour_number
                    )
                    db.session.add(new_match)
                    matches_added += 1

            except Exception as e:
                print(f"Ошибка при обработке матча {home_team_api} vs {away_team_api}: {e}")
                continue

        db.session.commit()

        message = f"добавлено {matches_added}, обновлено {matches_updated}"
        if settled_bets_count > 0:
            message += f", рассчитано ставок: {settled_bets_count}"
        return True, message

    except Exception as e:
        print(f"Ошибка при обновлении матчей тура {tour_number}: {e}")
        db.session.rollback()
        return False, f"ошибка API"

@app.route('/update_matches_from_api', methods=['POST'])
@login_required
def update_matches_from_api():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    try:
        success, message = update_matches_from_sstats()
        if success:
            flash(f"Матчи обновлены: {message}", 'success')
        else:
            flash(f"Ошибка при обновлении матчей: {message}", 'danger')
    except Exception as e:
        flash(f"Ошибка: {e}", 'danger')

    return redirect(url_for('edit_matches'))

# Изменение матчей

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
    db.session.delete(match)
    db.session.commit()

    return redirect(url_for('edit_matches'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Загрузка аватара
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

        # Обработка смены темы
        if 'theme' in request.form:
            theme_name = request.form['theme']
            if theme_name in AVAILABLE_THEMES:
                # Проверяем, есть ли уже эта тема у пользователя
                user_theme = UserTheme.query.filter_by(
                    user_id=current_user.id,
                    theme_name=theme_name
                ).first()

                if not user_theme:
                    # Покупка новой темы
                    theme_price = AVAILABLE_THEMES[theme_name]['price']
                    user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()

                    if not user_balance:
                        user_balance = UserBalance(user_id=current_user.id, balance=100)
                        db.session.add(user_balance)

                    if user_balance.balance >= theme_price:
                        # Списание средств
                        user_balance.balance -= theme_price

                        # Добавление темы
                        new_theme = UserTheme(
                            user_id=current_user.id,
                            theme_name=theme_name,
                            is_active=False
                        )
                        db.session.add(new_theme)
                        db.session.commit()
                        flash(f'Тема "{AVAILABLE_THEMES[theme_name]["name"]}" успешно приобретена!', 'success')
                    else:
                        flash('Недостаточно средств для покупки темы', 'danger')
                        return redirect(url_for('profile'))

                # Активация темы
                UserTheme.query.filter_by(user_id=current_user.id).update({'is_active': False})
                user_theme = UserTheme.query.filter_by(
                    user_id=current_user.id,
                    theme_name=theme_name
                ).first()
                user_theme.is_active = True
                db.session.commit()

                flash(f'Тема "{AVAILABLE_THEMES[theme_name]["name"]}" активирована!', 'success')
                return redirect(url_for('profile'))

        # Сохранение нового имени и информации о себе
        new_name = request.form.get('name')
        about_text = request.form.get('about', '')[:250]

        if new_name and new_name != current_user.name:
            current_user.name = new_name
        current_user.about = about_text
        db.session.commit()
        return redirect(url_for('profile'))

    # Получаем текущую активную тему пользователя
    active_theme = UserTheme.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).first()

    # Получаем все темы пользователя
    user_themes = UserTheme.query.filter_by(user_id=current_user.id).all()
    owned_themes = {theme.theme_name for theme in user_themes}

    # Добавляем бесплатные темы
    owned_themes.add('light')
    owned_themes.add('dark')

    # Получаем баланс
    user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()
    balance = user_balance.balance if user_balance else 100

    return render_template('profile.html',
                         themes=AVAILABLE_THEMES,
                         owned_themes=owned_themes,
                         active_theme=active_theme.theme_name if active_theme else 'light',
                         balance=balance)


# Просмотр пользователей
@app.route('/users')
@login_required
def show_users():
    try:
        print("DEBUG: Начало функции show_users")

        # Простой запрос пользователей
        users = User.query.all()
        print(f"DEBUG: Найдено пользователей: {len(users)}")

        # Создаем словарь балансов
        user_balances = {}
        try:
            balances = UserBalance.query.all()
            print(f"DEBUG: Найдено балансов: {len(balances)}")
            for balance in balances:
                user_balances[balance.user_id] = balance.balance
                print(f"DEBUG: Баланс для user_id {balance.user_id}: {balance.balance}")
        except Exception as e:
            print(f"DEBUG: Ошибка при запросе балансов: {e}")
            # Если есть ошибка, используем значения по умолчанию
            for user in users:
                user_balances[user.id] = 100

        print("DEBUG: Рендеринг шаблона")
        return render_template('users.html', users=users, user_balances=user_balances)

    except Exception as e:
        print(f"ERROR: Критическая ошибка в show_users: {e}")
        import traceback
        traceback.print_exc()
        flash('Произошла ошибка при загрузке списка пользователей', 'danger')
        return redirect(url_for('home'))


# Просмотр профилей
@app.route('/user/<int:user_id>')
@login_required
def view_user(user_id):
    try:
        print(f"DEBUG: Загрузка профиля пользователя {user_id}")

        # Используем db.session.get вместо User.query.get
        user = db.session.get(User, user_id)
        if not user:
            print(f"DEBUG: Пользователь {user_id} не найден")
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('show_users'))

        print(f"DEBUG: Найден пользователь: {user.name}")

        # Получаем баланс пользователя
        user_balance_obj = UserBalance.query.filter_by(user_id=user_id).first()
        print(f"DEBUG: Баланс объекта: {user_balance_obj}")

        if user_balance_obj:
            user_balance = user_balance_obj.balance
            print(f"DEBUG: Баланс из БД: {user_balance}")
        else:
            # Создаем баланс, если его нет
            user_balance = 100
            new_balance = UserBalance(user_id=user_id, balance=100)
            db.session.add(new_balance)
            db.session.commit()
            print("DEBUG: Создан новый баланс: 100")

        return render_template('user_profile.html', user=user, user_balance=user_balance)

    except Exception as e:
        print(f"ERROR: Ошибка в view_user: {e}")
        import traceback
        traceback.print_exc()
        flash('Произошла ошибка при загрузке профиля', 'danger')
        return redirect(url_for('show_users'))

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
        return redirect(url_for('home'))

    table = db.session.query(RPLTable).order_by(RPLTable.position).all()
    return render_template('edit_rpl_table.html', table=table)


@app.route('/place_bet/<int:match_id>', methods=['POST'])
@login_required
def place_bet(match_id):
    try:
        print(f"DEBUG: Размещение ставки для матча {match_id} пользователем {current_user.id}")

        match = db.session.get(Match, match_id)
        if not match:
            flash('Матч не найден', 'danger')
            return redirect(url_for('home'))

        if match.is_played:
            flash('Нельзя делать ставки на завершенные матчи', 'danger')
            return redirect(url_for('home'))

        bet_type = request.form.get('bet_type')
        amount = int(request.form.get('amount', 0))

        # Проверяем валидность ставки
        if bet_type not in ['home_win', 'draw', 'away_win']:
            flash('Неверный тип ставки', 'danger')
            return redirect(url_for('home'))

        if amount <= 0:
            flash('Сумма ставки должна быть положительной', 'danger')
            return redirect(url_for('home'))

        # Проверяем баланс пользователя
        user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()
        if not user_balance:
            user_balance = UserBalance(user_id=current_user.id, balance=100)
            db.session.add(user_balance)
            db.session.commit()

        if user_balance.balance < amount:
            flash('Недостаточно средств для ставки', 'danger')
            return redirect(url_for('home'))

        # Проверяем, не делал ли пользователь уже ставку на этот матч
        existing_bet = Bet.query.filter_by(user_id=current_user.id, match_id=match_id).first()
        if existing_bet:
            flash('Вы уже сделали ставку на этот матч', 'danger')
            return redirect(url_for('home'))

        # Создаем ставку и списываем средства
        new_bet = Bet(
            user_id=current_user.id,
            match_id=match_id,
            bet_type=bet_type,
            amount=amount
        )

        user_balance.balance -= amount

        db.session.add(new_bet)
        db.session.commit()

        print(f"DEBUG: Ставка создана успешно: {new_bet.id}")
        flash(f'Ставка на {amount} монет успешно размещена!', 'success')
        return redirect(url_for('home'))

    except Exception as e:
        print(f"ERROR: Ошибка при размещении ставки: {e}")
        db.session.rollback()
        flash(f'Ошибка при размещении ставки: {e}', 'danger')
        return redirect(url_for('home'))


@app.route('/my_bets')
@login_required
def my_bets():
    try:
        # Получаем или создаем баланс пользователя
        user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()
        if not user_balance:
            user_balance = UserBalance(user_id=current_user.id, balance=100)
            db.session.add(user_balance)
            db.session.commit()
            balance_amount = 100
        else:
            balance_amount = user_balance.balance

        # Получаем все ставки пользователя
        bets = Bet.query.filter_by(user_id=current_user.id).order_by(Bet.created_at.desc()).all()

        # Собираем данные о матчах для каждой ставки
        bets_data = []
        for bet in bets:
            match = Match.query.get(bet.match_id)
            if match:  # Проверяем, что матч существует
                bets_data.append({
                    'bet': bet,
                    'match': match
                })

        return render_template('my_bets.html',
                               bets_data=bets_data,
                               balance=balance_amount)

    except Exception as e:
        print(f"Ошибка в my_bets: {e}")
        # Возвращаем простую страницу с ошибкой
        return render_template('my_bets.html',
                               bets_data=[],
                               balance=100,
                               error="Произошла ошибка при загрузке ставок")

@app.route('/edit_match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def edit_match(match_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    match = db.session.get(Match, match_id)
    if not match:
        flash('Матч не найден', 'danger')
        return redirect(url_for('edit_matches'))

    if request.method == 'POST':
        try:
            # Сохраняем предыдущее состояние для проверки ставок
            was_played_before = match.is_played

            # Обновляем данные матча
            match.home_team = request.form['home_team']
            match.away_team = request.form['away_team']
            match.match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
            match.tour_number = int(request.form['tour_number'])

            # Обрабатываем счет матча
            home_score = request.form.get('home_score', '').strip()
            away_score = request.form.get('away_score', '').strip()

            if home_score and away_score:
                match.home_score = int(home_score)
                match.away_score = int(away_score)
                match.is_played = True

                # Автоматически рассчитываем ставки при установке счета
                if not was_played_before:
                    settle_bets(match.id)
                    flash('Счет установлен и ставки рассчитаны', 'success')
            else:
                match.home_score = None
                match.away_score = None
                match.is_played = False

            db.session.commit()
            flash('Матч успешно обновлен', 'success')
            return redirect(url_for('edit_matches'))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении матча: {e}', 'danger')

    return render_template('edit_match.html', match=match, clubs=RPL_CLUBS)



# Функция для расчета результатов ставок
def settle_bets(match_id):
    match = db.session.get(Match, match_id)
    if not match or not match.is_played:
        return

    # Определяем результат матча
    if match.home_score is None or match.away_score is None:
        return

    if match.home_score > match.away_score:
        actual_result = 'home_win'
    elif match.home_score == match.away_score:
        actual_result = 'draw'
    else:
        actual_result = 'away_win'

    # Находим все ставки на этот матч
    bets = Bet.query.filter_by(match_id=match_id, is_settled=False).all()

    print(f"Рассчитываем ставки для матча {match.home_team} vs {match.away_team}")
    print(f"Результат: {match.home_score}:{match.away_score}, тип: {actual_result}")
    print(f"Найдено ставок для расчета: {len(bets)}")

    for bet in bets:
        bet.is_settled = True

        if bet.bet_type == actual_result:
            # Ставка выиграла - удваиваем сумму
            user_balance = UserBalance.query.filter_by(user_id=bet.user_id).first()
            if user_balance:
                user_balance.balance += bet.amount * 2
                bet.won = True
                print(f"Ставка пользователя {bet.user_id} выиграла: +{bet.amount * 2} монет")
            else:
                print(f"Ошибка: не найден баланс пользователя {bet.user_id}")
        else:
            # Ставка проиграла - деньги уже списаны
            bet.won = False
            print(f"Ставка пользователя {bet.user_id} проиграла")

    try:
        db.session.commit()
        print(f"Ставки для матча {match_id} успешно рассчитаны")
    except Exception as e:
        print(f"Ошибка при сохранении результатов ставок: {e}")
        db.session.rollback()


@app.route('/settle_bets/<int:match_id>', methods=['POST'])
@login_required
def settle_bets_manual(match_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    try:
        settle_bets(match_id)
        flash('Ставки успешно рассчитаны', 'success')
    except Exception as e:
        flash(f'Ошибка при расчете ставок: {e}', 'danger')


@app.route('/nuclear_db')
def nuclear_db():
    """Полное пересоздание базы"""
    db.drop_all()
    db.create_all()

    # Создаем админа
    admin = User(
        name='Admin',
        email=ADMIN_EMAIL,
        club='Краснодар',
        password=pw_secure.encrypt_password('admin123'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()

    # Баланс и темы
    UserBalance(user_id=1, balance=1000)
    UserTheme(user_id=1, theme_name='light', is_active=True)
    UserTheme(user_id=1, theme_name='dark', is_active=False)
    db.session.commit()

    return "✅ База полностью пересоздана!"

@app.route('/admin/update_balance_simple/<int:user_id>', methods=['POST'])
@login_required
def admin_update_balance_simple(user_id):
    """Упрощенная версия обновления баланса"""
    try:
        print(f"DEBUG: Обновление баланса для пользователя {user_id}")

        if not current_user.is_admin:
            flash('Доступ запрещен', 'danger')
            return redirect(url_for('view_user', user_id=user_id))

        amount = int(request.form.get('amount', 0))
        action = request.form.get('action', 'add')

        print(f"DEBUG: Сумма: {amount}, Действие: {action}")

        if amount <= 0 or amount > 100000:
            flash('Неверная сумма (должна быть от 1 до 100000)', 'danger')
            return redirect(url_for('view_user', user_id=user_id))

        # Находим пользователя
        user = User.query.get(user_id)
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('users'))

        print(f"DEBUG: Найден пользователь: {user.name}")

        # Получаем или создаем баланс пользователя
        user_balance = UserBalance.query.filter_by(user_id=user_id).first()
        if not user_balance:
            print("DEBUG: Создаем новый баланс")
            user_balance = UserBalance(user_id=user_id, balance=100)
            db.session.add(user_balance)
        else:
            print(f"DEBUG: Текущий баланс: {user_balance.balance}")

        # Выполняем действие с балансом
        if action == 'add':
            user_balance.balance += amount
            message = f'Успешно добавлено {amount} монет пользователю {user.name}'
        else:  # action == 'set'
            user_balance.balance = amount
            message = f'Баланс пользователя {user.name} установлен на {amount} монет'

        print(f"DEBUG: Новый баланс: {user_balance.balance}")
        db.session.commit()

        flash(message, 'success')

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: Ошибка при обновлении баланса: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Ошибка при обновлении баланса: {e}', 'danger')

    return redirect(url_for('view_user', user_id=user_id))


@app.route('/debug/users')
@login_required
def debug_users():
    """Диагностическая страница всех пользователей"""
    if not current_user.is_admin:
        return "Доступ запрещен"

    try:
        users = User.query.all()
        result = "<h1>Диагностика пользователей</h1>"

        for user in users:
            balance = UserBalance.query.filter_by(user_id=user.id).first()
            result += f"""
            <div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
                <p><strong>ID:</strong> {user.id}</p>
                <p><strong>Имя:</strong> {user.name}</p>
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Баланс объект:</strong> {balance}</p>
                <p><strong>Баланс значение:</strong> {balance.balance if balance else 'Не найден'}</p>
                <p><a href="/user/{user.id}">Перейти к профилю</a></p>
            </div>
            """

        return result

    except Exception as e:
        return f"Ошибка: {e}"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

def init_user_balances():
    """Инициализирует балансы для всех пользователей, у которых их нет"""
    try:
        users_without_balance = db.session.query(User).filter(
            ~User.id.in_(db.session.query(UserBalance.user_id))
        ).all()

        for user in users_without_balance:
            user_balance = UserBalance(user_id=user.id, balance=100)
            db.session.add(user_balance)

        db.session.commit()
        print(f"Инициализировано балансов: {len(users_without_balance)}")
    except Exception as e:
        print(f"Ошибка при инициализации балансов: {e}")
        db.session.rollback()


    def init_user_themes():
        """Инициализирует темы для всех пользователей"""
        try:
            users_without_themes = db.session.query(User).filter(
                ~User.id.in_(db.session.query(UserTheme.user_id))
            ).all()

            for user in users_without_themes:
                # Добавляем бесплатные темы по умолчанию
                light_theme = UserTheme(
                    user_id=user.id,
                    theme_name='light',
                    is_active=True
                )
                dark_theme = UserTheme(
                    user_id=user.id,
                    theme_name='dark',
                    is_active=False
                )
                db.session.add(light_theme)
                db.session.add(dark_theme)

            db.session.commit()
            print(f"Инициализировано тем: {len(users_without_themes) * 2}")
        except Exception as e:
            print(f"Ошибка при инициализации тем: {e}")
            db.session.rollback()


if __name__ == '__main__':
    with app.app_context():
        print("=== СОЗДАЕМ БАЗУ С НУЛЯ ===")

        # ... предыдущий код создания таблиц ...

        # МАТЧИ - ВОТ ОНИ!
        if Match.query.count() == 0:
            # Создаем матчи на разные туры
            today = datetime.now()

            # МАТЧИ ПРЕДЫДУЩЕГО ТУРА (завершенные)
            prev_match1 = Match(
                home_team="Зенит",
                away_team="Спартак",
                match_date=today - timedelta(days=7),  # Прошлая неделя
                home_score=2,
                away_score=1,
                is_played=True,
                tour_number=1  # Предыдущий тур
            )

            prev_match2 = Match(
                home_team="ЦСКА",
                away_team="Динамо Москва",
                match_date=today - timedelta(days=6),
                home_score=0,
                away_score=0,
                is_played=True,
                tour_number=1
            )

            prev_match3 = Match(
                home_team="Краснодар",
                away_team="Локомотив",
                match_date=today - timedelta(days=5),
                home_score=3,
                away_score=2,
                is_played=True,
                tour_number=1
            )

            # МАТЧИ ТЕКУЩЕГО ТУРА
            current_match1 = Match(
                home_team="Ростов",
                away_team="Ахмат",
                match_date=today + timedelta(hours=2),  # Скоро
                tour_number=2  # Текущий тур
            )

            current_match2 = Match(
                home_team="Рубин",
                away_team="Оренбург",
                match_date=today + timedelta(days=1),
                tour_number=2
            )

            # МАТЧИ СЛЕДУЮЩЕГО ТУРА
            next_match1 = Match(
                home_team="Спартак",
                away_team="Краснодар",
                match_date=today + timedelta(days=7),
                tour_number=3  # Следующий тур
            )

            next_match2 = Match(
                home_team="Зенит",
                away_team="ЦСКА",
                match_date=today + timedelta(days=8),
                tour_number=3
            )

            # Добавляем все матчи
            db.session.add_all([
                prev_match1, prev_match2, prev_match3,
                current_match1, current_match2,
                next_match1, next_match2
            ])
            db.session.commit()
            print("✅ Тестовые матчи созданы (предыдущий, текущий, следующий туры)")

        # Тестовый вопрос
        if ClubTest.query.count() == 0:
            test = ClubTest(
                question="В каком году основан Спартак?",
                correct_answer="1922",
                option1="1902",
                option2="1920",
                option3="1922",
                option4="1912",
                difficulty=1
            )
            db.session.add(test)
            db.session.commit()
            print("✅ Тестовый вопрос добавлен")

        print("🎉 БАЗА ДАННЫХ ГОТОВА К РАБОТЕ!")
        print("📅 Матчи созданы!")

        # Запускаем приложение
        app.run(host='127.0.0.1', port=5000, debug=True)
