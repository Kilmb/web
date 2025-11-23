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
from clubs import CLUBS_DATA, RPL_CLUBS
import random
import translators as ts

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


def main():
    app.run()


# Проверка расширения файла
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Класс для хэширования и проверки паролей
class Password_inkognito:
    def encrypt_password(self, password):
        return generate_password_hash(password)

    def verify_password(self, hashed_password, input_password):
        return check_password_hash(hashed_password, input_password)


pw_secure = Password_inkognito()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    club = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))
    about = db.Column(db.String(250))
    theme = db.Column(db.String(50), default='default')
    purchased_themes = db.Column(db.Text, default='default')

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

    def get_purchased_themes(self):
        if not self.purchased_themes:
            return ['default']
        try:
            return json.loads(self.purchased_themes)
        except:
            return ['default']

    def add_purchased_theme(self, theme_name):
        purchased = self.get_purchased_themes()
        if theme_name not in purchased:
            purchased.append(theme_name)
            self.purchased_themes = json.dumps(purchased)


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


class WheelSpin(db.Model):
    __tablename__ = 'wheel_spins'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    last_spin = db.Column(db.DateTime)
    spins_count = db.Column(db.Integer, default=0)

    user = db.relationship('User')

class Match(db.Model):
    __tablename__ = 'matches'

    id = db.Column(db.Integer, primary_key=True)
    home_team = db.Column(db.String(50), nullable=False)
    away_team = db.Column(db.String(50), nullable=False)
    match_date = db.Column(db.DateTime, nullable=False)
    home_score = db.Column(db.Integer, nullable=True)
    away_score = db.Column(db.Integer, nullable=True)
    is_played = db.Column(db.Boolean, default=False)
    is_started = db.Column(db.Boolean, default=False)
    tour_number = db.Column(db.Integer, nullable=False)

    # === ИЗМЕНЕНИЕ 1: Добавлено поле для ID матча из API ===
    sstats_id = db.Column(db.Integer, nullable=True, index=True)

    def __repr__(self):
        return f"Match('{self.home_team} vs {self.away_team}', {self.match_date})"


class MatchMessage(db.Model):
    __tablename__ = 'match_messages'

    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('matches.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User')


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


class UserBalance(db.Model):
    __tablename__ = 'user_balances'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    balance = db.Column(db.Integer, default=100)

    user = db.relationship('User')


class Bet(db.Model):
    __tablename__ = 'bets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    match_id = db.Column(db.Integer, db.ForeignKey('matches.id'))
    bet_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_settled = db.Column(db.Boolean, default=False)
    won = db.Column(db.Boolean, default=False)

    user = db.relationship('User')
    match = db.relationship('Match')


class Player(db.Model):
    __tablename__ = 'players'

    id = db.Column(db.Integer, primary_key=True) # ID из SStats API
    name = db.Column(db.String(100), nullable=False) # Русское имя
    team_id = db.Column(db.Integer, nullable=True)   # ID команды (необязательно, но полезно)

    def __repr__(self):
        return f"Player({self.id}, '{self.name}')"


class MatchEvent(db.Model):
    __tablename__ = 'match_events'

    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('matches.id'), nullable=False)
    team_id = db.Column(db.Integer)  # ID команды
    minute = db.Column(db.Integer)   # Минута
    type = db.Column(db.Integer)     # 1=Гол, 2=ЖК, 3=Замена
    player_name = db.Column(db.String(100)) # Имя игрока (уже русское)
    extra_info = db.Column(db.String(100))  # Ассистент или ушедший игрок

    def __repr__(self):
        return f"Event({self.minute}', {self.player_name})"


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


names_cache = {}


def transliterate_name(text):
    """
    Перевод через библиотеку translators (использует онлайн-сервисы).
    """
    if not text: return ""

    # Если уже переводили - берем из памяти
    if text in names_cache:
        return names_cache[text]

    # Если уже кириллица - возвращаем
    if any('\u0400' <= char <= '\u04FF' for char in text):
        return text

    try:
        # Используем движок 'google' или 'bing' (bing часто быстрее для бесплатных запросов)
        # Можно попробовать translator='yandex', но он иногда требует капчу
        rus_text = ts.translate_text(text, translator='google', from_language='en', to_language='ru')

        names_cache[text] = rus_text
        return rus_text
    except Exception as e:
        print(f"Ошибка API перевода для {text}: {e}")
        return text


# Загружает пользователя
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


def get_current_tour_from_api():
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

        completed_matches = [m for m in matches_data if m.get('status') == 8]
        current_tour = (len(completed_matches) // 8) + 1

        return min(current_tour, 30)

    except Exception as e:
        print(f"Ошибка при определении текущего тура: {e}")
        return load_current_tour_from_file()


@app.context_processor
def inject_current_tour():
    return {'current_tour': load_current_tour()}


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


# Главная страница
@app.route('/')
def home():
    # 1. Загружаем таблицу
    table = db.session.query(RPLTable).order_by(RPLTable.position).all()

    # 2. Определяем текущий тур (как раньше)
    current_tour = load_current_tour()

    # 3. Загружаем ВСЕ матчи сезона
    all_matches = db.session.query(Match).order_by(Match.match_date).all()

    # 4. Группируем матчи по номерам туров
    # Результат будет словарем: {1: [матч, матч...], 2: [матч...], ...}
    matches_by_tour = {}

    # Определяем максимальный возможный тур (для РПЛ это 30)
    max_tour = 30

    # Заполняем словарь пустыми списками, чтобы туры шли по порядку
    for i in range(1, max_tour + 1):
        matches_by_tour[i] = []

    for match in all_matches:
        # Если у матча прописан тур (и он > 0), кладем в нужную ячейку
        t_num = match.tour_number
        if t_num and t_num in matches_by_tour:
            matches_by_tour[t_num].append(match)
        elif t_num == 0:
            # Если тур 0 (не определен), можно временно кинуть в конец или игнорировать
            pass

    context = {
        'rpl_table': table,
        'matches_by_tour': matches_by_tour,  # Передаем весь словарь
        'current_tour': current_tour,
        'max_tour': max_tour,
        'clubs': CLUBS_DATA
    }

    if current_user.is_authenticated:
        return render_template('home.html', **context)

    return render_template('home.html', **context, show_public_content=True)


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

            new_balance = UserBalance(user_id=user.id, balance=100)
            db.session.add(new_balance)
            db.session.commit()

            login_user(user)
            return redirect(url_for('home'))

    return render_template('register.html', clubs=RPL_CLUBS, all_clubs=CLUBS_DATA)


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

    return render_template('login.html', clubs=CLUBS_DATA)


# Тесты только для пользователей
@app.route('/club_tests')
@login_required
def club_tests():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    tests = db.session.query(ClubTest).order_by(ClubTest.id).all()
    return render_template('club_tests.html', tests=tests, clubs=CLUBS_DATA)


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
                           title='Лёгкий тест',
                           clubs=CLUBS_DATA)


@app.route('/medium_quiz')
@login_required
def medium_quiz():
    tests = db.session.query(ClubTest).filter(ClubTest.difficulty == 2).order_by(ClubTest.id).limit(10).all()

    if not tests:
        return redirect(url_for('home'))

    return render_template('quiz.html',
                           tests=tests,
                           test_type='medium',
                           title='Средний тест',
                           clubs=CLUBS_DATA)


@app.route('/hard_quiz')
@login_required
def hard_quiz():
    tests = db.session.query(ClubTest).filter(ClubTest.difficulty == 3).order_by(ClubTest.id).limit(10).all()

    if not tests:
        return redirect(url_for('home'))

    return render_template('quiz.html',
                           tests=tests,
                           test_type='hard',
                           title='Сложный тест',
                           clubs=CLUBS_DATA)


# Проверка результатов
@app.route('/check_quiz/<test_type>', methods=['POST'])
@login_required
def check_quiz(test_type):
    score = 0
    results = []

    difficulty_multiplier_map = {
        'easy': 1,
        'medium': 2,
        'hard': 3
    }
    difficulty_multiplier = difficulty_multiplier_map.get(test_type, 1)

    difficulty_filter = {
        'easy': (1, 1),
        'medium': (2, 2),
        'hard': (3, 3)
    }.get(test_type, (1, 3))

    for question_id, user_answer in request.form.items():
        if question_id.startswith('q_'):
            test_id = question_id[2:]

            test = db.session.get(ClubTest, int(test_id))

            if test and difficulty_filter[0] <= test.difficulty <= difficulty_filter[1]:
                is_correct = (user_answer == test.correct_answer)
                if is_correct:
                    score += 1

                results.append({
                    'question': test.question,
                    'user_answer': user_answer,
                    'correct_answer': test.correct_answer,
                    'is_correct': is_correct,
                    'difficulty': test.difficulty
                })

    total_questions = len(results)

    result = TestResult(
        user_id=current_user.id,
        test_type=test_type,
        score=score,
        total=total_questions,
        date=datetime.now()
    )
    db.session.add(result)
    db.session.commit()

    reward = score * difficulty_multiplier

    if reward > 0:
        user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()

        if not user_balance:
            user_balance = UserBalance(user_id=current_user.id, balance=100)
            db.session.add(user_balance)

        user_balance.balance += reward
        db.session.commit()

        flash(f'Тест пройден! Вы получили {reward} монет.', 'success')

    return render_template('quiz_results.html',
                           score=score,
                           total=total_questions,
                           results=results,
                           test_type=test_type,
                           clubs=CLUBS_DATA)


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

    return render_template('edit_test.html', test=test, clubs=CLUBS_DATA)


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
    return render_template('edit_rpl_table.html', table=table, clubs=CLUBS_DATA)


# Обновление таблицы и матчей из API
@app.route('/update_data_from_api', methods=['POST'])
@login_required
def update_data_from_api():
    try:
        success_table, message_table = update_rpl_table_from_sstats()

        current_tour = load_current_tour()
        success_current, message_current = update_matches_for_tour(current_tour)

        next_tour = current_tour + 1
        success_next, message_next = update_matches_for_tour(next_tour)

        prev_tour = current_tour - 1
        success_prev, message_prev = update_matches_for_tour(prev_tour)

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

                status = match_data.get('status', 2)

                is_played = status in [8, 9, 10]
                is_started = status in [3, 4, 5, 6, 7, 11]

                # === ИЗМЕНЕНИЕ 2: Получаем ID матча из API ===
                sstats_id = match_data.get('id')

                existing_match = db.session.query(Match).filter(
                    Match.home_team == home_team,
                    Match.away_team == away_team,
                    Match.tour_number == tour_number
                ).first()

                if existing_match:
                    was_played_before = existing_match.is_played
                    was_started_before = existing_match.is_started

                    existing_match.home_score = home_score if is_played or is_started else None
                    existing_match.away_score = away_score if is_played or is_started else None
                    existing_match.is_played = is_played
                    existing_match.is_started = is_started
                    existing_match.match_date = match_date_msk

                    # === ИЗМЕНЕНИЕ 2: Сохраняем ID матча ===
                    existing_match.sstats_id = sstats_id

                    matches_updated += 1

                    if is_played and not was_played_before:
                        settle_bets(existing_match.id)
                    elif is_started and not was_started_before:
                        print(f"Матч {home_team} vs {away_team} начался!")

                else:
                    new_match = Match(
                        home_team=home_team,
                        away_team=away_team,
                        match_date=match_date_msk,
                        home_score=home_score if is_played or is_started else None,
                        away_score=away_score if is_played or is_started else None,
                        is_played=is_played,
                        is_started=is_started,
                        tour_number=tour_number,

                        # === ИЗМЕНЕНИЕ 2: Сохраняем ID матча ===
                        sstats_id=sstats_id
                    )
                    db.session.add(new_match)
                    matches_added += 1

            except Exception as e:
                print(f"Ошибка при обработке матча {home_team_api} vs {away_team_api}: {e}")
                continue

        db.session.commit()

        message = f"добавлено {matches_added}, обновлено {matches_updated}"
        return True, message

    except Exception as e:
        print(f"Ошибка при обновлении матчей тура {tour_number}: {e}")
        db.session.rollback()
        return False, f"ошибка API"


@app.route('/wheel')
@login_required
def wheel_page():
    return render_template('wheel.html', clubs=CLUBS_DATA)


@app.route('/api/wheel/spin', methods=['POST'])
@login_required
def wheel_spin():
    try:
        wheel_spin_record = WheelSpin.query.filter_by(user_id=current_user.id).first()

        if wheel_spin_record and wheel_spin_record.last_spin:
            time_since_last_spin = datetime.now() - wheel_spin_record.last_spin

            if time_since_last_spin.total_seconds() < 24 * 60 * 60:  # 24 часа
                hours_left = 24 - (time_since_last_spin.total_seconds() // 3600)
                return jsonify({
                    'success': False,
                    'message': f'Вы можете крутить колесо только раз в 24 часа. Попробуйте через {int(hours_left)} часов.'
                })

        prizes = [
            {'type': 'add', 'amount': 50, 'probability': 20},  # 20%
            {'type': 'add', 'amount': 100, 'probability': 15},  # 15%
            {'type': 'add', 'amount': 250, 'probability': 8},  # 8%
            {'type': 'subtract', 'amount': 50, 'probability': 15},  # 15%
            {'type': 'subtract', 'amount': 100, 'probability': 10},  # 10%
            {'type': 'subtract', 'amount': 250, 'probability': 5},  # 5%
            {'type': 'multiply', 'multiplier': 2, 'probability': 10},  # 10%
            {'type': 'multiply', 'multiplier': 3, 'probability': 5},  # 5%
            {'type': 'divide', 'divider': 2, 'probability': 8},  # 8%
            {'type': 'jackpot', 'amount': 10000, 'probability': 4}
        ]

        # Выбираем приз на основе вероятностей
        total_probability = sum(prize['probability'] for prize in prizes)
        random_value = random.uniform(0, total_probability)

        current_probability = 0
        selected_prize = None

        for prize in prizes:
            current_probability += prize['probability']
            if random_value <= current_probability:
                selected_prize = prize
                break

        # Получаем баланс пользователя
        user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()

        if not user_balance:
            user_balance = UserBalance(user_id=current_user.id, balance=100)
            db.session.add(user_balance)

        old_balance = user_balance.balance
        new_balance = old_balance

        # Применяем приз
        if selected_prize['type'] == 'add':
            new_balance = old_balance + selected_prize['amount']
            message = f"+{selected_prize['amount']} монет!"

        elif selected_prize['type'] == 'subtract':
            new_balance = max(0, old_balance - selected_prize['amount'])
            message = f"-{selected_prize['amount']} монет"

        elif selected_prize['type'] == 'multiply':
            new_balance = old_balance * selected_prize['multiplier']
            message = f"x{selected_prize['multiplier']} к балансу!"

        elif selected_prize['type'] == 'divide':
            new_balance = max(0, old_balance // selected_prize['divider'])
            message = f"÷{selected_prize['divider']} к балансу"

        elif selected_prize['type'] == 'jackpot':
            new_balance = old_balance + selected_prize['amount']
            message = f"ДЖЕКПОТ! +{selected_prize['amount']} монет! 🎉"

        user_balance.balance = new_balance

        # Обновляем запись о вращении
        if not wheel_spin_record:
            wheel_spin_record = WheelSpin(user_id=current_user.id)
            db.session.add(wheel_spin_record)

        wheel_spin_record.last_spin = datetime.now()
        wheel_spin_record.spins_count = (wheel_spin_record.spins_count or 0) + 1

        db.session.commit()
        return jsonify({
            'success': True,
            'prize': selected_prize,
            'message': message,
            'old_balance': old_balance,
            'new_balance': new_balance,
            'next_spin_time': wheel_spin_record.last_spin.timestamp() + 24 * 60 * 60
        })

    except Exception as e:
        db.session.rollback()
        print(f"ERROR in wheel_spin: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Произошла ошибка: {str(e)}'
        })

@app.route('/api/wheel/status')
@login_required
def wheel_status():
    try:
        wheel_spin_record = WheelSpin.query.filter_by(user_id=current_user.id).first()

        if wheel_spin_record and wheel_spin_record.last_spin:
            time_since_last_spin = datetime.now() - wheel_spin_record.last_spin
            can_spin = time_since_last_spin.total_seconds() >=  24 * 60 * 60
            next_spin_time = wheel_spin_record.last_spin.timestamp() + 24 * 60 * 60
        else:
            can_spin = True
            next_spin_time = None

        return jsonify({
            'can_spin': can_spin,
            'next_spin_time': next_spin_time,
            'spins_count': wheel_spin_record.spins_count if wheel_spin_record else 0
        })
    except Exception as e:
        return jsonify({
            'can_spin': False,
            'next_spin_time': None,
            'spins_count': 0
        })


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if 'avatar' in request.files and request.files['avatar'].filename != '':
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
                flash('Аватар успешно обновлен!', 'success')
                return redirect(url_for('profile'))

        elif form_type == 'profile_info':
            new_name = request.form.get('name')
            about_text = request.form.get('about', '')[:250]

            if new_name and new_name != current_user.name:
                current_user.name = new_name
            current_user.about = about_text
            db.session.commit()
            flash('Информация профиля сохранена!', 'success')
            return redirect(url_for('profile'))

        elif form_type == 'theme':
            new_theme = request.form.get('theme')

            THEME_COSTS = {
                'default': 0,
                'indigo': 100,
                'sunset': 100,
                'forest': 100,
                'crimson': 100,
                'dark': 0,
                'gold': 100,
                'club': 150
            }

            theme_cost = THEME_COSTS.get(new_theme)

            user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()
            if not user_balance:
                user_balance = UserBalance(user_id=current_user.id, balance=100)
                db.session.add(user_balance)

            purchased_themes = current_user.get_purchased_themes()

            if new_theme in purchased_themes:
                current_user.theme = new_theme
                db.session.commit()
                flash(f'Тема успешно применена!', 'success')
            elif user_balance.balance >= theme_cost:
                user_balance.balance -= theme_cost
                current_user.theme = new_theme
                current_user.add_purchased_theme(new_theme)
                db.session.commit()
                flash(f'Тема успешно куплена и применена!', 'success')
            else:
                flash('Недостаточно монет для покупки темы!', 'danger')

            return redirect(url_for('profile'))

    user_balance_obj = UserBalance.query.filter_by(user_id=current_user.id).first()
    user_balance = user_balance_obj.balance if user_balance_obj else 100
    total_bets = Bet.query.filter_by(user_id=current_user.id).count()
    bets_won = Bet.query.filter_by(user_id=current_user.id, won=True).count()
    last_test = TestResult.query.filter_by(user_id=current_user.id).order_by(TestResult.date.desc()).first()
    bets_history = Bet.query.filter_by(user_id=current_user.id).order_by(Bet.created_at.desc()).limit(10).all()

    purchased_themes = current_user.get_purchased_themes()

    return render_template('profile.html',
                           user_balance=user_balance,
                           total_bets=total_bets,
                           bets_won=bets_won,
                           last_test=last_test,
                           bets_history=bets_history,
                           clubs=CLUBS_DATA,
                           purchased_themes=purchased_themes)


# Просмотр пользователей
@app.route('/users')
@login_required
def show_users():
    try:
        users = User.query.all()
        user_balances = {}
        try:
            balances = UserBalance.query.all()
            for balance in balances:
                user_balances[balance.user_id] = balance.balance
        except Exception as e:
            for user in users:
                user_balances[user.id] = 100

        try:
            sorted_users = sorted(
                users,
                key=lambda u: user_balances.get(u.id, 100),
                reverse=True
            )
        except Exception as e:
            sorted_users = users

        return render_template('users.html', users=sorted_users, user_balances=user_balances, clubs=CLUBS_DATA)

    except Exception as e:
        print(f"ERROR: Критическая ошибка в show_users: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('home'))


# Просмотр профилей
@app.route('/user/<int:user_id>')
@login_required
def view_user(user_id):
    try:

        user = db.session.get(User, user_id)

        user_balance_obj = UserBalance.query.filter_by(user_id=user_id).first()

        if user_balance_obj:
            user_balance = user_balance_obj.balance
        else:
            user_balance = 100
            new_balance = UserBalance(user_id=user_id, balance=100)
            db.session.add(new_balance)
            db.session.commit()

        return render_template('user_profile.html', user=user, user_balance=user_balance, clubs=CLUBS_DATA)

    except Exception as e:
        print(f"ERROR: Ошибка в view_user: {e}")
        import traceback
        traceback.print_exc()
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


@app.route('/place_bet/<int:match_id>', methods=['POST'])
@login_required
def place_bet(match_id):
    match = db.session.get(Match, match_id)

    if match.is_started or match.is_played:
        return redirect(url_for('home'))

    bet_type = request.form.get('bet_type')
    amount = int(request.form.get('amount', 0))

    if amount <= 0:
        flash('Сумма ставки должна быть положительной', 'danger')
        return redirect(url_for('home'))

    user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()
    if not user_balance:
        user_balance = UserBalance(user_id=current_user.id, balance=100)
        db.session.add(user_balance)
        db.session.commit()

    if user_balance.balance < amount:
        flash('Недостаточно средств для ставки', 'danger')
        return redirect(url_for('home'))

    existing_bet = Bet.query.filter_by(user_id=current_user.id, match_id=match_id).first()
    if existing_bet:
        flash('Вы уже сделали ставку на этот матч', 'danger')
        return redirect(url_for('home'))

    new_bet = Bet(
        user_id=current_user.id,
        match_id=match_id,
        bet_type=bet_type,
        amount=amount
    )

    user_balance.balance -= amount

    db.session.add(new_bet)
    db.session.commit()

    flash(f'Ставка на {amount} монет успешно размещена!', 'success')
    return redirect(url_for('home'))


# Функция для расчета результатов ставок
def settle_bets(match_id):
    match = db.session.get(Match, match_id)
    if not match or not match.is_played:
        return

    if match.home_score > match.away_score:
        actual_result = 'home_win'
    elif match.home_score == match.away_score:
        actual_result = 'draw'
    else:
        actual_result = 'away_win'

    bets = Bet.query.filter_by(match_id=match_id, is_settled=False).all()

    for bet in bets:
        bet.is_settled = True

        if bet.bet_type == actual_result:
            user_balance = UserBalance.query.filter_by(user_id=bet.user_id).first()
            user_balance.balance += bet.amount * 2
            bet.won = True
        else:
            bet.won = False

    db.session.commit()


@app.route('/admin/update_balance_simple/<int:user_id>', methods=['POST'])
@login_required
def admin_update_balance_simple(user_id):
    try:

        if not current_user.is_admin:
            return redirect(url_for('view_user', user_id=user_id))

        amount = int(request.form.get('amount', 0))
        action = request.form.get('action', 'add')

        if amount <= 0 or amount > 100000:
            flash('Неверная сумма (должна быть от 1 до 100000)', 'danger')
            return redirect(url_for('view_user', user_id=user_id))

        user = User.query.get(user_id)

        user_balance = UserBalance.query.filter_by(user_id=user_id).first()
        if not user_balance:
            user_balance = UserBalance(user_id=user_id, balance=100)
            db.session.add(user_balance)

        if action == 'add':
            user_balance.balance += amount
            message = f'Успешно добавлено {amount} монет пользователю {user.name}'
        else:
            user_balance.balance = amount
            message = f'Баланс пользователя {user.name} установлен на {amount} монет'

        db.session.commit()

        flash(message, 'success')

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: Ошибка при обновлении баланса: {e}")
        import traceback
        traceback.print_exc()

    return redirect(url_for('view_user', user_id=user_id))


def init_user_balances():
    try:
        users_without_balance = db.session.query(User).filter(
            ~User.id.in_(db.session.query(UserBalance.user_id))
        ).all()

        for user in users_without_balance:
            user_balance = UserBalance(user_id=user.id, balance=100)
            db.session.add(user_balance)

        db.session.commit()
    except Exception as e:
        print(f"Ошибка при инициализации балансов: {e}")
        db.session.rollback()


def get_team_form(team_name, limit=5):
    matches = Match.query.filter(((Match.home_team == team_name) | (Match.away_team == team_name)),
                                 Match.is_played == True).order_by(Match.match_date.desc()).limit(limit).all()
    form = []
    for m in matches:
        if m.home_team == team_name:
            form.append(
                {'class': 'win' if m.home_score > m.away_score else ('loss' if m.home_score < m.away_score else 'draw'),
                 'text': 'В' if m.home_score > m.away_score else ('П' if m.home_score < m.away_score else 'Н')})
        else:
            form.append(
                {'class': 'win' if m.away_score > m.home_score else ('loss' if m.away_score < m.home_score else 'draw'),
                 'text': 'В' if m.away_score > m.home_score else ('П' if m.away_score < m.home_score else 'Н')})
    return form


@app.route('/match/<int:match_id_db>')
@login_required
def match_details(match_id_db):
    match = db.session.get(Match, match_id_db)
    if not match: return redirect(url_for('home'))

    home_form = get_team_form(match.home_team)
    away_form = get_team_form(match.away_team)
    chat_messages = MatchMessage.query.filter_by(match_id=match_id_db).order_by(MatchMessage.created_at.asc()).all()

    api_data = {}

    if match.sstats_id:
        try:
            headers = {'apikey': '8ftkpzresyxo7dqz'}
            url_main = f"https://api.sstats.net/Games/{match.sstats_id}"
            resp = requests.get(url_main, headers=headers, timeout=15)

            if resp.ok:
                json_resp = resp.json()
                api_data = json_resp.get('data', {}) if isinstance(json_resp, dict) else {}

                # 1. Перевод тренеров
                if api_data.get('lineups'):
                    for side in ['homeCoach', 'awayCoach']:
                        if api_data['lineups'].get(side):
                            c_name = api_data['lineups'][side].get('name')
                            api_data['lineups'][side]['name'] = transliterate_name(c_name)

                # === СБОР ТОЛЬКО ЗАМЕН (ОСТАЛЬНОЕ ИГНОРИРУЕМ) ===
                player_events_data = {}

                events = api_data.get('events')
                if events and isinstance(events, list):
                    for e in events:
                        if not isinstance(e, dict): continue

                        minute = e.get('elapsed', 0)
                        etype = e.get('type')  # 3 = Замена

                        # Обрабатываем ТОЛЬКО замены
                        if etype == 3:
                            pid_raw = e.get('player', {}).get('id') if e.get('player') else None
                            aid_raw = e.get('assistPlayer', {}).get('id') if e.get('assistPlayer') else None

                            pid = str(pid_raw) if pid_raw is not None else None
                            aid = str(aid_raw) if aid_raw is not None else None

                            # Тот кто ВЫХОДИТ (Запасной) -> ВВЕРХ (Зеленая)
                            if pid:
                                if pid not in player_events_data: player_events_data[pid] = []
                                player_events_data[pid].append({'type': 'sub_out', 'min': minute})

                            # Тот кто УХОДИТ (Старт) -> ВНИЗ (Красная)
                            if aid:
                                if aid not in player_events_data: player_events_data[aid] = []
                                player_events_data[aid].append({'type': 'sub_in', 'min': minute})

                # 3. Обработка игроков
                lineups = api_data.get('lineupPlayers')
                if lineups and isinstance(lineups, list):
                    pos_weights = {'G': 1, 'D': 2, 'M': 3, 'F': 4}
                    for p in lineups:
                        if isinstance(p, dict):
                            if p.get('playerName'): p['playerName'] = transliterate_name(p['playerName'])

                            p_id = str(p.get('playerId'))

                            # Добавляем ТОЛЬКО замены
                            p['events_list'] = player_events_data.get(p_id, [])

                            pos_char = str(p.get('position', 'M'))
                            p['sort_weight'] = pos_weights.get(pos_char, 3)
                            p['is_bench'] = 0 if p.get('startXI') else 1

                    lineups.sort(key=lambda x: (x.get('is_bench', 1), x.get('sort_weight', 5)))

            # Статистика
            stats_url = "https://api.sstats.net/games/query-games"
            stats_payload = {"Condition": f"Id = {match.sstats_id}", "Format": "json",
                             "Fields": ["BallPossessionHome", "BallPossessionAway", "TotalShotsHome", "TotalShotsAway",
                                        "ShotsOnGoalHome", "ShotsOnGoalAway", "CornerKicksHome", "CornerKicksAway",
                                        "OffsidesHome", "OffsidesAway", "FoulsHome", "FoulsAway", "YellowCardsHome",
                                        "YellowCardsAway", "RedCardsHome", "RedCardsAway", "ExpectedGoalsHome",
                                        "ExpectedGoalsAway"]}
            try:
                stats_resp = requests.post(stats_url, headers=headers, json=stats_payload, timeout=5)
                if stats_resp.ok:
                    stats_json = stats_resp.json()
                    if isinstance(stats_json, dict) and isinstance(stats_json.get('data'), list) and len(
                            stats_json['data']) > 0:
                        s_raw = stats_json['data'][0]
                        if 'statistics' not in api_data: api_data['statistics'] = {}
                        for key, val in s_raw.items(): api_data['statistics'][key[0].lower() + key[1:]] = val
            except:
                pass

        except Exception as e:
            print(f"API Error: {e}")

    return render_template('match_details.html', match=match, api_data=api_data,
                           home_form=home_form, away_form=away_form,
                           chat_messages=chat_messages, clubs=CLUBS_DATA)


@app.route('/admin/sync_season', methods=['POST'])
@login_required
def sync_full_season_route():
    if not current_user.is_admin:
        flash('Только для администратора', 'danger')
        return redirect(url_for('home'))

    try:
        db.session.query(Match).delete()
        db.session.commit()

        url = "https://api.sstats.net/games/list?"
        params = {
            'leagueId': 235,
            'year': 2025,
            'format': 'json',
            'limit': 1000
        }
        headers = {'apikey': '8ftkpzresyxo7dqz'}

        response = requests.get(url, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        matches_data = data.get('data', [])
        matches_data.sort(key=lambda x: x['date'])

        added = 0

        for i, match_data in enumerate(matches_data):
            try:
                calculated_tour = (i // 8) + 1

                home_team = map_team_name(match_data['homeTeam']['name'])
                away_team = map_team_name(match_data['awayTeam']['name'])

                match_date_str = match_data['date']
                match_date_utc = datetime.fromisoformat(match_date_str.replace('Z', '+00:00'))
                match_date_msk = match_date_utc.replace(tzinfo=None) + timedelta(hours=3)

                status = match_data.get('status', 2)
                is_played = status in [8, 9, 10]
                is_started = status in [3, 4, 5, 6, 7, 11]
                sstats_id = match_data.get('id')

                new_match = Match(
                    home_team=home_team,
                    away_team=away_team,
                    match_date=match_date_msk,
                    home_score=match_data.get('homeResult'),
                    away_score=match_data.get('awayResult'),
                    is_played=is_played,
                    is_started=is_started,
                    tour_number=calculated_tour,
                    sstats_id=sstats_id
                )
                db.session.add(new_match)
                added += 1

            except Exception as e:
                print(f"Ошибка при обработке матча: {e}")
                continue

        db.session.commit()
        try:
            current_tour = (len([m for m in matches_data if m.get('status') == 8]) // 8) + 1
            save_current_tour(min(current_tour, 30))
        except:
            pass

        flash(f'База полностью обновлена! Загружено матчей: {added}. Туры пересчитаны.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'danger')

    return redirect(url_for('home'))


@app.route('/match/<int:match_id>/send_message', methods=['POST'])
@login_required
def send_match_message(match_id):
    text = request.form.get('message_text')

    if text and len(text.strip()) > 0:
        if len(text) > 500:
            text = text[:500]

        new_msg = MatchMessage(
            match_id=match_id,
            user_id=current_user.id,
            text=text.strip()
        )
        db.session.add(new_msg)
        db.session.commit()

    return redirect(url_for('match_details', match_id_db=match_id))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

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

        # Заполнение таблицы клубов, если она пуста
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

        # Добавление тестовых данных, если нет матчей
        if db.session.query(Match).count() == 0:
            today = datetime.now()
            matches = [
                Match(home_team="Зенит", away_team="Спартак",
                      match_date=today, tour_number=1)
            ]
            for match in matches:
                db.session.add(match)
            db.session.commit()

        init_user_balances()

        # Добавление тестовых вопросов, если их нет
        if db.session.query(ClubTest).count() == 0:
            sample_tests = [
                ClubTest(
                    question="В каком году основан Спартак?",
                    correct_answer="1922",
                    option1="1902",
                    option2="1920",
                    option3="1922",
                    option4="1912",
                    difficulty=1
                )
            ]
            db.session.add_all(sample_tests)
            db.session.commit()

        schedule_tour_update()

        # Запуск приложения в режиме отладки
        app.run(host='127.0.0.1', port=5000, debug=True)
