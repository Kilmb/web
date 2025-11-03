from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
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

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"


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
    is_started = db.Column(db.Boolean, default=False)
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


class UserBalance(db.Model):
    __tablename__ = 'user_balances'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    balance = db.Column(db.Integer, default=100)  # Начальный баланс 100 монет

    user = db.relationship('User')


class Bet(db.Model):
    __tablename__ = 'bets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    match_id = db.Column(db.Integer, db.ForeignKey('matches.id'))
    bet_type = db.Column(db.String(20), nullable=False)  # 'home_win', 'draw', 'away_win'
    amount = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_settled = db.Column(db.Boolean, default=False)
    won = db.Column(db.Boolean, default=False)

    user = db.relationship('User')
    match = db.relationship('Match')


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


# Загружает пользователя
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


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

    context = {
        'rpl_table': table,
        'current_tour_matches': current_tour_matches,
        'prev_tour_matches': prev_tour_matches,
        'next_tour_matches': next_tour_matches,
        'current_tour': current_tour,
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

            # Создаем баланс для нового пользователя
            new_balance = UserBalance(user_id=user.id, balance=100)
            db.session.add(new_balance)
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

                status = match_data.get('status', 2)  # По умолчанию "Not Started"

                # Определяем статусы матча
                is_played = status in [8, 9, 10]  # Завершенные матчи
                is_started = status in [3, 4, 5, 6, 7, 11]  # Матчи в процессе

                # Ищем существующий матч
                existing_match = db.session.query(Match).filter(
                    Match.home_team == home_team,
                    Match.away_team == away_team,
                    Match.tour_number == tour_number
                ).first()

                if existing_match:
                    # Сохраняем предыдущее состояние матча для проверки ставок
                    was_played_before = existing_match.is_played
                    was_started_before = existing_match.is_started

                    existing_match.home_score = home_score if is_played or is_started else None
                    existing_match.away_score = away_score if is_played or is_started else None
                    existing_match.is_played = is_played
                    existing_match.is_started = is_started
                    existing_match.match_date = match_date_msk
                    matches_updated += 1

                    # Если матч завершен и ранее не был сыгран, рассчитываем ставки
                    if is_played and not was_played_before:
                        settle_bets(existing_match.id)
                    # Если матч начался и ранее не был начат, можно уведомить пользователей
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
                        tour_number=tour_number
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


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        form_type = request.form.get('form_type')

        # --- Форма 1: Обновление Аватара ---
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

        # --- Форма 2: Обновление Информации (Имя, О себе) ---
        elif form_type == 'profile_info':
            new_name = request.form.get('name')
            about_text = request.form.get('about', '')[:250]

            if new_name and new_name != current_user.name:
                current_user.name = new_name
            current_user.about = about_text
            db.session.commit()
            flash('Информация профиля сохранена!', 'success')
            return redirect(url_for('profile'))

        # --- Форма 3: Покупка Темы ---
        elif form_type == 'theme':
            new_theme = request.form.get('theme')

            # --- ИЗМЕНЕНИЕ: Добавлена 'dark' ---
            THEME_COSTS = {
                'default': 0,
                'indigo': 100,
                'sunset': 100,
                'forest': 100,
                'crimson': 100,
                'dark': 100,
                'gold': 150,
                'club': 150
            }

            theme_cost = THEME_COSTS.get(new_theme)

            if theme_cost is None:
                flash('Выбрана неизвестная тема.', 'danger')
                return redirect(url_for('profile'))

            if new_theme == 'club' and not current_user.club:
                flash('Нельзя купить "Клубную" тему, не выбрав любимый клуб!', 'warning')
                return redirect(url_for('profile'))

            user_balance = UserBalance.query.filter_by(user_id=current_user.id).first()
            if not user_balance:
                user_balance = UserBalance(user_id=current_user.id, balance=100)
                db.session.add(user_balance)

            if current_user.theme == new_theme:
                flash('Эта тема у вас уже есть.', 'info')
            elif user_balance.balance >= theme_cost:
                user_balance.balance -= theme_cost
                current_user.theme = new_theme
                db.session.commit()
                flash(f'Тема успешно куплена!', 'success')
            else:
                flash('Недостаточно монет для покупки темы!', 'danger')

            return redirect(url_for('profile'))

    # --- GET-запрос: Отображение страницы ---

    user_balance_obj = UserBalance.query.filter_by(user_id=current_user.id).first()
    user_balance = user_balance_obj.balance if user_balance_obj else 100
    total_bets = Bet.query.filter_by(user_id=current_user.id).count()
    bets_won = Bet.query.filter_by(user_id=current_user.id, won=True).count()
    last_test = TestResult.query.filter_by(user_id=current_user.id).order_by(TestResult.date.desc()).first()
    bets_history = Bet.query.filter_by(user_id=current_user.id).order_by(Bet.created_at.desc()).limit(10).all()

    return render_template('profile.html',
                           user_balance=user_balance,
                           total_bets=total_bets,
                           bets_won=bets_won,
                           last_test=last_test,
                           bets_history=bets_history,
                           clubs=CLUBS_DATA)


# Просмотр пользователей
@app.route('/users')
@login_required
def show_users():
    try:
        print("DEBUG: Начало функции show_users")

        users = User.query.all()
        print(f"DEBUG: Найдено пользователей: {len(users)}")

        user_balances = {}
        try:
            balances = UserBalance.query.all()
            print(f"DEBUG: Найдено балансов: {len(balances)}")
            for balance in balances:
                user_balances[balance.user_id] = balance.balance
                print(f"DEBUG: Баланс для user_id {balance.user_id}: {balance.balance}")
        except Exception as e:
            print(f"DEBUG: Ошибка при запросе балансов: {e}")
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

        user = db.session.get(User, user_id)
        if not user:
            print(f"DEBUG: Пользователь {user_id} не найден")
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('show_users'))

        print(f"DEBUG: Найден пользователь: {user.name}")

        user_balance_obj = UserBalance.query.filter_by(user_id=user_id).first()
        print(f"DEBUG: Баланс объекта: {user_balance_obj}")

        if user_balance_obj:
            user_balance = user_balance_obj.balance
            print(f"DEBUG: Баланс из БД: {user_balance}")
        else:
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
    match = db.session.get(Match, match_id)
    if not match:
        flash('Матч не найден', 'danger')
        return redirect(url_for('home'))

    if match.is_started or match.is_played:
        flash('Нельзя делать ставки на начавшиеся или завершенные матчи', 'danger')
        return redirect(url_for('home'))

    bet_type = request.form.get('bet_type')
    amount = int(request.form.get('amount', 0))

    if bet_type not in ['home_win', 'draw', 'away_win']:
        flash('Неверный тип ставки', 'danger')
        return redirect(url_for('home'))

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


# --- ИЗМЕНЕНИЕ: Маршрут /my_bets удален ---


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
            # flash() здесь не будет работать, так как функция вызывается фоном
        else:
            bet.won = False

    db.session.commit()


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

        user = User.query.get(user_id)
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('users'))

        print(f"DEBUG: Найден пользователь: {user.name}")

        user_balance = UserBalance.query.filter_by(user_id=user_id).first()
        if not user_balance:
            print("DEBUG: Создаем новый баланс")
            user_balance = UserBalance(user_id=user_id, balance=100)
            db.session.add(user_balance)
        else:
            print(f"DEBUG: Текущий баланс: {user_balance.balance}")

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

        # Инициализация балансов для существующих пользователей
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

        # Запускаем фоновое обновление тура
        schedule_tour_update()

        # Запуск приложения в режиме отладки
        app.run(host='127.0.0.1', port=5000, debug=True)
