from datetime import datetime
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .db_session import db
import translators as ts


class Password_inkognito:
    def encrypt_password(self, password):
        return generate_password_hash(password)

    def verify_password(self, hashed_password, input_password):
        return check_password_hash(hashed_password, input_password)


pw_secure = Password_inkognito()

names_cache = {}


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


class MatchEvent(db.Model):
    __tablename__ = 'match_events'

    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('matches.id'), nullable=False)
    team_id = db.Column(db.Integer)
    minute = db.Column(db.Integer)
    type = db.Column(db.Integer)
    player_name = db.Column(db.String(100))
    extra_info = db.Column(db.String(100))

    def __repr__(self):
        return f"Event({self.minute}', {self.player_name})"


class NameTranslation(db.Model):
    __tablename__ = 'name_translations'

    id = db.Column(db.Integer, primary_key=True)
    original = db.Column(db.String(150), unique=True, nullable=False, index=True)
    translated = db.Column(db.String(150), nullable=False)


def transliterate_name(text):
    if not text:
        return ""
    text = text.strip()

    if text in names_cache:
        return names_cache[text]

    try:
        stored_translation = db.session.query(NameTranslation).filter_by(original=text).first()
        if stored_translation:
            names_cache[text] = stored_translation.translated
            return stored_translation.translated
    except Exception as e:
        print(f"Ошибка чтения перевода из БД: {e}")

    try:
        rus_text = ts.translate_text(text, translator='google', from_language='en', to_language='ru')
        names_cache[text] = rus_text
        try:
            new_trans = NameTranslation(original=text, translated=rus_text)
            db.session.add(new_trans)
            db.session.commit()
        except Exception as db_err:
            db.session.rollback()
            print(f"Не удалось сохранить перевод в БД: {db_err}")

        return rus_text
    except Exception as e:
        print(f"Ошибка API перевода для {text}: {e}")
        return text