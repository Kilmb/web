from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin
from sqlalchemy_serializer import SerializerMixin

SqlAlchemyBase = declarative_base()


class User(SqlAlchemyBase, UserMixin, SerializerMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    club = Column(String(50), nullable=False)
    password = Column(String(200), nullable=False)
    is_admin = Column(Boolean, default=False)
    avatar = Column(String(200))
    about = Column(String(250))

    serialize_rules = ('-password',)  # Исключаем пароль из сериализации


class RPLTable(SqlAlchemyBase, SerializerMixin):
    __tablename__ = 'rpl_table'

    id = Column(Integer, primary_key=True)
    position = Column(Integer, nullable=False)
    team = Column(String(50), nullable=False, unique=True)
    matches = Column(Integer, default=0)
    wins = Column(Integer, default=0)
    draws = Column(Integer, default=0)
    losses = Column(Integer, default=0)
    goals_for = Column(Integer, default=0)
    goals_against = Column(Integer, default=0)
    points = Column(Integer, default=0)


class Match(SqlAlchemyBase, SerializerMixin):
    __tablename__ = 'matches'

    id = Column(Integer, primary_key=True)
    home_team = Column(String(50), nullable=False)
    away_team = Column(String(50), nullable=False)
    match_date = Column(DateTime, nullable=False)
    home_score = Column(Integer, nullable=True)
    away_score = Column(Integer, nullable=True)
    is_played = Column(Boolean, default=False)
    tour_number = Column(Integer, nullable=False)