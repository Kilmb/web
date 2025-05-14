from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///db/site.db')
Session = sessionmaker(bind=engine)


def create_session():
    return Session()


def global_init(db_file):
    global engine
    engine = create_engine(f'sqlite:///{db_file}')
    Session.configure(bind=engine)
