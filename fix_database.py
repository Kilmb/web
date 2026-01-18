from main import app, db
from main import User, RPLTable, Match, ClubTest, UserBalance, WheelSpin, Bet, TestResult, MatchMessage
from main import RPL_CLUBS, ADMIN_EMAIL, pw_secure


def fix_database():
    with app.app_context():
        print("🔧 Исправляем базу данных...")
        
        print("🗑️ Удаляем все таблицы...")
        db.drop_all()
        
        print("🔄 Создаем все таблицы...")
        db.create_all()

        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"✅ Созданные таблицы: {tables}")

        print("👨‍💼 Создаем администратора...")
        admin = User(
            name='Admin',
            email=ADMIN_EMAIL,
            club='Краснодар',
            password=pw_secure.encrypt_password('Admin_RPL_404?!'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

        print("🏆 Заполняем таблицу RPL...")
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

        teams_count = RPLTable.query.count()
        print(f"✅ В RPLTable записано {teams_count} команд")

        teams = RPLTable.query.order_by(RPLTable.position).all()
        print("📋 Содержимое RPL таблицы:")
        for team in teams:
            print(f"  {team.position}. {team.team} - {team.points} очков")

        print("🎉 База данных полностью исправлена!")


if __name__ == '__main__':

    fix_database()
