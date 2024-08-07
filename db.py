from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Float, String


# データベースへの接続
engine = create_engine('mysql+pymysql://authoperator:authoperatorpass@127.0.0.1:3306/authdb')

# セッションの作成
db_session = scoped_session(
  sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
  )
)

# テーブルを作成する
Base = declarative_base()

class User(Base):
    # テーブル名
    __tablename__ = 'users'
    # カラムの定義
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)

Base.metadata.create_all(bind=engine)

# user = User(name="John")
# db_session.add(user)
# db_session.commit()

db = db_session.query(User).all()
for row in db:
    print(row.name)