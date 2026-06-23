from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///firewall_logs.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()

class PacketLog(Base):
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True)
    protocol = Column(String)
    source = Column(String)
    destination = Column(String)
    port = Column(Integer)
    decision = Column(String)

Base.metadata.create_all(bind=engine)