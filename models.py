from sqlalchemy import Column, Integer, String, Boolean, DateTime
from database import Base

class EventLog(Base):
    __tablename__ = "event_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    source = Column(String, index=True)
    event_id = Column(String, index=True)
    category = Column(String)
    message = Column(String)
    suspicious = Column(Boolean, default=False)
