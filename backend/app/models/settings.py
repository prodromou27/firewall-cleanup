from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.sql import func
from app.database import Base
import uuid


class AppSettings(Base):
    __tablename__ = "app_settings"

    key = Column(String, primary_key=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
