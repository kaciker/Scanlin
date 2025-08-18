from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime

class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    ip: str
    mac: str
    os: Optional[str] = None
    last_seen: Optional[datetime] = None
    tags: Optional[str] = None
