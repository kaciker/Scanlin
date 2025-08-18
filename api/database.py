from os import getenv
from typing import AsyncGenerator
from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

DB_USER = getenv("POSTGRES_USER", getenv("DB_USER", "scanlin"))
DB_PASS = getenv("POSTGRES_PASSWORD", getenv("DB_PASS", "clave_segura"))
DB_HOST = getenv("DB_HOST", "postgres")
DB_NAME = getenv("POSTGRES_DB", getenv("DB_NAME", "scanlindb"))
DB_PORT = getenv("DB_PORT", "5432")

DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
async_session = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session
