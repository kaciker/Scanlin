# routers/devices.py
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from api.models.device import Device
from api.database import get_session

router = APIRouter(tags=["devices"])

@router.get("/devices", response_model=List[Device])
async def get_devices(
    session: AsyncSession = Depends(get_session),
    tag: Optional[str] = Query(None, description="Filtrar por tag"),
    search: Optional[str] = Query(None, description="Busca por nombre/IP/MAC"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    stmt = select(Device)
    if tag:
        stmt = stmt.where(Device.tags.ilike(f"%{tag}%"))
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            (Device.name.ilike(like)) |
            (Device.ip.ilike(like)) |
            (Device.mac.ilike(like))
        )
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    return result.scalars().all()

@router.get("/devices/{device_id}", response_model=Device)
async def get_device(device_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Device).where(Device.id == device_id))
    dev = result.scalars().first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device no encontrado")
    return dev

@router.post("/devices", response_model=Device)
async def create_device(device: Device, session: AsyncSession = Depends(get_session)):
    session.add(device)
    await session.commit()
    await session.refresh(device)
    return device
