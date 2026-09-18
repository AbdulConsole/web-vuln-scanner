from __future__ import annotations

import socket

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # noqa: F401
from app.core.config import get_settings
from app.core.exceptions import NotFoundError, UnsafeTargetError, ValidationFailedError
from app.database.base import Base
from app.database.repositories.target_repository import TargetRepository
from app.schemas.target import AuthConfig, ScanConfig, TargetCreate, TargetUpdate
from app.services.target_service import TargetService

pytestmark = pytest.mark.asyncio

_PUBLIC_IP = "93.184.216.34"  # arbitrary public-range IP for test purposes
_PRIVATE_IP = "10.0.0.5"


def _fake_getaddrinfo(mapping):
    """Build a deterministic stand-in for socket.getaddrinfo so tests never
    depend on real DNS/network access."""

    def _resolve(host, *args, **kwargs):
        ip = mapping.get(host, _PUBLIC_IP)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    return _resolve


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
def service(session):
    return TargetService(TargetRepository(session))


async def test_create_target_happy_path(service, monkeypatch):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"public.example.com": _PUBLIC_IP}),
    )
    payload = TargetCreate(
        name="Public Test App",
        base_url="http://public.example.com/",
        allowed_domains=["staging.public.example.com"],
    )
    target = await service.create_target(payload)

    assert target.id is not None
    assert target.base_url == "http://public.example.com/"
    assert target.allowed_domains == ["staging.public.example.com"]
    assert target.scan_config["crawl_depth"] == get_settings().DEFAULT_CRAWL_DEPTH


async def test_create_target_rejects_duplicate_name(service, monkeypatch):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"a.example.com": _PUBLIC_IP, "b.example.com": _PUBLIC_IP}),
    )
    await service.create_target(
        TargetCreate(name="Same Name", base_url="http://a.example.com")
    )
    with pytest.raises(ValidationFailedError):
        await service.create_target(
            TargetCreate(name="Same Name", base_url="http://b.example.com")
        )


async def test_create_target_rejects_duplicate_base_url(service, monkeypatch):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"dup.example.com": _PUBLIC_IP}),
    )
    await service.create_target(
        TargetCreate(name="First", base_url="http://dup.example.com/app/")
    )
    with pytest.raises(ValidationFailedError):
        # Same URL, different casing/port -- normalizes to an identical
        # base_url, so this must still be caught as a duplicate.
        await service.create_target(
            TargetCreate(name="Second", base_url="HTTP://Dup.Example.com:80/app/")
        )


async def test_create_target_rejects_private_ip_resolution_without_lab_mode(
    service, monkeypatch
):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"internal.example.com": _PRIVATE_IP}),
    )
    with pytest.raises(UnsafeTargetError):
        await service.create_target(
            TargetCreate(name="Internal App", base_url="http://internal.example.com")
        )


async def test_create_target_allows_private_ip_when_lab_mode_enabled(
    service, monkeypatch
):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"lab.example.com": _PRIVATE_IP}),
    )
    target = await service.create_target(
        TargetCreate(name="Lab App", base_url="http://lab.example.com")
    )
    assert target.base_url == "http://lab.example.com/"


async def test_get_target_raises_not_found_for_unknown_id(service):
    import uuid

    with pytest.raises(NotFoundError):
        await service.get_target(uuid.uuid4())


async def test_update_target_renames_and_revalidates_domains(service, monkeypatch):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"update.example.com": _PUBLIC_IP}),
    )
    target = await service.create_target(
        TargetCreate(name="Original Name", base_url="http://update.example.com")
    )

    updated = await service.update_target(
        target.id,
        TargetUpdate(
            name="New Name",
            allowed_domains=["extra.update.example.com"],
            scan_config=ScanConfig(crawl_depth=5),
        ),
    )

    assert updated.name == "New Name"
    assert updated.allowed_domains == ["extra.update.example.com"]
    assert updated.scan_config["crawl_depth"] == 5


async def test_update_target_rejects_rename_to_existing_name(service, monkeypatch):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"one.example.com": _PUBLIC_IP, "two.example.com": _PUBLIC_IP}),
    )
    await service.create_target(TargetCreate(name="Taken", base_url="http://one.example.com"))
    target_two = await service.create_target(
        TargetCreate(name="Free", base_url="http://two.example.com")
    )

    with pytest.raises(ValidationFailedError):
        await service.update_target(target_two.id, TargetUpdate(name="Taken"))


async def test_delete_target_removes_it(service, monkeypatch):
    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"todelete.example.com": _PUBLIC_IP}),
    )
    target = await service.create_target(
        TargetCreate(name="Ephemeral", base_url="http://todelete.example.com")
    )
    await service.delete_target(target.id)

    with pytest.raises(NotFoundError):
        await service.get_target(target.id)


async def test_target_read_never_exposes_raw_auth_config(service, monkeypatch):
    """Defensive check: TargetRead must only ever expose a boolean flag for
    auth config, never the underlying credentials -- this matters because
    auth_config is stored unencrypted (see app/models/target.py)."""
    from app.schemas.target import TargetRead

    monkeypatch.setattr(
        "app.core.security.socket.getaddrinfo",
        _fake_getaddrinfo({"authed.example.com": _PUBLIC_IP}),
    )
    target = await service.create_target(
        TargetCreate(
            name="Authed App",
            base_url="http://authed.example.com",
            auth_config=AuthConfig(type="bearer_token", bearer_token="super-secret-token"),
        )
    )

    read_model = TargetRead.from_model(target)
    dumped = read_model.model_dump()

    assert dumped["has_auth_config"] is True
    assert "auth_config" not in dumped
    assert "super-secret-token" not in str(dumped)
