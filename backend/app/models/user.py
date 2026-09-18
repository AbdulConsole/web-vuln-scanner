"""
User model.

LIMITATION: this table exists so the schema has a place to store accounts,
but no authentication endpoints, password hashing, session/JWT handling, or
authorization checks are implemented yet — no route currently reads or
writes this table. It is intentionally excluded from the API surface until
that is built and tested as its own milestone. Do not treat its presence
here as evidence that auth is enforced anywhere in the current system.
"""
from __future__ import annotations

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email!r}>"
