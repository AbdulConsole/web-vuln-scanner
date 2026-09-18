"""
Application exception hierarchy and centralized FastAPI error handling.

Using typed exceptions (rather than raising HTTPException throughout the
codebase) keeps the domain layer (crawler, detectors, risk engine) free of
any HTTP-specific concerns and gives us one place to map errors to
consistent JSON error responses.
"""
from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


class ScannerError(Exception):
    """Base class for all application-raised errors."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_message: str = "An unexpected error occurred."

    def __init__(self, message: str | None = None):
        self.message = message or self.default_message
        super().__init__(self.message)


class NotFoundError(ScannerError):
    status_code = status.HTTP_404_NOT_FOUND
    default_message = "Resource not found."


class ValidationFailedError(ScannerError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Validation failed."


class ScopeViolationError(ScannerError):
    """Raised whenever a request or target configuration falls outside the
    authorized scan scope. This is treated as a hard security boundary."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_message = (
        "Requested action is outside the authorized target scope."
    )


class UnsafeTargetError(ScannerError):
    """Raised when a target resolves to a blocked network range (SSRF
    protection) without an explicit lab-mode override."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_message = (
        "Target resolves to a restricted network range and cannot be scanned "
        "without explicit lab-mode configuration."
    )


class ScanConflictError(ScannerError):
    status_code = status.HTTP_409_CONFLICT
    default_message = "Scan is in a state that does not allow this operation."


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ScannerError)
    async def handle_scanner_error(request: Request, exc: ScannerError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.__class__.__name__, "message": exc.message},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception):
        # Never leak internals (stack traces, file paths) to API clients.
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "message": "An unexpected error occurred.",
            },
        )
