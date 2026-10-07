import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import activity, auth, files
from app.config import Settings
from app.database import make_engine, session_factory
from app.security import Crypto, hash_password
from app.storage import make_storage


class BodyLimit:
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length"}, status_code=400)(scope, receive, send)
        if length > self.limit:
            return await JSONResponse({"detail": "Request exceeds the upload limit"}, status_code=413)(
                scope, receive, send
            )
        size = 0

        async def bounded_receive():
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > self.limit:
                raise HTTPException(413, "Request exceeds the upload limit")
            return message

        await self.app(scope, bounded_receive, send)


def create_app(settings=None, engine=None, storage=None):
    settings = settings or Settings()
    engine = engine or make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(app):
        async def worker():
            from app.maintenance import run_maintenance

            while True:
                await asyncio.sleep(60)
                try:
                    await asyncio.to_thread(run_maintenance, app)
                except Exception:
                    import logging

                    logging.getLogger(__name__).warning("Maintenance will retry on the next cycle")

        task = asyncio.create_task(worker()) if not settings.testing else None
        yield
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        engine.dispose()

    app = FastAPI(title="Secure Vault", version="2.0.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessions = session_factory(engine)
    app.state.storage = storage or make_storage(settings)
    app.state.crypto = Crypto(settings)
    app.state.dummy_hash = hash_password("not-a-real-account-password")
    app.state.sent_mail = []
    app.add_middleware(BodyLimit, limit=settings.max_upload_bytes + 1024 * 1024)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in settings.allowed_hosts.split(",")])

    @app.middleware("http")
    async def browser_security(request, call_next):
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin and origin.rstrip("/") not in settings.origins:
            return JSONResponse({"detail": "Untrusted request origin"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error):
        # Validation responses must not echo passwords or action tokens.
        return JSONResponse({"detail": [{"loc": e["loc"], "msg": e["msg"]} for e in error.errors()]}, status_code=422)

    @app.get("/healthz")
    def live():
        return {"status": "ok"}

    @app.get("/readyz")
    def ready():
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT id FROM accounts LIMIT 1"))
            app.state.storage.healthy()
        except Exception:
            raise HTTPException(503, "A dependency is unavailable or migrations are pending") from None
        return {"status": "ready"}

    for router in [auth.router, files.router, activity.router]:
        app.include_router(router, prefix="/api")
    return app
