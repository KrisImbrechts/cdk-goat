import logging
import os
from base64 import urlsafe_b64decode

from aiohttp import web
from aiohttp.web_exceptions import HTTPForbidden
from aiohttp_jinja2 import render_template
from aiohttp_session import EncryptedCookieStorage, get_session
from aiohttp_session import session_middleware as session_middleware_
from cryptography import fernet

log = logging.getLogger(__name__)


def _get_session_secret_key() -> bytes:
    """
    Retrieve or generate a secret key for session encryption.

    In production, this should be loaded from a secure configuration source
    (environment variable, secrets manager, etc.) and must remain constant
    across application restarts to preserve existing sessions.
    """
    secret_key_b64 = os.environ.get("SESSION_SECRET_KEY")

    if secret_key_b64:
        try:
            return urlsafe_b64decode(secret_key_b64)
        except Exception as e:
            log.warning(
                "Failed to decode SESSION_SECRET_KEY from environment: %s. "
                "Generating a new key.",
                e,
            )

    # Generate a new Fernet key if none is configured
    # WARNING: This will invalidate all existing sessions on restart
    key = fernet.Fernet.generate_key()
    log.warning(
        "No SESSION_SECRET_KEY configured. Generated ephemeral key. "
        "All sessions will be invalidated on application restart. "
        "For production use, set SESSION_SECRET_KEY environment variable."
    )
    return key


@web.middleware
async def session_middleware(request, handler):
    """Wrapper to Session Middleware factory."""
    # Do the trick, by passing app & handler back to original session
    # middleware factory. Do not forget to await on results here as original
    # session middleware factory is also awaitable.
    secret_key = _get_session_secret_key()
    storage = EncryptedCookieStorage(secret_key)
    middleware = session_middleware_(storage)
    return await middleware(request, handler)


@web.middleware
async def csrf_middleware(request, handler):
    """Provides csrf"""
    if request.method == "POST":
        session = await get_session(request)
        token = session.pop("_csrf_token", None)
        formdata = await request.post()
        if not token or token != formdata.get("_csrf_token"):
            log.error(
                "Request to %s was aborted because CSRF tokens mismatched",
                request.rel_url,
            )
            raise HTTPForbidden()
    return await handler(request)


def error_pages(overrides):
    @web.middleware
    async def middleware(request, handler):
        try:
            response = await handler(request)
            override = overrides.get(response.status)
            if override is None:
                return response
            else:
                return await override(request, response)
        except web.HTTPException as ex:
            override = overrides.get(ex.status)
            if override is None:
                raise
            else:
                return await override(request, ex)

    return middleware


async def handle_40x(request, exc):
    response = render_template("errors/40x.jinja2", request, {"error": exc})
    return response


async def handle_50x(request, exc):
    response = render_template("errors/50x.jinja2", request, {"error": exc})
    return response


error_middleware = error_pages(
    {x: handle_40x if x < 500 else handle_50x for x in range(401, 600)}
)
