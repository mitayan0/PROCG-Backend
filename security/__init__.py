"""
rls/__init__.py
================
Row-Level Security (RLS) Flask hooks for PROCG Backend.
Tenant isolation is enforced by default.

ARCHITECTURE (fail-closed):
    Before every HTTP request:
        1. before_request hook reads JWT claims (no DB query).
        2. Stores tenant_id / user_id / role flags into Flask g.
        3. Authenticated requests use their JWT claims.
        4. Unauthenticated requests get NO access (all RLS vars unset → all
           protected rows hidden) — EXCEPT an explicit allowlist of public
           auth endpoints (login, invitation, forgot-password) that must query
           user tables without a JWT. Those get is_superadmin=True so their
           initial DB lookups work. Everything else fails closed.

    On every SQLAlchemy transaction BEGIN:
        5. Engine 'begin' event fires.
        6. Parameterised set_config() calls push the context into PostgreSQL
           (equivalent to SET LOCAL, reset automatically on COMMIT/ROLLBACK —
           safe with connection pooling).

    Role flags (mutually exclusive, exactly one is true per request):
        is_superadmin  – cross-tenant, reads+writes everything
        is_admin       – own tenant only, reads+writes all tenant rows
        is_auditor     – own tenant only, reads all tenant rows, NO writes
        is_user        – own tenant only, reads+writes own rows only

    Celery / threads / SSE generators have no request context: the hook
    returns early there and the caller must use security.celery_context to
    set an explicit tenant context. Without it, protected tables return 0 rows.
"""

import logging

from flask import g, request, has_request_context
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from flask_jwt_extended.exceptions import JWTExtendedException
from sqlalchemy import event, text

logger = logging.getLogger(__name__)


def register_rls_hooks(flask_app, db):
    """
    Register the before_request hook and SQLAlchemy engine 'begin' event.

    Args:
        flask_app: The Flask application instance.
        db:        The Flask-SQLAlchemy SQLAlchemy instance.
    """
    _register_before_request(flask_app)
    _register_engine_begin_event(flask_app, db)
    logger.info("[RLS] Hooks registered. Tenant isolation is ACTIVE.")


PUBLIC_RLS_ALLOWLIST = (
    "/login",
    "/logout",
    "/auth/refresh-token",
    "/auth/user",
    "/qr-code/verify-token",
    "/invitation/",
    "/forgot-password/",
)


def is_public_rls_path(path: str) -> bool:
    """True if an unauthenticated request path is on the narrow RLS bypass allowlist."""
    if not path:
        return False
    return any(path == p.rstrip("/") or path.startswith(p) for p in PUBLIC_RLS_ALLOWLIST)


def _register_before_request(flask_app):
    """Decode JWT claims and store tenant/role context in Flask g (fail-closed)."""
    @flask_app.before_request
    def _rls_set_tenant_context():
        """
        Read tenant/user/role context from JWT claims into Flask g.

        Role flags are mutually exclusive — exactly one is True:
          is_superadmin  →  cross-tenant access, all rows
          is_admin       →  own tenant, all rows
          is_auditor     →  own tenant, all rows (read-only at DB level)
          is_user        →  own tenant, own rows only

        Fail-closed: no valid JWT on a non-public path → all flags False
        → RLS blocks all protected rows.

        /login establishes a NEW identity, so a still-valid token from a
        previous session (browser cookies) must never scope its user lookup
        — otherwise switching accounts across tenants 404s with
        "User not found". It always runs as superadmin.
        """
        if request.path == "/login" or request.path == "/login/":
            g.tenant_id = None
            g.user_id   = None
            g.is_superadmin = True
            g.is_admin      = False
            g.is_auditor    = False
            g.is_user       = False
            return
        try:
            verify_jwt_in_request(optional=True)
            claims = get_jwt()
            if claims:
                # user_id
                user_id = claims.get("user_id")
                try:
                    g.user_id = int(user_id) if user_id is not None else None
                except (ValueError, TypeError):
                    g.user_id = None

                # tenant_id — always a plain integer in new tokens
                tenant_id = claims.get("tenant_id")
                try:
                    g.tenant_id = int(tenant_id) if tenant_id is not None else None
                except (ValueError, TypeError):
                    g.tenant_id = None

                # Role flags — mutually exclusive booleans
                g.is_superadmin = bool(claims.get("is_superadmin", False))
                g.is_admin      = bool(claims.get("is_admin",      False))
                g.is_auditor    = bool(claims.get("is_auditor",    False))
                g.is_user       = bool(claims.get("is_user",       False))

                # Ensure exactly one flag is set (superadmin > admin > auditor > user)
                if g.is_superadmin:
                    g.is_admin = g.is_auditor = g.is_user = False
                elif g.is_admin:
                    g.is_auditor = g.is_user = False
                elif g.is_auditor:
                    g.is_user = False
                elif not g.is_user:
                    g.is_user = True  # default fallback

                return
        except (JWTExtendedException, Exception):
            pass  # No valid JWT → fall through to allowlist check below

        # No JWT present: narrow bypass for public auth endpoints only.
        if is_public_rls_path(request.path):
            g.tenant_id = None
            g.user_id   = None
            g.is_superadmin = True
            g.is_admin      = False
            g.is_auditor    = False
            g.is_user       = False
        else:
            g.tenant_id = None
            g.user_id   = None
            g.is_superadmin = False
            g.is_admin      = False
            g.is_auditor    = False
            g.is_user       = False


def _register_engine_begin_event(flask_app, db):
    """Register SQLAlchemy engine 'begin' event to SET LOCAL RLS variables."""
    @event.listens_for(db.engine, "begin")
    def _rls_set_session_vars(conn):
        """
        Push PostgreSQL RLS session variables at the start of every transaction.
        Uses parameterised set_config(..., is_local=true) — equivalent to
        SET LOCAL, reset on COMMIT/ROLLBACK (safe with pooling). No f-string
        interpolation of tenant/user ids into SQL text.
        Celery / threads / app_context-only paths have no request context:
        return early there — callers must use security.celery_context explicitly.
        """
        if not has_request_context():
            return

        tenant_id   = getattr(g, 'tenant_id', None)
        user_id     = getattr(g, 'user_id',   None)
        is_superadmin = getattr(g, 'is_superadmin', False)
        is_admin    = getattr(g, 'is_admin',       False)
        is_auditor  = getattr(g, 'is_auditor',     False)
        is_user     = getattr(g, 'is_user',        False)

        try:
            if tenant_id is not None:
                conn.execute(
                    text("SELECT set_config('app.current_tenant_id', :v, true)"),
                    {"v": str(int(tenant_id))},
                )

            if user_id is not None:
                conn.execute(
                    text("SELECT set_config('app.current_user_id', :v, true)"),
                    {"v": str(int(user_id))},
                )

            conn.execute(
                text("SELECT set_config('app.is_superadmin', :v, true)"),
                {"v": 'true' if is_superadmin else 'false'},
            )
            conn.execute(
                text("SELECT set_config('app.is_admin', :v, true)"),
                {"v": 'true' if is_admin else 'false'},
            )
            conn.execute(
                text("SELECT set_config('app.is_auditor', :v, true)"),
                {"v": 'true' if is_auditor else 'false'},
            )
            conn.execute(
                text("SELECT set_config('app.is_user', :v, true)"),
                {"v": 'true' if is_user else 'false'},
            )

        except Exception as exc:
            logger.error(f"[RLS] Failed to set session variables: {exc}")
