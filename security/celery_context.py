"""
rls/celery_context.py
======================
Tenant context manager for Celery tasks and background jobs.

Provides the same RLS context that the Flask before_request hook
provides for HTTP requests — without needing Flask g or a request context.

Usage
-----
    from security.celery_context import celery_tenant_context

    @celery_app.task
    def process_tenant_schedules(tenant_id: int, user_id: int, is_admin: bool = False, is_user: bool = True):
        from executors import flask_app
        with flask_app.app_context():
            with celery_tenant_context(tenant_id, user_id, is_admin=is_admin, is_user=is_user):
                schedules = DefAsyncTaskScheduleNew.query.all()
                # Only rows matching the RLS policy for this tenant/user are returned
                ...

    # Superadmin context (sees all rows across all tenants):
    @celery_app.task
    def system_maintenance():
        from executors import flask_app
        with flask_app.app_context():
            with celery_tenant_context(is_superadmin=True):
                all_tasks = DefAsyncTaskRequest.query.all()

Notes
-----
- Uses db.session.execute(SET LOCAL ...) which scopes variables to the
  current transaction and resets automatically on COMMIT/ROLLBACK.
- The finally block issues RESET as a belt-and-suspenders cleanup.
- This file has NO dependency on Flask g or request context.
"""

from contextlib import contextmanager
import logging
from sqlalchemy import text

from executors.extensions import db

logger = logging.getLogger(__name__)


@contextmanager
def celery_tenant_context(
    tenant_id: "int | None" = None,
    user_id: "int | None" = None,
    is_superadmin: bool = False,
    is_admin: bool = False,
    is_auditor: bool = False,
    is_user: bool = False
):
    """
    Set PostgreSQL RLS session variables for a Celery task.

    Args:
        tenant_id:     Integer tenant ID (None for superadmin tasks).
        user_id:       Integer user ID. Required for Tier 1b (user-owned) tables.
        is_superadmin: True to bypass all tenant boundaries.
        is_admin:      True to apply admin-level visibility within the tenant.
        is_auditor:    True to apply read-only visibility within the tenant.
        is_user:       True to apply user-level visibility.
    """
    try:
        with db.session.begin_nested():
            if tenant_id is not None:
                db.session.execute(
                    text("SELECT set_config('app.current_tenant_id', :v, true)"),
                    {"v": str(int(tenant_id))},
                )
            
            if user_id is not None:
                db.session.execute(
                    text("SELECT set_config('app.current_user_id', :v, true)"),
                    {"v": str(int(user_id))},
                )

            db.session.execute(
                text("SELECT set_config('app.is_superadmin', :v, true)"),
                {"v": 'true' if is_superadmin else 'false'},
            )
            db.session.execute(
                text("SELECT set_config('app.is_admin', :v, true)"),
                {"v": 'true' if is_admin else 'false'},
            )
            db.session.execute(
                text("SELECT set_config('app.is_auditor', :v, true)"),
                {"v": 'true' if is_auditor else 'false'},
            )
            db.session.execute(
                text("SELECT set_config('app.is_user', :v, true)"),
                {"v": 'true' if is_user else 'false'},
            )

            yield

    finally:
        try:
            db.session.execute(text("RESET app.current_tenant_id"))
            db.session.execute(text("RESET app.current_user_id"))
            db.session.execute(text("RESET app.is_superadmin"))
            db.session.execute(text("RESET app.is_admin"))
            db.session.execute(text("RESET app.is_auditor"))
            db.session.execute(text("RESET app.is_user"))
        except Exception as exc:
            logger.warning(f"[RLS] Failed to reset session variables in finally: {exc}")
