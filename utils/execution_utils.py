from flask_jwt_extended import get_jwt_identity
from sqlalchemy import or_, text as sa_text
from executors.extensions import db
from executors.models import DefUser, DefProcessExecution
from utils.auth import is_superadmin, is_admin, is_auditor
from enum import Enum

class ExecutionScope(str, Enum):
    ALL = "all"
    TENANT = "tenant"
    AUDIT = "audit"
    OWN = "own"

def _caller_scope():
    """Return (scope, user_id, tenant_id): 'all' | 'tenant' | 'audit' | 'own'."""
    uid = get_jwt_identity()
    try:
        user = db.session.get(DefUser, int(uid)) if uid is not None else None
    except (ValueError, TypeError):
        user = None
    if user is not None and is_superadmin(user):
        return ExecutionScope.ALL, uid, getattr(user, "tenant_id", None)
    if user is not None and is_admin(user):
        return ExecutionScope.TENANT, uid, getattr(user, "tenant_id", None)
    if user is not None and is_auditor(user):
        return ExecutionScope.AUDIT, uid, getattr(user, "tenant_id", None)
    tenant_id = getattr(user, "tenant_id", None) if user is not None else None
    return ExecutionScope.OWN, uid, tenant_id

def _execution_visible(execution, scope, uid, tid):
    """App-level ownership check (defense in depth alongside RLS)."""
    if execution is None:
        return False
    if scope == ExecutionScope.ALL:
        return True
    if scope in (ExecutionScope.TENANT, ExecutionScope.AUDIT):  # auditor has same read visibility as admin
        exec_tid = getattr(execution, "tenant_id", None)
        if exec_tid is not None:
            return exec_tid == tid
        # Legacy row without tenant_id: visible if creator is in caller's tenant.
        try:
            creator = (
                db.session.get(DefUser, int(execution.created_by))
                if execution.created_by is not None
                else None
            )
            return creator is not None and getattr(creator, "tenant_id", None) == tid
        except (ValueError, TypeError):
            return False
    try:
        return execution.created_by is not None and str(execution.created_by) == str(uid)
    except Exception:
        return False

def _scope_execution_query(query, scope, uid, tid):
    """Restrict an execution query to rows the caller may see."""
    if scope == ExecutionScope.ALL:
        return query
    if scope in (ExecutionScope.TENANT, ExecutionScope.AUDIT):  # auditor reads same as admin
        if tid is None:
            return query.filter(sa_text("1=0"))
        tenant_users = db.session.query(DefUser.user_id).filter(DefUser.tenant_id == tid)
        return query.filter(
            or_(
                DefProcessExecution.tenant_id == tid,
                DefProcessExecution.created_by.in_(tenant_users),
            )
        )
    try:
        return query.filter(DefProcessExecution.created_by == int(uid))
    except (ValueError, TypeError):
        return query.filter(sa_text("1=0"))

def _apply_worker_rls(scope, uid, tid):
    """Re-apply RLS session vars on a non-request (worker/SSE) session.

    Must be called after every rollback/commit, which clears SET LOCAL state.
    Sets the four boolean flags that match the new SQL helper functions.
    """
    _is_superadmin = scope == ExecutionScope.ALL
    _is_admin      = scope == ExecutionScope.TENANT
    _is_auditor    = scope == ExecutionScope.AUDIT
    _is_user       = scope == ExecutionScope.OWN

    if tid is not None:
        try:
            db.session.execute(
                sa_text("SELECT set_config('app.current_tenant_id', :v, true)"),
                {"v": str(int(tid))},
            )
        except (ValueError, TypeError):
            pass

    if uid is not None:
        try:
            db.session.execute(
                sa_text("SELECT set_config('app.current_user_id', :v, true)"),
                {"v": str(int(uid))},
            )
        except (ValueError, TypeError):
            pass

    db.session.execute(
        sa_text("SELECT set_config('app.is_superadmin', :v, true)"),
        {"v": 'true' if _is_superadmin else 'false'},
    )
    db.session.execute(
        sa_text("SELECT set_config('app.is_admin', :v, true)"),
        {"v": 'true' if _is_admin else 'false'},
    )
    db.session.execute(
        sa_text("SELECT set_config('app.is_auditor', :v, true)"),
        {"v": 'true' if _is_auditor else 'false'},
    )
    db.session.execute(
        sa_text("SELECT set_config('app.is_user', :v, true)"),
        {"v": 'true' if _is_user else 'false'},
    )
