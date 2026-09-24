from flask import jsonify
from flask_jwt_extended import jwt_required
from executors.extensions import cache
from utils.dashboard_service import fetch_counts, fetch_items
from utils.execution_utils import ExecutionScope, _caller_scope as caller_scope
from utils.auth import role_required
from . import dashboard_bp


@dashboard_bp.route('/dashboard/summary', methods=['GET'])
@jwt_required()
@role_required()
def get_dashboard_summary():
    try:
        scope, uid, tid = caller_scope()
        if scope != "all" and tid is None:
            scope = ExecutionScope.OWN
        cache_key = f"dashboard_summary:v2:{scope}:{uid}:{tid}"
        cached = cache.get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        # Same request/connection: RLS SET LOCAL from security hooks still applies.
        counts = fetch_counts(scope, uid, tid)
        items = fetch_items(scope, uid, tid)

        payload = {
            "async_tasks": {
                "total": counts.tasks_total,
                "active": counts.tasks_active,
                "cancelled": counts.tasks_inactive,
                "srs": counts.tasks_srs,
                "sf": counts.tasks_sf,
                "items": items['async_task'],
            },
            "scheduled_tasks": {
                "total": counts.schedules_total,
                "scheduled": counts.schedules_scheduled,
                "cancelled": counts.schedules_cancelled,
                "items": items['schedule'],
            },
            "workflow_runs": {
                "total": counts.runs_total,
                "running": counts.runs_running,
                "completed": counts.runs_completed,
                "failed": counts.runs_failed,
                "waiting": counts.runs_waiting,
                "items": items['run'],
            },
            "executors": {"total": counts.executors, "items": items['executor']},
            "users": {"total": counts.users, "items": items['user']},
            "tenants": {"total": counts.tenants, "items": items['tenant']},
            "enterprises": {"total": counts.enterprises, "items": items['enterprise']},
            "workflows": {"total": counts.workflows, "items": items['workflow']},
        }
        cache.set(cache_key, payload, timeout=60)
        return jsonify(payload), 200

    except Exception as e:
        return jsonify({"message": "Error fetching dashboard summary", "error": str(e)}), 500
