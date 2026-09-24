import logging
from celery import shared_task
from security.celery_context import celery_tenant_context
from workflow_engine.engine import WorkflowEngine, WorkflowError

logger = logging.getLogger(__name__)


def _tenant_scope(tenant_id, user_id, is_admin=False):
    """Return a tenant context manager for a worker task.

    Dispatch sites pass the execution owner's tenant explicitly. Legacy
    already-queued messages carry None (or the old 'superadmin' string) →
    fall back to superadmin so they keep running (logged as a warning).
    """
    if tenant_id is None or tenant_id == 'superadmin':
        logger.warning(
            "Celery workflow task without tenant context — using superadmin "
            "fallback. Dispatch sites should pass tenant_id/user_id."
        )
        return celery_tenant_context(is_superadmin=True)
    return celery_tenant_context(tenant_id, user_id, is_admin=bool(is_admin), is_user=not bool(is_admin))


@shared_task(name='workflow_engine.tasks.execute_workflow_task')
def execute_workflow_task(execution_id: int, process_structure: dict = None,
                          tenant_id=None, user_id=None, is_admin=False):
    """Celery task to dispatch the first step of a workflow execution.

    Returns immediately after dispatching. Subsequent steps are chained
    via Celery's link callback (advance_workflow_step).
    """
    try:
        with _tenant_scope(tenant_id, user_id, is_admin):
            engine = WorkflowEngine()
            engine.execute_from_id(execution_id, process_structure=process_structure)
    except Exception as e:
        logger.error(f"Error in execute_workflow_task for execution {execution_id}: {e}", exc_info=True)


@shared_task(name='workflow_engine.tasks.resume_workflow_task')
def resume_workflow_task(execution_id: int, task_result: dict,
                         tenant_id=None, user_id=None, is_admin=False):
    """Celery task to resume a paused or waiting workflow."""
    try:
        with _tenant_scope(tenant_id, user_id, is_admin):
            engine = WorkflowEngine()
            engine.resume_execution(execution_id, task_result)
    except WorkflowError as e:
        logger.warning(f"Workflow logic error during resume of {execution_id}: {e}")
    except Exception as e:
        logger.error(f"Error in resume_workflow_task for execution {execution_id}: {e}", exc_info=True)


@shared_task(name='workflow_engine.tasks.advance_workflow_step')
def advance_workflow_step(executor_result, execution_id: int, node_id: str,
                          tenant_id=None, user_id=None, is_admin=False):
    """Celery callback task — called automatically when an executor step completes.

    Updates the step record and dispatches the next node in the workflow.
    """
    try:
        with _tenant_scope(tenant_id, user_id, is_admin):
            engine = WorkflowEngine()
            engine._complete_step_and_advance(execution_id, node_id, executor_result)
    except Exception as e:
        logger.error(f"Error in advance_workflow_step for execution {execution_id}, node {node_id}: {e}", exc_info=True)
