import contextvars
from dataclasses import dataclass
from typing import Optional

@dataclass
class RunContext:
    jail_dir: str
    db_path: str
    target_file: str = ""
    sandbox: object = None
    run_id: str = ""
    sandbox_executed: bool = False
    snapshot_id: str = ""
    budget_controller: object = None
    static_sandbox_attempts: int = 0
    active_node: str = ""

current_run_context: contextvars.ContextVar[Optional[RunContext]] = contextvars.ContextVar(
    "current_run_context", default=None
)

