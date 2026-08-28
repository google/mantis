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

current_run_context: contextvars.ContextVar[Optional[RunContext]] = contextvars.ContextVar(
    "current_run_context", default=None
)

