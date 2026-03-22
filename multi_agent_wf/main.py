from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from multi_agent_wf.config import bootstrap_from_env
else:
    from .config import bootstrap_from_env


def main() -> None:
    app_settings = bootstrap_from_env()

    if __package__ in {None, ""}:
        from multi_agent_wf.frontend import WorkflowUI
    else:
        from .frontend import WorkflowUI

    WorkflowUI(app_settings=app_settings).launch()


if __name__ == "__main__":
    main()
