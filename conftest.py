"""Root conftest: ensure this worktree's src/ is first on sys.path.

Git worktrees share the venv from the main checkout, whose editable
.pth file points at the main checkout's src/.  We need *this*
worktree's src/ to take priority so new/modified modules are found.
"""

import pathlib
import sys

_src = str(pathlib.Path(__file__).resolve().parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)
