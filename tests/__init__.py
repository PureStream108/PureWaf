# package

import os
from pathlib import Path

os.environ.setdefault(
    "PUREWAF_SANDBOX_ROOT",
    str(Path(__file__).resolve().parents[1] / ".purewaf-sandbox"),
)
