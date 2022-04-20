from datetime import datetime
from pathlib import Path
now = datetime.now()
SCAN_DATE =now.strftime("%d-%m-%Y_%H:%M:%S")

SURIKATZ_PATH = Path("/tmp") / "surikatz" / SCAN_DATE
Path.mkdir(SURIKATZ_PATH, parents=True, exist_ok=True)