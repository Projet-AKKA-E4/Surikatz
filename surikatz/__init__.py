from datetime import datetime
from pathlib import Path
now = datetime.now()
SCAN_DATE =now.strftime("%d_%m_%Y_%H_%M_%S")

SURIKATZ_PATH = Path("/tmp") / "surikatz" / SCAN_DATE
Path.mkdir(SURIKATZ_PATH, parents=True, exist_ok=True)
Path.mkdir(SURIKATZ_PATH / "nmap", parents=True, exist_ok=True)