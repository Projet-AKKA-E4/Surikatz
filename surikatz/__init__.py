from datetime import datetime
from pathlib import Path
now = datetime.now()
datenow = now.strftime("%d/%m/%Y, %H:%M:%S")

SURIKATZ_PATH = Path.cwd() / datenow