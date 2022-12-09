
from importlib import resources
from pathlib import Path
import os

path = f'{Path.home()}/{Path("temp.txt")}'
with resources.path(os.getcwd(), "temp.txt") as p:
    p.write_text("Hello")
# resources.path()