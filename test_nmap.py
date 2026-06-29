import subprocess
import time
import sys

proc = subprocess.Popen(
    ["nmap", "--stats-every", "1s", "scanme.nmap.org"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

start = time.time()
while time.time() - start < 4:
    line = proc.stdout.readline()
    if line:
        print(f"OUT: {line.strip()}")
        sys.stdout.flush()

proc.terminate()
