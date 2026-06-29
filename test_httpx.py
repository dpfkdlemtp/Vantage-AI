import subprocess
import time
import os

proc = subprocess.Popen(
    ["httpx", "-u", "http://example.com", "-stats", "-si", "1"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)
os.set_blocking(proc.stderr.fileno(), False)

stop_at = time.time() + 5
while time.time() < stop_at:
    try:
        line = proc.stderr.readline()
        if line:
            print(f"ERR: {line.strip()}")
    except TypeError:
        pass
    except Exception as e:
        print(f"Exception: {e}")
    
    if proc.poll() is not None:
        break
    time.sleep(0.1)
proc.terminate()
